// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package jwks — верификатор identity-JWT data-plane реестра по Hydra JWKS.
//
// Токен выдаёт Ory Hydra (client_credentials — для docker через token-шим;
// jwt-bearer — для k8s workload). Токен несёт ИДЕНТИЧНОСТЬ (sub = principal id,
// напр. Hydra client_id ↔ ServiceAccount), без pre-issued Docker-scope: авторизация —
// per-request Check в registry (identity-only, Вариант B). Verifier тянет публичные
// ключи с Hydra-public JWKS-endpoint, кэширует их с ограниченным TTL (Cache-Control
// max-age, но не бесконечно), рефетчит по неизвестному kid (key rotation) и энфорсит
// подпись RS256 или ES256 + exp + aud (наш service) + опц. iss (Hydra). Реализация —
// на stdlib (crypto/rsa + crypto/ecdsa + encoding/base64/json), без внешних
// JWT-зависимостей.
//
// Fail-closed (JWKS — hard-dependency AuthN-стадии): JWKS недоступен и нужного ключа
// нет в свежем кэше → отказ (не обслуживаем по устаревшему кэшу «вечно» — иначе
// ротированный/отозванный ключ оставался бы валидным без ограничения). alg вне
// allowlist {RS256, ES256} (в т.ч. `none`, HS*) → отказ.
//
// Реализует порт dataplane.TokenVerifier (структурно: Verify(ctx,string)(string,error)).
package jwks

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ErrInvalidToken — обобщённая ошибка верификации (подпись/срок/aud/iss/kid/alg/формат).
// Data-plane маппит любую ошибку Verify в 401 error="invalid_token" (не раскрывая
// причину клиенту — defense-in-depth).
var ErrInvalidToken = errors.New("jwks: invalid token")

// defaultTTL — TTL кэша JWKS (fallback, если сервер не задал Cache-Control).
const defaultTTL = 5 * time.Minute

// Verifier — потокобезопасный верификатор Hydra-issued identity-JWT по Hydra JWKS.
type Verifier struct {
	jwksURL string
	aud     string        // ожидаемый audience (наш service); обязателен
	iss     string        // ожидаемый issuer (Hydra); "" → проверка iss пропускается
	ttl     time.Duration // ограниченный TTL кэша ключей
	http    *http.Client
	now     func() time.Time

	mu      sync.Mutex
	keys    map[string]crypto.PublicKey // kid → *rsa.PublicKey | *ecdsa.PublicKey
	fetched time.Time
}

// New строит Verifier для Hydra JWKS-endpoint. aud — обязательный expected audience
// (наш service, напр. "registry.kacho.local"); iss — опциональный expected issuer
// (Hydra; пусто → не проверяется).
func New(jwksURL, aud, iss string) *Verifier {
	return &Verifier{
		jwksURL: jwksURL,
		aud:     aud,
		iss:     iss,
		ttl:     defaultTTL,
		http:    &http.Client{Timeout: 10 * time.Second},
		now:     time.Now,
		keys:    map[string]crypto.PublicKey{},
	}
}

// jwtHeader — разбираемая часть JOSE-header (alg + kid).
type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// jwtClaims — энфорсимые claim'ы identity-JWT. aud может быть строкой или массивом
// (JWT RFC 7519) — обрабатывается кастомным типом audience.
type jwtClaims struct {
	Sub string   `json:"sub"`
	Exp int64    `json:"exp"`
	Iss string   `json:"iss"`
	Aud audience `json:"aud"`
}

// Verify верифицирует Bearer-JWT и возвращает identity (`sub`). Энфорс: alg ∈
// {RS256, ES256}, подпись по JWKS-ключу (kid) + exp>now + aud==наш service + (если
// задан) iss. Любое нарушение → ErrInvalidToken.
func (v *Verifier) Verify(ctx context.Context, raw string) (string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("%w: not a compact JWS", ErrInvalidToken)
	}

	var hdr jwtHeader
	if err := decodeSegment(parts[0], &hdr); err != nil {
		return "", fmt.Errorf("%w: bad header", ErrInvalidToken)
	}
	if hdr.Alg != algRS256 && hdr.Alg != algES256 {
		return "", fmt.Errorf("%w: unexpected alg %q", ErrInvalidToken, hdr.Alg)
	}

	key, err := v.keyFor(ctx, hdr.Kid)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", fmt.Errorf("%w: bad signature encoding", ErrInvalidToken)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := verifySignature(hdr.Alg, key, sum[:], sig); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	var claims jwtClaims
	if err := decodeSegment(parts[1], &claims); err != nil {
		return "", fmt.Errorf("%w: bad claims", ErrInvalidToken)
	}
	if claims.Exp == 0 || v.now().After(time.Unix(claims.Exp, 0)) {
		return "", fmt.Errorf("%w: expired", ErrInvalidToken)
	}
	if !claims.Aud.contains(v.aud) {
		return "", fmt.Errorf("%w: audience mismatch", ErrInvalidToken)
	}
	if v.iss != "" && claims.Iss != v.iss {
		return "", fmt.Errorf("%w: issuer mismatch", ErrInvalidToken)
	}
	if claims.Sub == "" {
		return "", fmt.Errorf("%w: empty subject", ErrInvalidToken)
	}
	return claims.Sub, nil
}

// keyFor возвращает публичный ключ по kid. Свежий кэш с этим kid → отдаём сразу; иначе
// один рефетч JWKS (key rotation). Рефетч не удался → отказ (fail-closed): по
// устаревшему кэшу не обслуживаем, чтобы ротированный/отозванный ключ не оставался
// валидным без ограничения TTL. Рефетч удался, но kid по-прежнему нет → отказ.
func (v *Verifier) keyFor(ctx context.Context, kid string) (crypto.PublicKey, error) {
	v.mu.Lock()
	key, ok := v.keys[kid]
	fresh := v.now().Sub(v.fetched) < v.ttl
	v.mu.Unlock()
	if ok && fresh {
		return key, nil
	}

	if err := v.refresh(ctx); err != nil {
		return nil, err
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("unknown kid %q", kid)
}

// refresh тянет JWKS и перестраивает кэш публичных ключей (RSA + EC/P-256). Любой сбой
// фетча/парсинга → ошибка (caller fail-closed).
func (v *Verifier) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := v.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks fetch status %d", resp.StatusCode)
	}

	var doc struct {
		Keys []jsonWebKey `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("jwks decode: %w", err)
	}

	fresh := make(map[string]crypto.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kid == "" {
			continue
		}
		pub, perr := k.toKey()
		if perr != nil {
			continue // ключ неподдерживаемого типа/битый пропускаем (остальные валидны)
		}
		fresh[k.Kid] = pub
	}

	ttl := parseMaxAge(resp.Header.Get("Cache-Control"))
	v.mu.Lock()
	v.keys = fresh
	v.fetched = v.now()
	if ttl > 0 {
		v.ttl = ttl
	}
	v.mu.Unlock()
	return nil
}

// verifySignature проверяет подпись JWS по alg. Тип ключа обязан соответствовать alg
// (RSA↔RS256, EC↔ES256) — несоответствие отвергается (защита от alg-confusion).
func verifySignature(alg string, key crypto.PublicKey, hash, sig []byte) error {
	switch alg {
	case algRS256:
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return errors.New("key type mismatch for RS256")
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash, sig); err != nil {
			return errors.New("signature mismatch")
		}
		return nil
	case algES256:
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("key type mismatch for ES256")
		}
		// JWS ES256: raw подпись r||s, по 32 байта (P-256).
		if len(sig) != 64 {
			return errors.New("bad ES256 signature length")
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(pub, hash, r, s) {
			return errors.New("signature mismatch")
		}
		return nil
	default:
		return fmt.Errorf("unexpected alg %q", alg)
	}
}

// поддерживаемые алгоритмы подписи (Hydra advertises RS256 по умолчанию, ES256 —
// опционально). Всё вне allowlist (`none`, HS*) отвергается.
const (
	algRS256 = "RS256"
	algES256 = "ES256"
)

// jsonWebKey — JWK (RFC 7517): RSA (n/e) либо EC/P-256 (crv/x/y) — base64url big-endian.
type jsonWebKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Crv string `json:"crv"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// toKey собирает публичный ключ из JWK по kty. Поддержаны RSA и EC/P-256 (ES256);
// остальные типы/кривые — ошибка.
func (k jsonWebKey) toKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		return k.toRSA()
	case "EC":
		return k.toECDSA()
	default:
		return nil, fmt.Errorf("unsupported kty %q", k.Kty)
	}
}

// toRSA собирает *rsa.PublicKey из base64url n/e.
func (k jsonWebKey) toRSA() (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	eb, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	if len(nb) == 0 || len(eb) == 0 {
		return nil, errors.New("empty modulus/exponent")
	}
	e := new(big.Int).SetBytes(eb)
	if !e.IsInt64() || e.Int64() < 2 {
		return nil, errors.New("invalid exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(e.Int64())}, nil
}

// toECDSA собирает *ecdsa.PublicKey из base64url x/y для кривой P-256 (ES256). Точка
// валидируется как лежащая на кривой (ecdh.P256().NewPublicKey отвергает off-curve),
// иначе битый/подложный ключ не попадает в кэш.
func (k jsonWebKey) toECDSA() (*ecdsa.PublicKey, error) {
	if k.Crv != "P-256" {
		return nil, fmt.Errorf("unsupported EC curve %q", k.Crv)
	}
	xb, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, err
	}
	yb, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, err
	}
	if len(xb) == 0 || len(xb) > 32 || len(yb) == 0 || len(yb) > 32 {
		return nil, errors.New("invalid EC coordinate length")
	}
	// Uncompressed SEC1: 0x04 || X(32) || Y(32); NewPublicKey проверяет on-curve.
	uncompressed := make([]byte, 1+32+32)
	uncompressed[0] = 4
	copy(uncompressed[1+(32-len(xb)):33], xb)
	copy(uncompressed[33+(32-len(yb)):], yb)
	if _, perr := ecdh.P256().NewPublicKey(uncompressed); perr != nil {
		return nil, fmt.Errorf("invalid EC point: %w", perr)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xb),
		Y:     new(big.Int).SetBytes(yb),
	}, nil
}

// audience — aud, допускающий строку ИЛИ массив строк (JWT RFC 7519).
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var single string
	if err := json.Unmarshal(b, &single); err == nil {
		*a = audience{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

func (a audience) contains(want string) bool {
	for _, v := range a {
		if v == want {
			return true
		}
	}
	return false
}

// decodeSegment base64url-декодирует JOSE-сегмент и разбирает JSON в out.
func decodeSegment(seg string, out any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// parseMaxAge извлекает max-age (секунды) из Cache-Control; 0 — не задан/битый.
func parseMaxAge(cacheControl string) time.Duration {
	for _, part := range strings.Split(cacheControl, ",") {
		part = strings.TrimSpace(part)
		if v, ok := strings.CutPrefix(part, "max-age="); ok {
			var secs int
			if _, err := fmt.Sscanf(v, "%d", &secs); err == nil && secs > 0 {
				return time.Duration(secs) * time.Second
			}
		}
	}
	return 0
}
