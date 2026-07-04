// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package jwks — верификатор identity-JWT data-plane реестра по IAM JWKS.
//
// IAM /token выдаёт короткоживущий RS256-JWT, несущий ИДЕНТИЧНОСТЬ (sub = principal
// id), без pre-issued Docker-scope (авторизация — per-request Check в registry,
// Вариант B). Verifier тянет публичные ключи с IAM JWKS-endpoint, кэширует их с TTL
// (Cache-Control max-age), рефетчит по неизвестному kid (key rotation) и энфорсит
// подпись RS256 + exp + aud (наш service) + опц. iss. Реализация — на stdlib
// (crypto/rsa + encoding/base64/json), без внешних JWT-зависимостей.
//
// Реализует порт dataplane.TokenVerifier (структурно: Verify(ctx,string)(string,error)).
package jwks

import (
	"context"
	"crypto"
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

// ErrInvalidToken — обобщённая ошибка верификации (подпись/срок/aud/kid/формат).
// Data-plane маппит любую ошибку Verify в 401 error="invalid_token" (не раскрывая
// причину клиенту — defense-in-depth).
var ErrInvalidToken = errors.New("jwks: invalid token")

// defaultTTL — TTL кэша JWKS (fallback, если сервер не задал Cache-Control).
const defaultTTL = 5 * time.Minute

// Verifier — потокобезопасный верификатор identity-JWT по IAM JWKS.
type Verifier struct {
	jwksURL string
	aud     string        // ожидаемый audience (наш service); обязателен
	iss     string        // ожидаемый issuer; "" → проверка iss пропускается
	ttl     time.Duration // TTL кэша ключей
	http    *http.Client
	now     func() time.Time

	mu      sync.Mutex
	keys    map[string]*rsa.PublicKey
	fetched time.Time
}

// New строит Verifier для IAM JWKS-endpoint. aud — обязательный expected audience
// (наш service, напр. "registry.kacho.local"); iss — опциональный expected issuer
// (пусто → не проверяется).
func New(jwksURL, aud, iss string) *Verifier {
	return &Verifier{
		jwksURL: jwksURL,
		aud:     aud,
		iss:     iss,
		ttl:     defaultTTL,
		http:    &http.Client{Timeout: 10 * time.Second},
		now:     time.Now,
		keys:    map[string]*rsa.PublicKey{},
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

// Verify верифицирует Bearer-JWT и возвращает identity (`sub`). Энфорс: RS256-подпись
// по JWKS-ключу (kid) + exp>now + aud==наш service + (если задан) iss. Любое
// нарушение → ErrInvalidToken.
func (v *Verifier) Verify(ctx context.Context, raw string) (string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("%w: not a compact JWS", ErrInvalidToken)
	}

	var hdr jwtHeader
	if err := decodeSegment(parts[0], &hdr); err != nil {
		return "", fmt.Errorf("%w: bad header", ErrInvalidToken)
	}
	if hdr.Alg != "RS256" {
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
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig); err != nil {
		return "", fmt.Errorf("%w: signature mismatch", ErrInvalidToken)
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

// keyFor возвращает RSA-pubkey по kid. Свежий кэш с этим kid → отдаём сразу; иначе
// рефетч JWKS (key rotation). JWKS недоступен + ключа в кэше нет → ошибка
// (fail-closed); ключ есть, но кэш протух и рефетч упал → используем кэш (ключ
// по-прежнему IAM'овский, безопасно).
func (v *Verifier) keyFor(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	key, ok := v.keys[kid]
	fresh := v.now().Sub(v.fetched) < v.ttl
	v.mu.Unlock()
	if ok && fresh {
		return key, nil
	}

	if err := v.refresh(ctx); err != nil {
		if ok {
			return key, nil // stale-но-известный ключ безопаснее, чем отказ
		}
		return nil, err
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("unknown kid %q", kid)
}

// refresh тянет JWKS и перестраивает кэш RSA-ключей. Любой сбой фетча/парсинга →
// ошибка (caller fail-closed либо fallback на кэш).
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

	fresh := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		pub, perr := k.toRSA()
		if perr != nil {
			continue // битый ключ пропускаем (остальные валидны)
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

// jsonWebKey — RSA JWK (RFC 7517): n/e — base64url big-endian.
type jsonWebKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
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
