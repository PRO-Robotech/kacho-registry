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
	"io"
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

// maxTTL — верхняя граница TTL кэша ключей. Cache-Control max-age сервера JWKS
// клампится до этого значения: непомерный/ошибочный max-age (напр. годы) не должен
// оставлять ротированный/отозванный ключ валидным дольше окна ротации. Держит
// обещание docstring'а («ограниченный TTL ... но не бесконечно», CWE-613).
const maxTTL = time.Hour

// defaultMinRefresh — минимальный интервал между рефетчами JWKS по неизвестному kid.
// kid приходит из attacker-controlled JOSE-header и читается ДО верификации подписи;
// без троттла каждый запрос с новым случайным kid форсил бы outbound-GET на Hydra JWKS
// (pre-auth DoS-амплификация, CWE-770/400). Легитимная ротация ключа подхватывается с
// задержкой ≤ minRefresh (после первого рефетча новый kid уже в кэше — обслуживается
// мгновенно; троттлятся только по-прежнему-неизвестные kid'ы).
const defaultMinRefresh = 10 * time.Second

// maxJWKSBytes — верхняя граница размера тела JWKS-ответа (io.LimitReader перед
// json.Decode): скомпрометированный/подменённый JWKS-endpoint не может исчерпать
// память verifier'а гигантским телом (CWE-400).
const maxJWKSBytes = 1 << 20 // 1 MiB

// Verifier — потокобезопасный верификатор Hydra-issued identity-JWT по Hydra JWKS.
type Verifier struct {
	jwksURL    string
	aud        string        // ожидаемый audience (наш service); обязателен
	iss        string        // ожидаемый issuer (Hydra); "" → проверка iss пропускается
	ttl        time.Duration // ограниченный TTL кэша ключей
	minRefresh time.Duration // минимальный интервал между рефетчами по неизвестному kid
	http       *http.Client
	now        func() time.Time

	mu          sync.Mutex
	keys        map[string]crypto.PublicKey // kid → *rsa.PublicKey | *ecdsa.PublicKey
	fetched     time.Time                   // время последнего УСПЕШНОГО рефетча (TTL-база)
	lastRefresh time.Time                   // время последней ПОПЫТКИ рефетча (троттл-база, вкл. неудачные)
}

// New строит Verifier для Hydra JWKS-endpoint. aud — обязательный expected audience
// (наш service, напр. "registry.kacho.local"); iss — опциональный expected issuer
// (Hydra; пусто → не проверяется).
func New(jwksURL, aud, iss string) *Verifier {
	return &Verifier{
		jwksURL:    jwksURL,
		aud:        aud,
		iss:        iss,
		ttl:        defaultTTL,
		minRefresh: defaultMinRefresh,
		http:       &http.Client{Timeout: 10 * time.Second},
		now:        time.Now,
		keys:       map[string]crypto.PublicKey{},
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
	// Ext — обёртка обогащения Hydra token-hook'а. Для федеративного SA/user токена
	// (client_credentials / jwt-bearer) `sub` — это Hydra client_id, а реальный
	// Kachō principal id (sva…/usr…) IAM штампует в ext.ext_claims.kacho_principal_id.
	Ext struct {
		ExtClaims struct {
			KachoPrincipalID string `json:"kacho_principal_id"`
		} `json:"ext_claims"`
	} `json:"ext"`
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
	// Kachō principal id (sva…/usr…) — источник истины authz-subject'а. Для
	// федеративного токена Hydra `sub` несёт client_id, а principal id обогащён
	// token-hook'ом в ext.ext_claims.kacho_principal_id. Пусто (необогащённый
	// user-OIDC / back-compat) → падаем обратно на `sub`.
	if pid := claims.Ext.ExtClaims.KachoPrincipalID; pid != "" {
		return pid, nil
	}
	return claims.Sub, nil
}

// keyFor возвращает публичный ключ по kid. Свежий кэш с этим kid → отдаём сразу; иначе
// один рефетч JWKS (key rotation). Рефетч не удался → отказ (fail-closed): по
// устаревшему кэшу не обслуживаем, чтобы ротированный/отозванный ключ не оставался
// валидным без ограничения TTL. Рефетч удался, но kid по-прежнему нет → отказ.
//
// Троттл (CWE-770/400): kid берётся из attacker-controlled JOSE-header ДО верификации
// подписи, поэтому рефетч ограничен одним на окно minRefresh. Слот рефетча захватывается
// под lock'ом ДО отпускания его на outbound-GET, поэтому конкурентные промахи (флуд
// случайных kid) коллапсируют в один фетч (не thundering herd), а не в N одновременных
// исходящих HTTPS-соединений. Троттлятся только по-прежнему-НЕИЗВЕСТНЫЕ kid'ы: если kid
// уже в кэше (протух по TTL, но известен), при активном троттл-окне он обслуживается из
// кэша — транзиентный сбой рефетча не блокирует валидные токены на всё окно minRefresh.
func (v *Verifier) keyFor(ctx context.Context, kid string) (crypto.PublicKey, error) {
	v.mu.Lock()
	now := v.now()
	key, ok := v.keys[kid]
	fresh := now.Sub(v.fetched) < v.ttl
	if ok && fresh {
		v.mu.Unlock()
		return key, nil
	}
	// Нужен рефетч (протухший кэш ИЛИ неизвестный kid). Троттлим: не чаще одного
	// рефетча на minRefresh. Захватываем слот (lastRefresh = now) под lock'ом до
	// отпускания его на HTTP-GET — конкурентные промахи в этом окне получают
	// throttled-fail, а не собственный outbound-фетч.
	if now.Sub(v.lastRefresh) < v.minRefresh {
		v.mu.Unlock()
		// Троттл — DoS-guard против флуда attacker-controlled НЕИЗВЕСТНЫХ kid'ов (каждый
		// форсил бы outbound-GET). Известный (уже в кэше) kid — из конечного набора
		// реальных ключей, для амплификации непригоден: при активном троттл-окне (недавний
		// рефетч, в т.ч. транзиентно неудачный) отдаём кэшированный ключ, а не блокируем
		// весь набор известных kid'ов как «unknown kid». Иначе один сетевой blip рефетча
		// амплифицировался бы в minRefresh-окно тотального auth-отказа для валидных токенов.
		if ok {
			return key, nil
		}
		return nil, fmt.Errorf("unknown kid %q", kid)
	}
	v.lastRefresh = now
	v.mu.Unlock()

	// Рефетч отвязан от request-ctx вызывающего: слот уже захвачен (lastRefresh
	// продвинут), поэтому отмена/RST победителя слота (в т.ч. pre-auth флуд
	// attacker-controlled kid'ов с немедленным RST) не должна ни срывать общий фетч
	// ключей, ни жечь троттл-слот, блокируя подхват ротации для остальных вызывающих.
	// Собственный дедлайн — http.Client.Timeout (как register-on-push в
	// dataplane/handler.go, отвязанный от request-ctx через context.WithoutCancel).
	fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), v.http.Timeout)
	defer cancel()
	if err := v.refresh(fetchCtx); err != nil {
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
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJWKSBytes)).Decode(&doc); err != nil {
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
	if ttl > maxTTL {
		ttl = maxTTL // кламп: непомерный server max-age не растягивает rotation-окно
	}
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
	n := new(big.Int).SetBytes(nb)
	// Минимальный размер модуля: < 2048 бит — forgeable-token risk (короткий модуль
	// факторизуется, подпись подделывается). Отвергаем, чтобы слабый ключ не попал в
	// кэш верификатора.
	if n.BitLen() < minRSAModulusBits {
		return nil, fmt.Errorf("RSA modulus too small: %d bits (min %d)", n.BitLen(), minRSAModulusBits)
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

// minRSAModulusBits — минимальный допустимый размер RSA-модуля. Ключи короче
// отвергаются как forgeable (недостаточная стойкость к факторизации).
const minRSAModulusBits = 2048

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
