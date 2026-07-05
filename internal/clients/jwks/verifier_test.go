// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package jwks

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	testAud      = "registry.kacho.local"
	testHydraIss = "https://hydra.api.kacho.cloud"
)

// jwksServer поднимает httptest Hydra-JWKS с RSA- и/или EC-ключами и считает число
// фетчей (для проверки кэша/рефетча по неизвестному kid). Hydra отдаёт RS256 ИЛИ
// ES256 — оба алгоритма верифицируются data-plane по одному JWKS.
type jwksServer struct {
	srv     *httptest.Server
	fetch   atomic.Int32
	rsaKeys map[string]*rsa.PrivateKey
	ecKeys  map[string]*ecdsa.PrivateKey
	docFor  func() map[string]any
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// padTo дополняет big-endian координату слева нулями до фиксированной длины (EC JWK
// x/y и raw ES256 r||s — ровно по 32 байта для P-256).
func padTo(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

func newJWKSServer(t *testing.T, rsaKids ...string) *jwksServer {
	t.Helper()
	js := &jwksServer{
		rsaKeys: map[string]*rsa.PrivateKey{},
		ecKeys:  map[string]*ecdsa.PrivateKey{},
	}
	for _, kid := range rsaKids {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		js.rsaKeys[kid] = key
	}
	js.docFor = js.defaultDoc
	js.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		js.fetch.Add(1)
		w.Header().Set("Cache-Control", "max-age=300")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(js.docFor())
	}))
	t.Cleanup(js.srv.Close)
	return js
}

// addEC генерирует P-256 EC-ключ (ES256) и кладёт его в JWKS под kid.
func (js *jwksServer) addEC(t *testing.T, kid string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	js.ecKeys[kid] = key
}

func (js *jwksServer) defaultDoc() map[string]any {
	keys := make([]map[string]any, 0, len(js.rsaKeys)+len(js.ecKeys))
	for kid, key := range js.rsaKeys {
		keys = append(keys, map[string]any{
			"kty": "RSA",
			"alg": "RS256",
			"use": "sig",
			"kid": kid,
			"n":   b64u(key.PublicKey.N.Bytes()),
			"e":   b64u(big.NewInt(int64(key.PublicKey.E)).Bytes()),
		})
	}
	for kid, key := range js.ecKeys {
		keys = append(keys, map[string]any{
			"kty": "EC",
			"crv": "P-256",
			"alg": "ES256",
			"use": "sig",
			"kid": kid,
			"x":   b64u(padTo(key.PublicKey.X.Bytes(), 32)),
			"y":   b64u(padTo(key.PublicKey.Y.Bytes(), 32)),
		})
	}
	return map[string]any{"keys": keys}
}

// mintRS256 чеканит RS256-JWT, подписанный ключом kid из сервера.
func (js *jwksServer) mintRS256(t *testing.T, kid string, claims map[string]any) string {
	t.Helper()
	key, ok := js.rsaKeys[kid]
	require.True(t, ok, "unknown test RSA kid %q", kid)
	signingInput := joseSigningInput("RS256", kid, claims)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	require.NoError(t, err)
	return signingInput + "." + b64u(sig)
}

// mintES256 чеканит ES256-JWT (raw r||s, по 32 байта), подписанный EC-ключом kid.
func (js *jwksServer) mintES256(t *testing.T, kid string, claims map[string]any) string {
	t.Helper()
	key, ok := js.ecKeys[kid]
	require.True(t, ok, "unknown test EC kid %q", kid)
	signingInput := joseSigningInput("ES256", kid, claims)
	sum := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	require.NoError(t, err)
	sig := append(padTo(r.Bytes(), 32), padTo(s.Bytes(), 32)...)
	return signingInput + "." + b64u(sig)
}

func joseSigningInput(alg, kid string, claims map[string]any) string {
	header := map[string]any{"alg": alg, "typ": "JWT", "kid": kid}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	return b64u(hb) + "." + b64u(cb)
}

// hydraClaims — Hydra-issued identity-JWT: sub = client_id (принципал для Check),
// aud ⊇ наш service, iss = Hydra.
func hydraClaims(sub string, exp time.Time) map[string]any {
	return map[string]any{"sub": sub, "aud": testAud, "iss": testHydraIss, "exp": exp.Unix()}
}

// REG-TX-13 — валидный Hydra RS256-JWT (Ory default) → Verify возвращает sub.
func TestJWKS_Verify_RS256_Valid(t *testing.T) {
	js := newJWKSServer(t, "kid-rsa")
	v := New(js.srv.URL, testAud, testHydraIss)
	tok := js.mintRS256(t, "kid-rsa", hydraClaims("cid-ci", time.Now().Add(time.Hour)))

	sub, err := v.Verify(context.Background(), tok)
	require.NoError(t, err)
	require.Equal(t, "cid-ci", sub)
}

// REG-TX-13 — валидный Hydra ES256-JWT → Verify возвращает sub. Hydra может отдавать
// как RS256, так и ES256 — data-plane обязан верифицировать оба по одному JWKS.
func TestJWKS_Verify_ES256_Valid(t *testing.T) {
	js := newJWKSServer(t)
	js.addEC(t, "kid-ec")
	v := New(js.srv.URL, testAud, testHydraIss)
	tok := js.mintES256(t, "kid-ec", hydraClaims("cid-ci", time.Now().Add(time.Hour)))

	sub, err := v.Verify(context.Background(), tok)
	require.NoError(t, err)
	require.Equal(t, "cid-ci", sub)
}

// Федеративный SA-токен: Hydra `sub` — это client_id, а Kachō principal id (sva…/usr…)
// лежит в `ext.ext_claims.kacho_principal_id` (обогащение IAM token-hook'а). Verify
// обязан вернуть principal id, а не сырой client_id — иначе data-plane authz Check
// целится в несуществующий service_account:<client_id> и отказывает любой push/pull.
func TestJWKS_Verify_ReturnsKachoPrincipalID(t *testing.T) {
	js := newJWKSServer(t, "kid-rsa")
	v := New(js.srv.URL, testAud, testHydraIss)
	claims := hydraClaims("81f92eee-client-uuid", time.Now().Add(time.Hour))
	claims["ext"] = map[string]any{"ext_claims": map[string]any{"kacho_principal_id": "svaz7x4kcr58s59fx75v"}}
	tok := js.mintRS256(t, "kid-rsa", claims)

	principal, err := v.Verify(context.Background(), tok)
	require.NoError(t, err)
	require.Equal(t, "svaz7x4kcr58s59fx75v", principal)
}

// Токен без обогащения (ext отсутствует) → Verify падает обратно на `sub`
// (back-compat: user-OIDC / not-yet-enriched токены).
func TestJWKS_Verify_FallsBackToSubWhenNoPrincipalClaim(t *testing.T) {
	js := newJWKSServer(t, "kid-rsa")
	v := New(js.srv.URL, testAud, testHydraIss)
	tok := js.mintRS256(t, "kid-rsa", hydraClaims("usr-bare", time.Now().Add(time.Hour)))

	sub, err := v.Verify(context.Background(), tok)
	require.NoError(t, err)
	require.Equal(t, "usr-bare", sub)
}

// REG-TX-13 — истёкший Hydra-JWT → 401 (invalid_token на стороне proxy).
func TestJWKS_Verify_Expired(t *testing.T) {
	js := newJWKSServer(t, "kid-rsa")
	v := New(js.srv.URL, testAud, testHydraIss)
	tok := js.mintRS256(t, "kid-rsa", hydraClaims("cid-ci", time.Now().Add(-time.Minute)))

	_, err := v.Verify(context.Background(), tok)
	require.Error(t, err)
}

// REG-TX-05/13 — wrong audience (токен для другого service) → отвергается.
func TestJWKS_Verify_WrongAudience(t *testing.T) {
	js := newJWKSServer(t, "kid-rsa")
	v := New(js.srv.URL, testAud, testHydraIss)
	claims := hydraClaims("cid-ci", time.Now().Add(time.Hour))
	claims["aud"] = "some-other-service"
	tok := js.mintRS256(t, "kid-rsa", claims)

	_, err := v.Verify(context.Background(), tok)
	require.Error(t, err)
}

// REG-TX-13 — wrong issuer (iss ≠ Hydra) → отвергается (старый IAM-native токен /
// чужой issuer после переключения не принимается).
func TestJWKS_Verify_WrongIssuer(t *testing.T) {
	js := newJWKSServer(t, "kid-rsa")
	v := New(js.srv.URL, testAud, testHydraIss)
	claims := hydraClaims("cid-ci", time.Now().Add(time.Hour))
	claims["iss"] = "https://api.kacho.local/iam/token" // старый IAM-native issuer
	tok := js.mintRS256(t, "kid-rsa", claims)

	_, err := v.Verify(context.Background(), tok)
	require.Error(t, err)
}

// REG-TX-13 — самоподписанный/чужой ключ (kid не в Hydra JWKS) → отвергается.
func TestJWKS_Verify_UnknownKid(t *testing.T) {
	js := newJWKSServer(t, "kid-rsa")
	// подписываем ключом, которого нет в JWKS.
	rogue, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	js.rsaKeys["kid-rogue"] = rogue
	tok := js.mintRS256(t, "kid-rogue", hydraClaims("cid-ci", time.Now().Add(time.Hour)))
	delete(js.rsaKeys, "kid-rogue") // JWKS больше его не отдаёт

	v := New(js.srv.URL, testAud, testHydraIss)
	_, err = v.Verify(context.Background(), tok)
	require.Error(t, err)
}

// REG-TX-13 — подпись не сходится (tampered payload) → отвергается.
func TestJWKS_Verify_BadSignature(t *testing.T) {
	js := newJWKSServer(t, "kid-rsa")
	v := New(js.srv.URL, testAud, testHydraIss)
	tok := js.mintRS256(t, "kid-rsa", hydraClaims("cid-ci", time.Now().Add(time.Hour)))
	tampered := tok[:len(tok)-2] + "AA"
	_, err := v.Verify(context.Background(), tampered)
	require.Error(t, err)
}

// REG-TX-21 alg-guard — HS256 (symmetric) → отвергается: RSA/EC pubkey из JWKS нельзя
// подсунуть как HMAC-секрет (alg-confusion). Allowlist — только {RS256, ES256}.
func TestJWKS_Verify_HS256_Rejected(t *testing.T) {
	js := newJWKSServer(t, "kid-rsa")
	v := New(js.srv.URL, testAud, testHydraIss)
	signingInput := joseSigningInput("HS256", "kid-rsa", hydraClaims("cid-ci", time.Now().Add(time.Hour)))
	tok := signingInput + "." + b64u([]byte("sig"))
	_, err := v.Verify(context.Background(), tok)
	require.Error(t, err)
}

// REG-TX-21 alg-guard — alg=none (unsigned) → отвергается. Никогда не принимать none.
func TestJWKS_Verify_NoneAlg_Rejected(t *testing.T) {
	js := newJWKSServer(t, "kid-rsa")
	v := New(js.srv.URL, testAud, testHydraIss)
	signingInput := joseSigningInput("none", "kid-rsa", hydraClaims("cid-ci", time.Now().Add(time.Hour)))
	tok := signingInput + "." // пустая подпись
	_, err := v.Verify(context.Background(), tok)
	require.Error(t, err)
}

// JWKS кэшируется (TTL): повторные Verify известным kid не рефетчат JWKS.
func TestJWKS_Verify_Caches(t *testing.T) {
	js := newJWKSServer(t, "kid-rsa")
	v := New(js.srv.URL, testAud, testHydraIss)
	for i := 0; i < 3; i++ {
		tok := js.mintRS256(t, "kid-rsa", hydraClaims("cid-ci", time.Now().Add(time.Hour)))
		_, err := v.Verify(context.Background(), tok)
		require.NoError(t, err)
	}
	require.Equal(t, int32(1), js.fetch.Load(), "JWKS fetched once, then cached")
}

// REG-TX-21(b) — неизвестный kid → рефетч JWKS (key rotation). Новый ES256-ключ,
// добавленный Hydra после первого фетча, подхватывается рефетчем → verify OK.
func TestJWKS_Verify_RefetchOnUnknownKid(t *testing.T) {
	js := newJWKSServer(t, "kid-rsa")
	v := New(js.srv.URL, testAud, testHydraIss)

	tok1 := js.mintRS256(t, "kid-rsa", hydraClaims("cid-ci", time.Now().Add(time.Hour)))
	_, err := v.Verify(context.Background(), tok1)
	require.NoError(t, err)
	require.Equal(t, int32(1), js.fetch.Load())

	// ротация Hydra: добавляем ES256 kid-ec2 в JWKS.
	js.addEC(t, "kid-ec2")
	tok2 := js.mintES256(t, "kid-ec2", hydraClaims("cid-ci2", time.Now().Add(time.Hour)))

	sub, err := v.Verify(context.Background(), tok2)
	require.NoError(t, err)
	require.Equal(t, "cid-ci2", sub)
	require.Equal(t, int32(2), js.fetch.Load(), "unknown kid triggered a refetch")
}

// REG-TX-21(a) — JWKS недоступен И ключа нет в кэше → fail-closed (не пропускаем).
func TestJWKS_Verify_JWKSUnreachable_FailClosed(t *testing.T) {
	js := newJWKSServer(t, "kid-rsa")
	tok := js.mintRS256(t, "kid-rsa", hydraClaims("cid-ci", time.Now().Add(time.Hour)))
	js.srv.Close() // JWKS больше недоступен, кэш пуст

	v := New(js.srv.URL, testAud, testHydraIss)
	_, err := v.Verify(context.Background(), tok)
	require.Error(t, err)
}

// REG-TX-21 cache-TTL инвариант — по истечении TTL кэш не обслуживается «вечно»: если
// JWKS недоступен, а закэшированные ключи протухли, verify известного kid всё равно
// fail-closed (ротированный/отозванный ключ не остаётся валидным бесконечно).
func TestJWKS_Verify_StaleCacheJWKSDown_FailClosed(t *testing.T) {
	js := newJWKSServer(t, "kid-rsa") // JWKS отдаёт Cache-Control: max-age=300
	v := New(js.srv.URL, testAud, testHydraIss)

	clock := time.Now()
	v.now = func() time.Time { return clock }

	tok := js.mintRS256(t, "kid-rsa", hydraClaims("cid-ci", clock.Add(time.Hour)))
	sub, err := v.Verify(context.Background(), tok)
	require.NoError(t, err)
	require.Equal(t, "cid-ci", sub)
	require.Equal(t, int32(1), js.fetch.Load())

	// Кэш-TTL (max-age=300) истёк + Hydra JWKS недоступен → рефетч падает.
	clock = clock.Add(6 * time.Minute)
	js.srv.Close()

	_, err = v.Verify(context.Background(), tok)
	require.Error(t, err, "stale cache must not be served after TTL when JWKS is down")
}

// Malformed token (не три сегмента) → отвергается.
func TestJWKS_Verify_Malformed(t *testing.T) {
	js := newJWKSServer(t, "kid-rsa")
	v := New(js.srv.URL, testAud, testHydraIss)
	_, err := v.Verify(context.Background(), "not-a-jwt")
	require.Error(t, err)
}
