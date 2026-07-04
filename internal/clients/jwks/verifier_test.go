// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package jwks

import (
	"context"
	"crypto"
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
	testAud = "registry.kacho.local"
	testIss = "https://api.kacho.local/iam/token"
)

// jwksServer поднимает httptest-JWKS с одним/несколькими RSA-ключами и считает
// число фетчей (для проверки кэша/рефетча по неизвестному kid).
type jwksServer struct {
	srv    *httptest.Server
	fetch  atomic.Int32
	keys   map[string]*rsa.PrivateKey
	docFor func() map[string]any
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func newJWKSServer(t *testing.T, kids ...string) *jwksServer {
	t.Helper()
	js := &jwksServer{keys: map[string]*rsa.PrivateKey{}}
	for _, kid := range kids {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		js.keys[kid] = key
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

func (js *jwksServer) defaultDoc() map[string]any {
	keys := make([]map[string]any, 0, len(js.keys))
	for kid, key := range js.keys {
		keys = append(keys, map[string]any{
			"kty": "RSA",
			"alg": "RS256",
			"use": "sig",
			"kid": kid,
			"n":   b64u(key.PublicKey.N.Bytes()),
			"e":   b64u(big.NewInt(int64(key.PublicKey.E)).Bytes()),
		})
	}
	return map[string]any{"keys": keys}
}

// mint чеканит RS256-JWT, подписанный ключом kid из сервера.
func (js *jwksServer) mint(t *testing.T, kid string, claims map[string]any) string {
	t.Helper()
	key, ok := js.keys[kid]
	require.True(t, ok, "unknown test kid %q", kid)
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	signingInput := b64u(hb) + "." + b64u(cb)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	require.NoError(t, err)
	return signingInput + "." + b64u(sig)
}

func stdClaims(sub string, exp time.Time) map[string]any {
	return map[string]any{"sub": sub, "aud": testAud, "iss": testIss, "exp": exp.Unix()}
}

// REG-11/REG-13 — валидный IAM-подписанный не истёкший JWT → Verify возвращает sub.
func TestJWKS_Verify_Valid(t *testing.T) {
	js := newJWKSServer(t, "kid-1")
	v := New(js.srv.URL, testAud, testIss)
	tok := js.mint(t, "kid-1", stdClaims("sva-ci", time.Now().Add(time.Hour)))

	sub, err := v.Verify(context.Background(), tok)
	require.NoError(t, err)
	require.Equal(t, "sva-ci", sub)
}

// REG-13 — истёкший JWT → ошибка (401 invalid_token на стороне proxy).
func TestJWKS_Verify_Expired(t *testing.T) {
	js := newJWKSServer(t, "kid-1")
	v := New(js.srv.URL, testAud, testIss)
	tok := js.mint(t, "kid-1", stdClaims("sva-ci", time.Now().Add(-time.Minute)))

	_, err := v.Verify(context.Background(), tok)
	require.Error(t, err)
}

// REG-13 — wrong audience (не наш service) → ошибка (токен для другого сервиса).
func TestJWKS_Verify_WrongAudience(t *testing.T) {
	js := newJWKSServer(t, "kid-1")
	v := New(js.srv.URL, testAud, testIss)
	claims := stdClaims("sva-ci", time.Now().Add(time.Hour))
	claims["aud"] = "some-other-service"
	tok := js.mint(t, "kid-1", claims)

	_, err := v.Verify(context.Background(), tok)
	require.Error(t, err)
}

// REG-13 — самоподписанный/чужой ключ (kid не в JWKS) → ошибка (не доверяем вслепую).
func TestJWKS_Verify_UnknownKid(t *testing.T) {
	js := newJWKSServer(t, "kid-1")
	// подписываем ключом, которого нет в JWKS.
	rogue, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	js.keys["kid-rogue"] = rogue
	tok := js.mint(t, "kid-rogue", stdClaims("sva-ci", time.Now().Add(time.Hour)))
	delete(js.keys, "kid-rogue") // JWKS больше его не отдаёт

	v := New(js.srv.URL, testAud, testIss)
	_, err = v.Verify(context.Background(), tok)
	require.Error(t, err)
}

// REG-13 — подпись не сходится (tampered payload) → ошибка.
func TestJWKS_Verify_BadSignature(t *testing.T) {
	js := newJWKSServer(t, "kid-1")
	v := New(js.srv.URL, testAud, testIss)
	tok := js.mint(t, "kid-1", stdClaims("sva-ci", time.Now().Add(time.Hour)))
	// портим последний символ подписи.
	tampered := tok[:len(tok)-2] + "AA"
	_, err := v.Verify(context.Background(), tampered)
	require.Error(t, err)
}

// non-RS256 alg (напр. HS256) → отклоняется (алгоритм не тот).
func TestJWKS_Verify_WrongAlg(t *testing.T) {
	js := newJWKSServer(t, "kid-1")
	v := New(js.srv.URL, testAud, testIss)
	header := map[string]any{"alg": "HS256", "typ": "JWT", "kid": "kid-1"}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(stdClaims("sva-ci", time.Now().Add(time.Hour)))
	tok := b64u(hb) + "." + b64u(cb) + "." + b64u([]byte("sig"))
	_, err := v.Verify(context.Background(), tok)
	require.Error(t, err)
}

// JWKS кэшируется (TTL): повторные Verify известным kid не рефетчат JWKS.
func TestJWKS_Verify_Caches(t *testing.T) {
	js := newJWKSServer(t, "kid-1")
	v := New(js.srv.URL, testAud, testIss)
	for i := 0; i < 3; i++ {
		tok := js.mint(t, "kid-1", stdClaims("sva-ci", time.Now().Add(time.Hour)))
		_, err := v.Verify(context.Background(), tok)
		require.NoError(t, err)
	}
	require.Equal(t, int32(1), js.fetch.Load(), "JWKS fetched once, then cached")
}

// Неизвестный kid → рефетч JWKS (key rotation). Новый ключ, добавленный в JWKS после
// первого фетча, подхватывается рефетчем.
func TestJWKS_Verify_RefetchOnUnknownKid(t *testing.T) {
	js := newJWKSServer(t, "kid-1")
	v := New(js.srv.URL, testAud, testIss)

	tok1 := js.mint(t, "kid-1", stdClaims("sva-ci", time.Now().Add(time.Hour)))
	_, err := v.Verify(context.Background(), tok1)
	require.NoError(t, err)
	require.Equal(t, int32(1), js.fetch.Load())

	// ротация: добавляем kid-2 в JWKS.
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	js.keys["kid-2"] = key2
	tok2 := js.mint(t, "kid-2", stdClaims("sva-ci2", time.Now().Add(time.Hour)))

	sub, err := v.Verify(context.Background(), tok2)
	require.NoError(t, err)
	require.Equal(t, "sva-ci2", sub)
	require.Equal(t, int32(2), js.fetch.Load(), "unknown kid triggered a refetch")
}

// Fail-closed: JWKS недоступен И ключа нет в кэше → ошибка (не пропускаем).
func TestJWKS_Verify_JWKSUnreachable_FailClosed(t *testing.T) {
	js := newJWKSServer(t, "kid-1")
	tok := js.mint(t, "kid-1", stdClaims("sva-ci", time.Now().Add(time.Hour)))
	js.srv.Close() // JWKS больше недоступен, кэш пуст

	v := New(js.srv.URL, testAud, testIss)
	_, err := v.Verify(context.Background(), tok)
	require.Error(t, err)
}

// Malformed token (не три сегмента) → ошибка.
func TestJWKS_Verify_Malformed(t *testing.T) {
	js := newJWKSServer(t, "kid-1")
	v := New(js.srv.URL, testAud, testIss)
	_, err := v.Verify(context.Background(), "not-a-jwt")
	require.Error(t, err)
}
