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
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
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
	// cacheControl — значение заголовка Cache-Control ответа JWKS. Пусто → дефолт
	// "max-age=300"; тест TTL-клампа выставляет заведомо огромный max-age.
	cacheControl string
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// ecXY возвращает big-endian координаты X/Y публичного P-256 ключа (по 32 байта),
// не обращаясь к deprecated ecdsa.PublicKey.X/Y (SA1019, deprecated since Go 1.26).
// Uncompressed SEC1-точка из crypto/ecdh: 0x04 || X(32) || Y(32).
func ecXY(key *ecdsa.PrivateKey) (x, y []byte) {
	pub, err := key.PublicKey.ECDH()
	if err != nil {
		panic(fmt.Sprintf("ec public key → ecdh (P-256 expected): %v", err))
	}
	raw := pub.Bytes()
	return raw[1:33], raw[33:65]
}

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
		cc := js.cacheControl
		if cc == "" {
			cc = "max-age=300"
		}
		w.Header().Set("Cache-Control", cc)
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
			"n":   b64u(key.N.Bytes()),
			"e":   b64u(big.NewInt(int64(key.E)).Bytes()),
		})
	}
	for kid, key := range js.ecKeys {
		x, y := ecXY(key)
		keys = append(keys, map[string]any{
			"kty": "EC",
			"crv": "P-256",
			"alg": "ES256",
			"use": "sig",
			"kid": kid,
			"x":   b64u(x),
			"y":   b64u(y),
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

// REG-TX-21 alg-guard — cross-type key/alg confusion: заголовок объявляет один alg,
// а kid резолвится в ключ ДРУГОГО типа (ES256 header ↔ RSA key, RS256 header ↔ EC key).
// verifySignature обязан отвергнуть по type-assertion ("key type mismatch"), НЕ подсунув
// ключ не того типа в проверку подписи (иначе — вектор forgery при adverse key-config).
// Пиннит обе ветви `if !ok` в verifySignature (RS256/ES256), которые до этого не
// покрывались ни одним negative-тестом (все прочие кейсы — off-allowlist alg / bad sig).
func TestJWKS_Verify_KeyTypeAlgConfusion_Rejected(t *testing.T) {
	// header alg=ES256, но kid указывает на RSA-ключ → key.(*ecdsa.PublicKey) не проходит.
	t.Run("es256-header-over-rsa-key", func(t *testing.T) {
		js := newJWKSServer(t, "kid-rsa")
		v := New(js.srv.URL, testAud, testHydraIss)
		signingInput := joseSigningInput("ES256", "kid-rsa", hydraClaims("cid-ci", time.Now().Add(time.Hour)))
		// подпись-заглушка нужной для ES256 длины (64B) — type-assert падает ДО её проверки.
		tok := signingInput + "." + b64u(make([]byte, 64))
		_, err := v.Verify(context.Background(), tok)
		require.ErrorIs(t, err, ErrInvalidToken)
	})
	// header alg=RS256, но kid указывает на EC-ключ → key.(*rsa.PublicKey) не проходит.
	t.Run("rs256-header-over-ec-key", func(t *testing.T) {
		js := newJWKSServer(t)
		js.addEC(t, "kid-ec")
		v := New(js.srv.URL, testAud, testHydraIss)
		signingInput := joseSigningInput("RS256", "kid-ec", hydraClaims("cid-ci", time.Now().Add(time.Hour)))
		tok := signingInput + "." + b64u([]byte("stub-signature"))
		_, err := v.Verify(context.Background(), tok)
		require.ErrorIs(t, err, ErrInvalidToken)
	})
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
// Рефетч по неизвестному kid'у троттлится (minRefresh), поэтому второй Verify
// выполняется по часам, продвинутым за окно троттла (иначе — throttled-fail).
func TestJWKS_Verify_RefetchOnUnknownKid(t *testing.T) {
	js := newJWKSServer(t, "kid-rsa")
	v := New(js.srv.URL, testAud, testHydraIss)
	clock := time.Now()
	v.now = func() time.Time { return clock }

	tok1 := js.mintRS256(t, "kid-rsa", hydraClaims("cid-ci", clock.Add(time.Hour)))
	_, err := v.Verify(context.Background(), tok1)
	require.NoError(t, err)
	require.Equal(t, int32(1), js.fetch.Load())

	// ротация Hydra: добавляем ES256 kid-ec2 в JWKS. Продвигаем часы за окно троттла
	// (кэш ещё свеж по TTL: minRefresh << ttl), чтобы рефетч по новому kid'у не был
	// подавлен троттлом.
	js.addEC(t, "kid-ec2")
	clock = clock.Add(defaultMinRefresh + time.Second)
	tok2 := js.mintES256(t, "kid-ec2", hydraClaims("cid-ci2", clock.Add(time.Hour)))

	sub, err := v.Verify(context.Background(), tok2)
	require.NoError(t, err)
	require.Equal(t, "cid-ci2", sub)
	require.Equal(t, int32(2), js.fetch.Load(), "unknown kid triggered a refetch")
}

// SEC (CWE-770/400) — флуд токенов со свежим случайным kid не должен форсить рефетч
// JWKS на каждый запрос: после первого успешного фетча неизвестный kid в пределах окна
// minRefresh получает throttled-fail БЕЗ дополнительного outbound-GET (pre-auth
// DoS-амплификация закрыта).
func TestJWKS_Verify_UnknownKidThrottled_NoRefetch(t *testing.T) {
	js := newJWKSServer(t, "kid-rsa")
	v := New(js.srv.URL, testAud, testHydraIss)
	clock := time.Now()
	v.now = func() time.Time { return clock }

	tok := js.mintRS256(t, "kid-rsa", hydraClaims("cid-ci", clock.Add(time.Hour)))
	_, err := v.Verify(context.Background(), tok)
	require.NoError(t, err)
	require.Equal(t, int32(1), js.fetch.Load())

	// Тот же момент времени (внутри окна minRefresh): 5 токенов с разными случайными
	// kid'ами. Ни один не форсит рефетч — kid читается до верификации подписи.
	for i := 0; i < 5; i++ {
		bogus := joseSigningInput("RS256", fmt.Sprintf("bogus-%d", i),
			hydraClaims("cid-x", clock.Add(time.Hour))) + ".QUFB"
		_, verr := v.Verify(context.Background(), bogus)
		require.Error(t, verr)
	}
	require.Equal(t, int32(1), js.fetch.Load(),
		"unknown-kid flood within minRefresh must not trigger additional JWKS fetches")
}

// SEC (CWE-770/400) — конкурентный флуд неизвестных kid'ов коллапсирует в один рефетч:
// слот рефетча захватывается под lock'ом до отпускания на HTTP-GET, поэтому N
// одновременных промахов не веерятся в N исходящих JWKS-фетчей (thundering herd).
func TestJWKS_Verify_ConcurrentUnknownKid_BoundsRefetch(t *testing.T) {
	js := newJWKSServer(t, "kid-rsa")
	v := New(js.srv.URL, testAud, testHydraIss)
	clock := time.Now()
	v.now = func() time.Time { return clock }

	tok := js.mintRS256(t, "kid-rsa", hydraClaims("cid-ci", clock.Add(time.Hour)))
	_, err := v.Verify(context.Background(), tok)
	require.NoError(t, err)
	require.Equal(t, int32(1), js.fetch.Load())

	// Продвигаем часы за окно троттла, затем стартуем конкурентный флуд. Ровно один
	// goroutine захватывает слот рефетча; остальные — throttled-fail. clock после этой
	// строки не мутируется — конкурентное чтение из v.now безопасно.
	clock = clock.Add(defaultMinRefresh + time.Second)

	const n = 16
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			bogus := joseSigningInput("RS256", fmt.Sprintf("cc-bogus-%d", i),
				hydraClaims("cid-x", clock.Add(time.Hour))) + ".QUFB"
			_, _ = v.Verify(context.Background(), bogus)
		}(i)
	}
	wg.Wait()
	require.Equal(t, int32(2), js.fetch.Load(),
		"concurrent unknown-kid flood must collapse to a single JWKS refetch")
}

// SEC/avail (audit-r11, concurrency) — рефетч JWKS не должен исполняться на request-ctx
// вызывающего: отмена/RST одного клиента (включая pre-auth флуд attacker-controlled kid'ов
// с немедленным RST) не должна ни срывать общий фетч ключей, ни жечь троттл-слот, блокируя
// подхват ротации для всех остальных. Победитель слота рефетча с УЖЕ ОТМЕНЁННЫМ ctx обязан
// всё равно довести фетч (detached ctx), иначе легитимный токен, подписанный только что
// ротированным ключом, отвергается как "unknown kid" на всё окно minRefresh.
func TestJWKS_Verify_RefreshDetachedFromRequestCtx(t *testing.T) {
	js := newJWKSServer(t, "kid-rsa")
	v := New(js.srv.URL, testAud, testHydraIss)
	clock := time.Now()
	v.now = func() time.Time { return clock }

	// Первый Verify: наполняем кэш (kid-rsa), fetch=1.
	tok := js.mintRS256(t, "kid-rsa", hydraClaims("cid-ci", clock.Add(24*time.Hour)))
	_, err := v.Verify(context.Background(), tok)
	require.NoError(t, err)
	require.Equal(t, int32(1), js.fetch.Load())

	// Ротация Hydra: добавлен новый ES256-ключ kid-ec2. Часы за окном TTL (max-age=300) →
	// следующий Verify инициирует рефетч.
	js.addEC(t, "kid-ec2")
	clock = clock.Add(6 * time.Minute)

	// «Атакующий» захватывает слот рефетча запросом с УЖЕ ОТМЕНЁННЫМ ctx (модель
	// disconnect/RST победителя слота). Его собственный Verify падает (bogus kid), но общий
	// фетч ключей не должен быть сорван его отменой, а троттл-слот — сожжён впустую.
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	bogus := joseSigningInput("RS256", "attacker-kid", hydraClaims("cid-x", clock.Add(time.Hour))) + ".QUFB"
	_, _ = v.Verify(canceled, bogus)

	// Легитимный токен, подписанный только что ротированным kid-ec2, в пределах окна
	// minRefresh после хода атакующего. С рефетчем на request-ctx атакующего фетч сорвался,
	// троттл-слот сожжён → здесь был бы "unknown kid". С detached-ctx рефетч довёл ключи —
	// токен верифицируется.
	tok2 := js.mintES256(t, "kid-ec2", hydraClaims("cid-ci2", clock.Add(time.Hour)))
	sub, err := v.Verify(context.Background(), tok2)
	require.NoError(t, err,
		"legit token signed by a freshly-rotated key must verify; a disconnecting client's canceled ctx must not poison the shared JWKS refresh")
	require.Equal(t, "cid-ci2", sub)
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

// SEC/avail (audit-r1, CWE-770) — транзиентный сбой рефетча JWKS не должен блокировать
// уже-закэшированные ИЗВЕСТНЫЕ kid'ы на всё окно minRefresh. Троттл существует против
// флуда attacker-controlled НЕИЗВЕСТНЫХ kid'ов (каждый форсил бы outbound-GET); известный
// kid — из конечного набора реальных ключей, для амплификации непригоден и обязан
// обслуживаться из кэша, пока троттл-окно активно. Иначе один сетевой blip рефетча
// амплифицируется в minRefresh-окно тотального auth-отказа для валидных токенов.
func TestJWKS_Verify_KnownKidServedFromCache_WhileRefetchThrottled(t *testing.T) {
	js := newJWKSServer(t, "kid-rsa") // Cache-Control: max-age=300
	v := New(js.srv.URL, testAud, testHydraIss)
	clock := time.Now()
	v.now = func() time.Time { return clock }

	tok := js.mintRS256(t, "kid-rsa", hydraClaims("cid-ci", clock.Add(24*time.Hour)))
	sub, err := v.Verify(context.Background(), tok)
	require.NoError(t, err)
	require.Equal(t, "cid-ci", sub)
	require.Equal(t, int32(1), js.fetch.Load())

	// TTL кэша (max-age=300) истёк → следующий Verify инициирует рефетч. JWKS ложится
	// (транзиентный blip): этот один рефетч-запрос падает fail-closed и захватывает
	// троттл-слот (lastRefresh = now).
	clock = clock.Add(6 * time.Minute)
	js.srv.Close()
	_, err = v.Verify(context.Background(), tok)
	require.Error(t, err, "the refetch-triggering request fails closed while JWKS is down")

	// В пределах окна minRefresh после неудачного рефетча повторный Verify того же
	// ИЗВЕСТНОГО kid'а обязан обслужиться из кэша, а не быть отклонён как «unknown kid».
	sub, err = v.Verify(context.Background(), tok)
	require.NoError(t, err, "known cached kid must be served during the refetch throttle window")
	require.Equal(t, "cid-ci", sub)
}

// SEC (CWE-613) — сервер JWKS отдаёт непомерный Cache-Control max-age → verifier
// НЕ должен адоптировать его дословно: TTL кэша клампится до maxTTL, иначе
// ротированный/отозванный ключ оставался бы валидным годами (нарушение fail-closed
// rotation-инварианта пакета). После refresh (первый Verify) v.ttl <= maxTTL.
func TestJWKS_Verify_CacheControlTTL_ClampedToMax(t *testing.T) {
	js := newJWKSServer(t, "kid-rsa")
	js.cacheControl = "max-age=999999999" // ~31 год
	v := New(js.srv.URL, testAud, testHydraIss)

	clock := time.Now()
	v.now = func() time.Time { return clock }

	tok := js.mintRS256(t, "kid-rsa", hydraClaims("cid-ci", clock.Add(time.Hour)))
	_, err := v.Verify(context.Background(), tok)
	require.NoError(t, err)

	v.mu.Lock()
	got := v.ttl
	v.mu.Unlock()
	require.LessOrEqual(t, got, maxTTL,
		"server-supplied max-age must be clamped to maxTTL (rotated key must not stay cached ~31y)")
	require.Greater(t, got, time.Duration(0))
}

// Malformed token (не три сегмента) → отвергается.
func TestJWKS_Verify_Malformed(t *testing.T) {
	js := newJWKSServer(t, "kid-rsa")
	v := New(js.srv.URL, testAud, testHydraIss)
	_, err := v.Verify(context.Background(), "not-a-jwt")
	require.Error(t, err)
}

// rsaJWK строит jsonWebKey (kty=RSA) из публичной части RSA-ключа (base64url n/e).
func rsaJWK(pub *rsa.PublicKey) jsonWebKey {
	return jsonWebKey{
		Kty: "RSA",
		N:   b64u(pub.N.Bytes()),
		E:   b64u(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// SEC — слишком короткий RSA-модуль (< 2048 бит) — риск подделки токена: атакующий
// может факторизовать модуль и подписать произвольный JWT. toRSA обязан отвергнуть
// такой ключ с внятной ошибкой, чтобы он не попал в кэш верификатора.
func TestJWKS_toRSA_RejectsSmallModulus(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	_, err = rsaJWK(&small.PublicKey).toRSA()
	require.Error(t, err)
	require.Contains(t, err.Error(), "modulus")
}

// SEC — нормальный 2048-битный ключ (Ory Hydra default) проходит toRSA без изменений
// поведения (регресс-страховка к минимальному размеру модуля).
func TestJWKS_toRSA_Accepts2048(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	got, err := rsaJWK(&key.PublicKey).toRSA()
	require.NoError(t, err)
	require.Equal(t, 0, key.N.Cmp(got.N))
	require.Equal(t, key.E, got.E)
}

// SEC (end-to-end) — JWKS с коротким (1024-бит) RSA-ключом: refresh пропускает такой
// ключ, поэтому токен, подписанный им, отвергается (kid не попал в кэш). Верификатор
// не должен принимать forgeable-токен даже если Hydra по ошибке отдала слабый ключ.
func TestJWKS_Verify_SmallModulusKey_Rejected(t *testing.T) {
	js := newJWKSServer(t)
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	js.rsaKeys["kid-weak"] = weak
	v := New(js.srv.URL, testAud, testHydraIss)
	tok := js.mintRS256(t, "kid-weak", hydraClaims("cid-ci", time.Now().Add(time.Hour)))

	_, err = v.Verify(context.Background(), tok)
	require.Error(t, err)
}
