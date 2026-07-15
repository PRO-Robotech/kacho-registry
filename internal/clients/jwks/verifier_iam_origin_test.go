// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package jwks

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Эти тесты фиксируют поведение data-plane verifier'а ПОСЛЕ registry-iam-jwks-unify:
// JWKS теперь скачивается из iam-JWKS-proxy (а не из Hydra напрямую), но issuer-pin
// остаётся на Hydra. verifier.go — origin-agnostic (I7): он не знает и не должен знать,
// что за URL стоит за JWKS-эндпоинтом. Поэтому эти кейсы — behaviour-lock декаплинга
// (JWKS-URL=iam ⟂ issuer=Hydra, I5), fail-closed (I3) и fetch-origin (I8): они ловят
// будущую регрессию, если кто-то заодно перенаправит issuer-pin на iam или сломает
// fail-closed. testHydraIss / testAud / newJWKSServer / mintRS256 / hydraClaims —
// общий harness из verifier_test.go (тот же package).

// iamJWKSServer — семантический alias: fake iam JWKS-proxy, отдающий Hydra-mirrored
// ключи (kid/alg байт-в-байт Hydra). Для verifier'а это просто JWKS-URL.
func iamJWKSServer(t *testing.T, hydraMirroredKids ...string) *jwksServer {
	t.Helper()
	return newJWKSServer(t, hydraMirroredKids...)
}

// RJU-09 — happy: JWKS скачивается из iam-URL, Hydra-подписанный токен (iss=Hydra,
// kid=hydra-kid-1) верифицируется, issuer-pin (Hydra) совпал → verify OK. Доказывает
// I8 (fetch происходит из сконфигурированного iam-эндпоинта) + I5 (iss=Hydra проходит).
func TestJWKS_Verify_IAMOrigin_HydraIssuerPinned(t *testing.T) {
	iam := iamJWKSServer(t, "hydra-kid-1")
	// verifier направлен на iam-JWKS-URL; issuer-pin — на Hydra (раздельные knob'ы).
	v := New(iam.srv.URL, testAud, testHydraIss)
	tok := iam.mintRS256(t, "hydra-kid-1", hydraClaims("cid-ci", time.Now().Add(time.Hour)))

	sub, err := v.Verify(context.Background(), tok)
	require.NoError(t, err, "Hydra-signed token must verify against JWKS fetched from the iam proxy")
	require.Equal(t, "cid-ci", sub)
	require.GreaterOrEqual(t, iam.fetch.Load(), int32(1),
		"JWKS must be fetched from the configured iam origin")
}

// RJU-11 — fail-closed: iam-JWKS-эндпоинт недоступен и нужного ключа нет в кэше →
// Verify падает и оборачивает ErrInvalidToken (data-plane маппит ЛЮБУЮ ошибку Verify
// в HTTP 401 invalid_token). Никогда не fail-open. Доказывает I3.
func TestJWKS_Verify_IAMOrigin_Unreachable_FailClosed(t *testing.T) {
	iam := iamJWKSServer(t, "hydra-kid-1")
	tok := iam.mintRS256(t, "hydra-kid-1", hydraClaims("cid-ci", time.Now().Add(time.Hour)))
	iam.srv.Close() // iam JWKS-proxy недоступен, кэш verifier'а пуст (cold)

	v := New(iam.srv.URL, testAud, testHydraIss)
	_, err := v.Verify(context.Background(), tok)
	require.Error(t, err, "iam JWKS unreachable + cold cache must fail closed (never allow)")
	require.ErrorIs(t, err, ErrInvalidToken,
		"fail-closed Verify error must map to 401 invalid_token")
}

// RJU-13/n2 — issuer-pin остаётся на Hydra НЕСМОТРЯ на смену JWKS-URL на iam
// (декаплинг knob'ов, I5): токен подписан валидным Hydra-mirrored ключом из iam-JWKS,
// но несёт iss = iam-URL (как если бы кто-то ошибочно перенаправил issuer на iam) →
// ОТВЕРГАЕТСЯ. Ловит регрессию «заодно перепинить issuer на iam».
func TestJWKS_Verify_IAMOrigin_IssuerMismatch_Rejected(t *testing.T) {
	iam := iamJWKSServer(t, "hydra-kid-1")
	v := New(iam.srv.URL, testAud, testHydraIss) // issuer-pin остаётся Hydra
	claims := hydraClaims("cid-ci", time.Now().Add(time.Hour))
	claims["iss"] = iam.srv.URL // iss указывает на iam, а не на Hydra — mismatch
	tok := iam.mintRS256(t, "hydra-kid-1", claims)

	_, err := v.Verify(context.Background(), tok)
	require.Error(t, err, "iss-mismatch must be rejected even though JWKS now comes from iam")
	require.ErrorIs(t, err, ErrInvalidToken)
}
