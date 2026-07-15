// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/config"
	"github.com/PRO-Robotech/kacho-registry/internal/clients/jwks"
)

// b64uJSON — base64url(JSON(v)) без padding (JOSE-сегмент).
func b64uJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// TestDataplaneVerifier_FetchesJWKSFromConfiguredIAMURL (RJU-09/RJU-14) — сквозной
// wiring config → verifier: env KACHO_REGISTRY_IAM_JWKS_URL питает cfg.IAMJWKSURL,
// который serve.go передаёт в jwks.New. Тест собирает verifier тем же вызовом, что и
// buildDataplaneHandler, и доказывает, что скачивание JWKS уходит на СКОНФИГУРИРОВАННЫЙ
// iam-origin (не Hydra): fake iam-сервер записывает путь/host входящего GET. Форсит
// фетч токеном с валидным JOSE-заголовком (alg=RS256, неизвестный kid → cache-miss →
// refresh). Референс cfg.IAMJWKSURL — RED до config-rename (поле не существует).
func TestDataplaneVerifier_FetchesJWKSFromConfiguredIAMURL(t *testing.T) {
	var mu sync.Mutex
	var gotPath, gotHost string
	fetched := false

	iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotPath, gotHost, fetched = r.URL.Path, r.Host, true
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer iam.Close()

	iamJWKSURL := iam.URL + "/.well-known/jwks.json"
	t.Setenv("KACHO_REGISTRY_DB_PASSWORD", "s3cr3t")
	t.Setenv("KACHO_REGISTRY_IAM_JWKS_URL", iamJWKSURL)
	t.Setenv("KACHO_REGISTRY_HYDRA_ISSUER", "https://hydra.api.kacho.cloud")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if cfg.IAMJWKSURL != iamJWKSURL {
		t.Fatalf("cfg.IAMJWKSURL = %q, want %q (env must feed the field)", cfg.IAMJWKSURL, iamJWKSURL)
	}

	// Тот же конструктор, что и в buildDataplaneHandler: JWKS-URL=iam, issuer-pin=Hydra.
	v := jwks.New(cfg.IAMJWKSURL, cfg.ServiceAud, cfg.HydraIssuer)

	// Токен с валидным JOSE-заголовком и неизвестным kid → cache-miss → refresh (GET на
	// iam-URL). Подпись/claims нерелевантны: фетч происходит до их проверки.
	header := b64uJSON(t, map[string]any{"alg": "RS256", "typ": "JWT", "kid": "probe"})
	claims := b64uJSON(t, map[string]any{"sub": "cid", "aud": cfg.ServiceAud})
	tok := header + "." + claims + "." + base64.RawURLEncoding.EncodeToString([]byte("sig"))
	_, _ = v.Verify(context.Background(), tok) // ожидаемо падает (unknown kid) — важен факт фетча

	mu.Lock()
	defer mu.Unlock()
	if !fetched {
		t.Fatalf("verifier never fetched JWKS from the configured iam URL")
	}
	if gotPath != "/.well-known/jwks.json" {
		t.Fatalf("JWKS fetched from path %q, want /.well-known/jwks.json", gotPath)
	}
	// Host входящего запроса = fake iam-сервер (доказывает: data-plane дёргает iam-origin,
	// сконфигурированный env'ом, а не Hydra).
	wantHost := iam.Listener.Addr().String()
	if gotHost != wantHost {
		t.Fatalf("JWKS fetched from host %q, want configured iam origin %q", gotHost, wantHost)
	}
}
