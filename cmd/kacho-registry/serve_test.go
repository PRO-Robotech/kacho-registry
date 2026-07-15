// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-corelib/grpcsrv"

	"github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/config"
)

// discardLogger — тихий slog для тестов validateAuthMode (ветки логируют WARN).
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestValidateSecurityConfig — fail-closed гейт security.md: без breakglass ОБА
// листенера обязаны иметь authz-Check (AuthZIAMGRPCAddr!="") И mTLS
// (Public+Internal ServerMTLS.Enable). breakglass=true — полный обход.
func TestValidateSecurityConfig(t *testing.T) {
	bothMTLS := func() config.Config {
		return config.Config{
			AuthZIAMGRPCAddr:   "kacho-iam-internal.kacho.svc:9091",
			PublicServerMTLS:   grpcsrv.TLSServer{Enable: true},
			InternalServerMTLS: grpcsrv.TLSServer{Enable: true},
		}
	}
	cases := []struct {
		name    string
		mutate  func(*config.Config)
		wantErr bool
	}{
		{"all-set-ok", func(*config.Config) {}, false},
		{"breakglass-bypasses-everything", func(c *config.Config) {
			// breakglass=true даже при пустом addr и выключенном mTLS → nil.
			c.AuthZBreakglass = true
			c.AuthZIAMGRPCAddr = ""
			c.PublicServerMTLS.Enable = false
			c.InternalServerMTLS.Enable = false
		}, false},
		{"empty-iam-addr-rejected", func(c *config.Config) { c.AuthZIAMGRPCAddr = "" }, true},
		{"public-mtls-disabled-rejected", func(c *config.Config) { c.PublicServerMTLS.Enable = false }, true},
		{"internal-mtls-disabled-rejected", func(c *config.Config) { c.InternalServerMTLS.Enable = false }, true},
		{"both-mtls-disabled-rejected", func(c *config.Config) {
			c.PublicServerMTLS.Enable = false
			c.InternalServerMTLS.Enable = false
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := bothMTLS()
			tc.mutate(&cfg)
			err := validateSecurityConfig(cfg)
			if tc.wantErr && err == nil {
				t.Fatalf("want error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("want nil, got %v", err)
			}
		})
	}
}

// TestValidateAuthMode — whitelist режимов + строгость DB-SSL. dev/production —
// без SSL-требований; production-strict обязан иметь sslmode require|verify-ca|
// verify-full; неизвестный режим — отказ старта.
func TestValidateAuthMode(t *testing.T) {
	cases := []struct {
		name     string
		authMode string
		sslMode  string
		wantErr  bool
	}{
		{"dev-disable-ok", "dev", "disable", false},
		{"dev-empty-ssl-ok", "dev", "", false},
		{"dev-require-ok", "dev", "require", false},
		{"production-disable-ok", "production", "disable", false},
		{"production-require-ok", "production", "require", false},
		{"prod-strict-require-ok", "production-strict", "require", false},
		{"prod-strict-verify-ca-ok", "production-strict", "verify-ca", false},
		{"prod-strict-verify-full-ok", "production-strict", "verify-full", false},
		{"prod-strict-disable-rejected", "production-strict", "disable", true},
		{"prod-strict-empty-ssl-rejected", "production-strict", "", true},
		{"prod-strict-prefer-rejected", "production-strict", "prefer", true},
		{"unknown-mode-rejected", "bogus", "require", true},
		{"empty-mode-rejected", "", "require", true},
	}
	log := discardLogger()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Config{AuthMode: tc.authMode, DBSSLMode: tc.sslMode}
			err := validateAuthMode(cfg, log)
			if tc.wantErr && err == nil {
				t.Fatalf("want error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("want nil, got %v", err)
			}
		})
	}
}

// TestRequireSecureJWKSURL — в production/production-strict JWKS trust-anchor
// обязан быть https://; в dev допускается http:// (как DB sslmode=disable).
func TestRequireSecureJWKSURL(t *testing.T) {
	cases := []struct {
		name     string
		authMode string
		jwksURL  string
		wantErr  bool
	}{
		{"dev-http-ok", "dev", "http://hydra.kacho.svc:4444/.well-known/jwks.json", false},
		{"dev-https-ok", "dev", "https://hydra.kacho.svc:4444/.well-known/jwks.json", false},
		{"prod-http-rejected", "production", "http://hydra.kacho.svc:4444/.well-known/jwks.json", true},
		{"prod-https-ok", "production", "https://hydra.api.kacho.cloud/.well-known/jwks.json", false},
		{"prod-strict-http-rejected", "production-strict", "http://hydra.kacho.svc:4444/.well-known/jwks.json", true},
		{"prod-strict-https-ok", "production-strict", "https://hydra.api.kacho.cloud/.well-known/jwks.json", false},
		{"prod-scheme-uppercase-ok", "production", "HTTPS://hydra.api.kacho.cloud/jwks", false},
		{"prod-bad-url", "production", "://not a url", true},
		// iam JWKS proxy URL (post-unify): http:// rejected, https:// accepted in prod.
		{"prod-iam-http-rejected", "production", "http://kacho-iam-internal.kacho.svc.cluster.local:9097/.well-known/jwks.json", true},
		{"prod-iam-https-ok", "production", "https://kacho-iam-internal.kacho.svc.cluster.local:9097/.well-known/jwks.json", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := requireSecureJWKSURL(tc.authMode, tc.jwksURL)
			if tc.wantErr && err == nil {
				t.Fatalf("want error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("want nil, got %v", err)
			}
		})
	}
}

// TestRequireSecureJWKSURL_ErrorNamesIAMEnv (RJU-14) — после config-rename prod-гард
// обязан именовать НОВЫЙ env KACHO_REGISTRY_IAM_JWKS_URL (а не старый _HYDRA_JWKS_URL)
// в тексте отказа. Behaviour-level lock рефактора имени переменной (testing.md APICONV):
// операторская диагностика указывает на актуальное имя env. Держит и позитивную сторону
// (упомянут IAM), и негативную (старое имя вычищено).
func TestRequireSecureJWKSURL_ErrorNamesIAMEnv(t *testing.T) {
	err := requireSecureJWKSURL("production", "http://kacho-iam-internal.kacho.svc.cluster.local:9097/.well-known/jwks.json")
	if err == nil {
		t.Fatalf("want error for http:// iam JWKS URL in production, got nil")
	}
	if !strings.Contains(err.Error(), "KACHO_REGISTRY_IAM_JWKS_URL") {
		t.Fatalf("error must name the renamed env KACHO_REGISTRY_IAM_JWKS_URL, got %q", err.Error())
	}
	if strings.Contains(err.Error(), "KACHO_REGISTRY_HYDRA_JWKS_URL") {
		t.Fatalf("error must not reference the old env KACHO_REGISTRY_HYDRA_JWKS_URL, got %q", err.Error())
	}
}

// TestRequireDataplaneTLSAck — data-plane OCI-листенер обслуживает открытый HTTP
// (bearer identity-JWT транзитят по сокету). В production/production-strict молчаливый
// plaintext-старт запрещён: оператор обязан ЯВНО подтвердить внешнюю TLS-терминацию
// (KACHO_REGISTRY_DATAPLANE_TLS_TERMINATED_EXTERNALLY=true), иначе старт отклоняется.
// В dev — no-op (как http:// JWKS и DB sslmode=disable). Параллель requireSecureJWKSURL/
// requireIssuerPinned.
func TestRequireDataplaneTLSAck(t *testing.T) {
	cases := []struct {
		name          string
		authMode      string
		tlsTerminated bool
		wantErr       bool
	}{
		{"dev-noack-ok", "dev", false, false},
		{"dev-ack-ok", "dev", true, false},
		{"prod-noack-rejected", "production", false, true},
		{"prod-ack-ok", "production", true, false},
		{"prod-strict-noack-rejected", "production-strict", false, true},
		{"prod-strict-ack-ok", "production-strict", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := requireDataplaneTLSAck(tc.authMode, tc.tlsTerminated)
			if tc.wantErr && err == nil {
				t.Fatalf("want error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("want nil, got %v", err)
			}
		})
	}
}

// TestRequireIssuerPinned — в production/production-strict issuer (iss) identity-JWT
// обязан быть закреплён (KACHO_REGISTRY_HYDRA_ISSUER непустой); пустой iss в проде
// принимал бы токен от любого RP с тем же JWKS+aud (federation-out). В dev пустой iss
// допустим (issuer-pinning опционален), симметрично http:// JWKS и DB sslmode=disable.
func TestRequireIssuerPinned(t *testing.T) {
	cases := []struct {
		name     string
		authMode string
		issuer   string
		wantErr  bool
	}{
		{"dev-empty-ok", "dev", "", false},
		{"dev-set-ok", "dev", "https://hydra.api.kacho.cloud", false},
		{"prod-empty-rejected", "production", "", true},
		{"prod-set-ok", "production", "https://hydra.api.kacho.cloud", false},
		{"prod-strict-empty-rejected", "production-strict", "", true},
		{"prod-strict-set-ok", "production-strict", "https://hydra.api.kacho.cloud", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := requireIssuerPinned(tc.authMode, tc.issuer)
			if tc.wantErr && err == nil {
				t.Fatalf("want error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("want nil, got %v", err)
			}
		})
	}
}
