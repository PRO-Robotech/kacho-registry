// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package main

import "testing"

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
