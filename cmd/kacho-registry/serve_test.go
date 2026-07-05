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
