// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package grpcsrv — tls.go: opt-in mTLS server-credentials helper.
//
// TLSServerCreds is the single source of truth for assembling server-side TLS
// transport credentials for inter-service gRPC. It is a server-option builder by
// analogy with the keepalive-helper: NewServer takes the returned
// grpc.ServerOption.
//
// Behavior contract:
//   - enable=false → insecure server-credentials (current plaintext behavior,
//     dev backward-compat); cert files are NOT read.
//   - enable=true  → mTLS: presents server-cert (cert_file/key_file), verifies
//     client-certs against client_ca_files with ClientAuth =
//     RequireAndVerifyClientCert (server-cert + client-CA).
//   - enable=true + unreadable/garbage cert / empty client-CA → error (fail-closed;
//     never a silent insecure fallback).
//
// Cert files are read once at startup; rotation = pod restart (hot-reload
// deliberately out of scope).
package grpcsrv

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// TLSServer is a HORIZONTAL, per-edge server-side TLS value-struct. It is
// a plain value struct with no process-wide TLS singleton: every grpcsrv.NewServer
// receives its own TLSServerCreds argument (no global singletons outside cmd/).
//
// It carries NO absolute envconfig tags ON PURPOSE. This struct is embedded by
// every service under its own per-edge config field; an absolute tag (e.g.
// KACHO_VPC_TLS_SERVER_ENABLE) would collapse every embedding onto the same env
// names and break per-edge independence. Instead the env name is derived from the
// hierarchy of field names: the SERVICE owns the edge name by choosing the parent
// field and loading with config.LoadPrefixed("KACHO_<DOMAIN>", &cfg).
//
// Example — a service with a public and an admin server-edge:
//
//	type Config struct {
//		Public grpcsrv.TLSServer // → KACHO_VPC_PUBLIC_ENABLE, ..._CERTFILE, ...
//		Admin  grpcsrv.TLSServer // → KACHO_VPC_ADMIN_ENABLE,  ..._CERTFILE, ...
//	}
//	_ = config.LoadPrefixed("KACHO_VPC", &cfg) // each edge resolves independently
//
// This yields the KACHO_<DOMAIN>_<EDGE>_<NAME> convention with true per-edge
// prefixing: distinct edges in one process resolve to distinct env blocks (one
// process may run a TLS server and an insecure client simultaneously).
type TLSServer struct {
	// Enable toggles mTLS for this server. Zero-value false ⇒ insecure.
	Enable bool
	// CertFile is the PEM server-certificate presented to clients.
	CertFile string
	// KeyFile is the PEM private key for CertFile.
	KeyFile string
	// ClientCAFiles are PEM CA bundles used to verify presented client-certs.
	ClientCAFiles []string
}

// TLSServerCreds returns the grpc.ServerOption carrying the transport credentials
// for this config. See package doc for the behavior contract.
func TLSServerCreds(cfg TLSServer) (grpc.ServerOption, error) {
	if !cfg.Enable {
		// insecure server, cert files NOT read.
		return grpc.Creds(insecure.NewCredentials()), nil
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("grpcsrv: load server cert/key: %w", err)
	}

	if len(cfg.ClientCAFiles) == 0 {
		// RequireAndVerifyClientCert needs a client-CA bundle to verify against.
		return nil, fmt.Errorf("grpcsrv: tls enabled but client_ca_files is empty (RequireAndVerifyClientCert needs a client CA)")
	}
	clientCAs, err := loadCAPool(cfg.ClientCAFiles)
	if err != nil {
		return nil, fmt.Errorf("grpcsrv: load client CA pool: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		MinVersion:   tls.VersionTLS12,
	}
	return grpc.Creds(credentials.NewTLS(tlsCfg)), nil
}

// loadCAPool reads PEM CA bundles into an x509.CertPool. An empty/garbage bundle
// (no parseable certificate) is an error — fail-closed.
func loadCAPool(files []string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for _, f := range files {
		pem, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("read CA file %q: %w", f, err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no valid PEM certificate in CA file %q", f)
		}
	}
	return pool, nil
}
