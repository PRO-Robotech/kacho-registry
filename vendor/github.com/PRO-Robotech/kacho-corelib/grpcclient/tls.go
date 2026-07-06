// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package grpcclient — tls.go: opt-in mTLS client-credentials helper.
//
// TLSClientCreds is the single source of truth for assembling client-side TLS
// transport credentials for inter-service gRPC dials, by analogy with the
// keepalive dial-option helper.
//
// Behavior contract:
//   - enable=false → insecure transport-credentials (current plaintext dial,
//     dev backward-compat); cert files are NOT read.
//   - enable=true  → mTLS: presents client-cert (cert_file/key_file), verifies the
//     server-cert against ca_files, and checks server_name against the server-cert
//     SAN (client-cert + server-CA + server-name).
//   - enable=true + empty cert_file AND key_file → one-way TLS: NO client-cert is
//     presented (still verifies server-cert via ca_files + server_name). This is
//     not a normal production edge — it exists so a require-and-verify server
//     correctly rejects a cert-less client → Unavailable.
//   - enable=true + unreadable/garbage cert / empty ca_files / empty server_name →
//     error (fail-closed; never a silent insecure fallback).
//
// Cert files are read once at startup; rotation = pod restart.
package grpcclient

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// TLSClient is a HORIZONTAL, per-edge client-side TLS value-struct. It is
// a plain value struct with no process-wide TLS singleton: every dial-site
// receives its own TLSClientCreds argument (no global singletons outside cmd/).
//
// It carries NO absolute envconfig tags ON PURPOSE. This struct
// is embedded by every service under its own per-edge (per-peer) dial config
// field; an absolute tag (e.g. KACHO_COMPUTE_TLS_CLIENT_ENABLE) would collapse
// every dial-edge onto the same env names and break per-edge independence.
// Instead the env name is derived from the hierarchy of field names: the SERVICE
// owns the edge name by choosing the parent field and loading with
// config.LoadPrefixed("KACHO_<DOMAIN>", &cfg).
//
// Example — a service that dials two peers:
//
//	type Config struct {
//		IAM grpcclient.TLSClient // → KACHO_COMPUTE_IAM_ENABLE, ..._CAFILES, ...
//		VPC grpcclient.TLSClient // → KACHO_COMPUTE_VPC_ENABLE, ..._CAFILES, ...
//	}
//	_ = config.LoadPrefixed("KACHO_COMPUTE", &cfg) // each dial-edge independent
//
// This yields the KACHO_<DOMAIN>_<EDGE>_<NAME> convention with true per-edge
// prefixing: distinct dial-edges in one process resolve to distinct env blocks
// (one process may run an mTLS client and an insecure server simultaneously).
type TLSClient struct {
	// Enable toggles mTLS for this dial. Zero-value false ⇒ insecure.
	Enable bool
	// CertFile is the PEM client-certificate presented to the server.
	CertFile string
	// KeyFile is the PEM private key for CertFile.
	KeyFile string
	// CAFiles are PEM CA bundles used to verify the server-cert.
	CAFiles []string
	// ServerName is checked against the server-cert SAN.
	ServerName string
}

// TLSClientCreds returns the grpc.DialOption carrying the transport credentials
// for this config. See package doc for the behavior contract.
func TLSClientCreds(cfg TLSClient) (grpc.DialOption, error) {
	creds, err := TLSClientTransportCreds(cfg)
	if err != nil {
		return nil, err
	}
	return grpc.WithTransportCredentials(creds), nil
}

// TLSClientTransportCreds returns the raw credentials.TransportCredentials for
// this config — the same building block TLSClientCreds wraps into a DialOption.
// Callers that dial through a builder taking TransportCredentials (rather than a
// DialOption) use this directly, keeping a single source of truth for the
// behavior contract.
func TLSClientTransportCreds(cfg TLSClient) (credentials.TransportCredentials, error) {
	if !cfg.Enable {
		// insecure dial, cert files NOT read.
		return insecure.NewCredentials(), nil
	}

	if len(cfg.CAFiles) == 0 {
		return nil, fmt.Errorf("grpcclient: tls enabled but ca_files is empty (server CA required to verify the server cert)")
	}
	rootCAs, err := loadCAPool(cfg.CAFiles)
	if err != nil {
		return nil, fmt.Errorf("grpcclient: load server CA pool: %w", err)
	}

	if cfg.ServerName == "" {
		// server_name is verified against the server-cert SAN; empty would
		// disable that check — fail-closed instead of silently accepting any name.
		return nil, fmt.Errorf("grpcclient: tls enabled but server_name is empty (required to verify the server-cert SAN)")
	}

	tlsCfg := &tls.Config{
		RootCAs:    rootCAs,
		ServerName: cfg.ServerName,
		MinVersion: tls.VersionTLS12,
	}

	// Present a client-cert only when both cert_file and key_file are set. Empty
	// pair ⇒ one-way TLS with no client-cert: a require-and-verify server rejects
	// this at handshake. A half-set pair is misconfiguration.
	if cfg.CertFile != "" || cfg.KeyFile != "" {
		cert, lerr := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if lerr != nil {
			return nil, fmt.Errorf("grpcclient: load client cert/key: %w", lerr)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return credentials.NewTLS(tlsCfg), nil
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
