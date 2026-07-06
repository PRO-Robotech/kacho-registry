// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package auth — outgoing-side helpers for principal propagation across
// service→service gRPC calls.
//
// Server-side extraction lives in `corelib/grpcsrv/principal_extract.go`
// (UnaryPrincipalExtract / StreamPrincipalExtract) and is unchanged. This
// package complements it with the outgoing-MD side: client adapters wrap
// outgoing ctx with PropagateOutgoing so the peer's incoming-MD interceptor
// reconstructs the caller's Principal instead of falling back to
// SystemPrincipal() = user:bootstrap.
//
// # Why this exists
//
// vpc/compute per-RPC authz interceptor calls
// `kacho-iam.InternalIAMService.Check` from `clients/check_client.go` adapter.
// Without this wrap, outgoing gRPC carries no `x-kacho-principal-*` MD →
// iam-server-side `grpcsrv.UnaryPrincipalExtract` falls back to
// `operations.SystemPrincipal() = user:bootstrap` → every iam handler that
// later calls `operations.PrincipalFromContext` (audit, scope-filter,
// policy-overlay context.user.*) sees the wrong identity. Lifting the helper
// here means любой peer-client (loadbalancer, dns) получает корректную
// propagation простым импортом, без per-repo копий.
//
// # Security boundary
//
// This helper is for **cluster-internal** service→service calls only. The
// external TLS listener of api-gateway STRIPS client-supplied
// `x-kacho-principal-*` headers so a tenant cannot inject a principal header
// to impersonate another user. The server-side cluster-internal listener is
// mTLS-only and not reachable from outside the cluster, so it does not need a
// symmetric strip today. If that guarantee weakens, add a strip-on-entry in
// vpc/compute server interceptors in a separate change.
package auth

import (
	"context"

	"google.golang.org/grpc/metadata"

	"github.com/PRO-Robotech/kacho-corelib/grpcsrv"
	"github.com/PRO-Robotech/kacho-corelib/operations"
)

// MD-key re-exports for ergonomic imports — callers shouldn't have to import
// `corelib/grpcsrv` just to know the wire-format header names. The canonical
// definitions remain in `corelib/grpcsrv/principal_extract.go` (server-side
// extract package owns the wire-format contract).
const (
	MDKeyPrincipalType    = grpcsrv.MDKeyPrincipalType
	MDKeyPrincipalID      = grpcsrv.MDKeyPrincipalID
	MDKeyPrincipalDisplay = grpcsrv.MDKeyPrincipalDisplay
)

// PropagateOutgoing forwards the caller's Principal onto outgoing gRPC
// metadata (`x-kacho-principal-type` / `-id` / `-display-name`) so the peer's
// `grpcsrv.UnaryPrincipalExtract` reconstructs the same Principal on the
// other side.
//
// Semantics:
//   - nil ctx → context.Background() (defensive — does not panic).
//   - ctx without an explicit WithPrincipal → operations.PrincipalFromContext
//     falls back to SystemPrincipal() (Type="system", ID="bootstrap"); that
//     is a NON-empty principal and headers ARE forwarded — worker peer-calls
//     stay attributable as system rather than going on the wire as
//     identity-less.
//   - ctx whose Principal has both Type=="" and ID=="" (an explicit empty
//     WithPrincipal — should not happen in practice) → ctx is returned
//     unchanged, no MD added.
//
// Per gRPC metadata.AppendToOutgoingContext semantics, a second wrap appends
// rather than overwrites; the peer reads the first value via md.Get(key)[0].
// Practically each outgoing RPC has exactly one wrap (in the outermost adapter
// method), so this never matters.
func PropagateOutgoing(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	p := operations.PrincipalFromContext(ctx)
	if p.ID == "" && p.Type == "" {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx,
		MDKeyPrincipalType, p.Type,
		MDKeyPrincipalID, p.ID,
		MDKeyPrincipalDisplay, p.DisplayName,
	)
}

// SystemPrincipalFor returns a typed system principal for worker / reconciler
// contexts that have no user identity (cron jobs, expirer workers, fga-outbox
// drainer, bootstrap workers).
//
// Use INSTEAD of `operations.SystemPrincipal()` for any cross-service call
// originating from such a worker — `bootstrap` is reserved for the
// kacho-iam bootstrap-admin seed and should not appear on the wire as the
// caller of normal operational traffic.
//
//   - service: "vpc" | "compute" | "iam" | "api-gateway" | ...
//   - role:    "reconciler" | "expirer" | "drainer" | "bootstrap" | ...
//
// Empty service or role → falls back to operations.SystemPrincipal() so an
// accidental empty-string caller does not produce a garbage `system:-` id.
//
// Produces:
//
//	Principal{Type: "user", ID: "system:<service>-<role>", DisplayName: "<service>-<role>"}
//
// "user" type (not "system") because FGA tuples and audit fields key on
// user-typed subjects; the `system:` prefix in the ID is the discriminator.
func SystemPrincipalFor(service, role string) operations.Principal {
	if service == "" || role == "" {
		return operations.SystemPrincipal()
	}
	return operations.Principal{
		Type:        "user",
		ID:          "system:" + service + "-" + role,
		DisplayName: service + "-" + role,
	}
}
