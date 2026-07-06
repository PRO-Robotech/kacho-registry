// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package grpcsrv — principal_extract.go.
//
// PrincipalExtractInterceptor читает три metadata-header'а, которые api-gateway
// auth-interceptor выставляет после успешной JWT-валидации:
//
//	x-kacho-principal-type         "user" | "service_account" | "system"
//	x-kacho-principal-id           "usr-..." | "sva-..." | "anonymous"
//	x-kacho-principal-display-name "alice@example.com" | "" | ...
//
// и кладет `operations.Principal` в ctx через `operations.WithPrincipal`.
// Backend use-case'ы вызывают `operations.PrincipalFromContext(ctx)` →
// `Repo.CreateWithPrincipal(ctx, op, p)` — реальный principal попадает в
// `operations.principal_*` колонки.
//
// Если headers отсутствуют (legacy-call'ы, прямой gRPC без api-gateway) —
// fallback на `SystemPrincipal()` (идентично `PrincipalFromContext` поведению без auth).
package grpcsrv

import (
	"context"
	"log/slog"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/PRO-Robotech/kacho-corelib/operations"
)

// debugExtract — debug-log incoming metadata + principal-extract decisions.
// Enabled via env KACHO_DEBUG_PRINCIPAL=1 (off by default). Useful for
// troubleshooting REST → gRPC metadata propagation issues.
var debugExtract = os.Getenv("KACHO_DEBUG_PRINCIPAL") == "1"
var debugLogger = slog.New(slog.NewJSONHandler(os.Stdout, nil))

const (
	MDKeyPrincipalType    = "x-kacho-principal-type"
	MDKeyPrincipalID      = "x-kacho-principal-id"
	MDKeyPrincipalDisplay = "x-kacho-principal-display-name"
)

// UnaryPrincipalExtract — gRPC unary interceptor для backend-сервисов.
// Должен стоять РАНЬШЕ бизнес-handler'ов в цепочке interceptor'ов.
//
// ВНИМАНИЕ (trust): этот extractor читает x-kacho-principal-* БЕЗУСЛОВНО, без
// проверки транспорта/cert-identity форвардера — он доверяет, что заголовки
// проставил только api-gateway. Монтировать ТОЛЬКО на listener'е, куда не может
// дозвониться неконтролируемый peer. Для cluster-internal mTLS-листенеров
// предпочтительна trust-aware связка UnaryCertIdentityExtract +
// UnaryTrustedPrincipalExtract(WithTrustedForwarders(<gateway-SAN>)): она снимает
// principal на недоверенном/не-форвардер peer'е (защита от confused-deputy).
// Для новых mTLS-листенеров предпочитайте именно trust-aware связку.
func UnaryPrincipalExtract() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx = extractPrincipal(ctx)
		return handler(ctx, req)
	}
}

// StreamPrincipalExtract — то же для stream RPC.
func StreamPrincipalExtract() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := extractPrincipal(ss.Context())
		return handler(srv, &principalStream{ServerStream: ss, ctx: ctx})
	}
}

type principalStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *principalStream) Context() context.Context { return s.ctx }

func extractPrincipal(ctx context.Context) context.Context {
	p, ok := principalFromIncomingMetadata(ctx)
	if !ok {
		return ctx
	}
	if debugExtract {
		debugLogger.Info("principal_extract: principal set", "type", p.Type, "id", p.ID)
	}
	return operations.WithPrincipal(ctx, p)
}

// principalFromIncomingMetadata parses the x-kacho-principal-* headers from the
// incoming metadata into an operations.Principal. ok is false when there is no
// incoming metadata or the required type/id headers are absent (legacy / direct
// gRPC calls). Shared by extractPrincipal (UnaryPrincipalExtract) and the
// trust-aware UnaryTrustedPrincipalExtract (cert_identity.go).
func principalFromIncomingMetadata(ctx context.Context) (operations.Principal, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		if debugExtract {
			debugLogger.Info("principal_extract: no incoming metadata")
		}
		return operations.Principal{}, false
	}
	if debugExtract {
		// Dump all metadata keys for debugging.
		keys := make([]string, 0, len(md))
		for k := range md {
			keys = append(keys, k+"="+strings.Join(md.Get(k), ","))
		}
		debugLogger.Info("principal_extract: incoming metadata", "keys", strings.Join(keys, "; "))
	}
	pType := first(md.Get(MDKeyPrincipalType))
	pID := first(md.Get(MDKeyPrincipalID))
	if pType == "" || pID == "" {
		if debugExtract {
			debugLogger.Info("principal_extract: missing principal headers", "type", pType, "id", pID)
		}
		return operations.Principal{}, false
	}
	return operations.Principal{
		Type:        pType,
		ID:          pID,
		DisplayName: first(md.Get(MDKeyPrincipalDisplay)),
	}, true
}

func first(vs []string) string {
	if len(vs) == 0 {
		return ""
	}
	return vs[0]
}
