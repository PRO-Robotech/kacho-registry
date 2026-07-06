// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package check

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-corelib/authz"
	"github.com/PRO-Robotech/kacho-corelib/operations"
	registryv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/registry/v1"

	"github.com/stretchr/testify/require"
)

// viewer_boundary_test.go — verb-tier boundary: субъект, ДЕРЖАЩИЙ v_get,
// но НЕ v_update/v_delete на существующем registry_registry:<id>, обязан получить
// NOT_FOUND (existence-hiding) на Update/Delete — а не молча унаследовать mutate от
// namespace-tier. Раньше это пиналось только fixture-gated newman-кейсом, который на
// single-user стенде всегда SKIP'ается зелёным. Этот тест всегда исполняется:
// прогоняет РЕАЛЬНЫЙ corelib authz-interceptor поверх registry PermissionMap с fake
// CheckClient, грантящим ровно v_get.

// viewerCheckClient — грантит только v_get на любой объект; на любой другой verb
// (v_update/v_delete/…) возвращает ErrHideExistence (объект есть, но verb'а нет →
// interceptor маппит в NOT_FOUND). Моделирует iam.Check для viewer'а на живом ресурсе.
func viewerCheckClient() authz.CheckClient {
	return authz.CheckClientFunc(func(_ context.Context, _, relation, _ string) (bool, error) {
		if relation == relVGet {
			return true, nil
		}
		return false, authz.ErrHideExistence
	})
}

func viewerInterceptor(t *testing.T) grpc.UnaryServerInterceptor {
	t.Helper()
	ic := authz.NewInterceptor(authz.InterceptorOptions{
		ServiceName: "kacho-registry",
		Map:         PermissionMap(),
		Client:      viewerCheckClient(),
		Cache:       authz.NewCache(0),
	})
	return ic.Unary()
}

func viewerCtx() context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr-viewer", DisplayName: "viewer"})
}

// TestViewerBoundary_GetAllowed_UpdateDeleteHidden — v_get-only subject: Get проходит
// (handler вызван), Update/Delete → NOT_FOUND (existence-hiding, viewer НЕ наследует
// mutate-verb от tier'а).
func TestViewerBoundary_GetAllowed_UpdateDeleteHidden(t *testing.T) {
	inter := viewerInterceptor(t)
	ctx := viewerCtx()
	const regID = "regVIEWERBOUND000000"

	ran := false
	okHandler := func(context.Context, any) (any, error) { ran = true; return "ok", nil }

	// Get — viewer имеет v_get → handler выполняется.
	_, err := inter(ctx, &registryv1.GetRegistryRequest{RegistryId: regID},
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.registry.v1.RegistryService/Get"}, okHandler)
	require.NoError(t, err, "viewer with v_get may Get")
	require.True(t, ran, "Get handler executed")

	// Update — нет v_update → NOT_FOUND (existence-hiding), handler НЕ вызван.
	ran = false
	_, err = inter(ctx, &registryv1.UpdateRegistryRequest{RegistryId: regID},
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.registry.v1.RegistryService/Update"}, okHandler)
	require.Equal(t, codes.NotFound, status.Code(err), "viewer denied Update → NOT_FOUND (existence-hidden)")
	require.False(t, ran, "Update handler NOT executed on deny")

	// Delete — нет v_delete → NOT_FOUND, handler НЕ вызван.
	ran = false
	_, err = inter(ctx, &registryv1.DeleteRegistryRequest{RegistryId: regID},
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.registry.v1.RegistryService/Delete"}, okHandler)
	require.Equal(t, codes.NotFound, status.Code(err), "viewer denied Delete → NOT_FOUND (existence-hidden)")
	require.False(t, ran, "Delete handler NOT executed on deny")
}
