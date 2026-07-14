// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package check

import (
	"context"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-corelib/authz"
	"github.com/PRO-Robotech/kacho-corelib/operations"
	registryv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/registry/v1"

	"github.com/stretchr/testify/require"
)

// revoke_cache_ttl_test.go — regression-lock для #33 (revoke не энфорсился
// оперативно): positive authz-Check кеш gRPC-интерсептора был always-on 5s
// (factory: authz.NewCache(0)), а registry НЕ подписан на IAM cache-invalidation
// (InternalAuthzCacheService.InvalidateSubject бьёт только api-gateway) и
// db-per-service ⇒ LISTEN/NOTIFY от iam сюда не доходит → отозванный субъект держал
// allow ≥5s. Фикс — configurable KACHO_REGISTRY_AUTHZ_CACHE_TTL (default 2s;
// 0 → positive-кеш выключен). Тесты локают ОБСЕРВАБЛ (окно ограничено TTL /
// выключено), а не только факт наличия knob'а.

const (
	testSubject   = "user:usr-grantee"
	testRegistry  = "regREVOKECACHE000000"
	testGetMethod = "/kacho.cloud.registry.v1.RegistryService/Get"
)

// ---- pure cache-semantics (helper authzCache, на котором строится фабрика) ----

// TestAuthzCache_ConfiguredTTLBoundsRevokeWindow — при CacheTTL>0 positive-запись
// живёт РОВНО TTL: до истечения — hit, после — miss. Значит окно, в течение которого
// отозванный субъект держит закешированный allow, ограничено сверху TTL (а не 5s).
func TestAuthzCache_ConfiguredTTLBoundsRevokeWindow(t *testing.T) {
	const ttl = 2 * time.Second
	c := authzCache(ttl)
	base := time.Now()
	clk := base
	c.SetNowFunc(func() time.Time { return clk })

	c.SetAllowed(testSubject, relVGet, objectTypeRegistry, testRegistry)

	// В пределах TTL — запись жива (positive кешируется, hit).
	clk = base.Add(ttl - time.Millisecond)
	_, hit := c.Get(testSubject, relVGet, objectTypeRegistry, testRegistry)
	require.True(t, hit, "positive entry must be cached within configured TTL")

	// За пределами TTL — запись истекла (revoke отразится не позднее TTL).
	clk = base.Add(ttl + time.Millisecond)
	_, hit = c.Get(testSubject, relVGet, objectTypeRegistry, testRegistry)
	require.False(t, hit, "positive entry must expire within configured TTL (revoke window bounded)")
}

// TestAuthzCache_ZeroTTLDisablesPositiveCaching — при CacheTTL<=0 positive-кеш
// выключен: любое реальное время между двумя запросами → miss, т.е. каждый RPC
// делает живой IAM Check (немедленный revoke). corelib authz.Cache не имеет
// first-class disabled-режима (NewCache(≤0)→5s), поэтому «выкл» = минимальный TTL,
// истекающий раньше следующего запроса (монотонные часы строго растут между
// SetAllowed и Get разных RPC).
func TestAuthzCache_ZeroTTLDisablesPositiveCaching(t *testing.T) {
	c := authzCache(0)
	base := time.Now()
	clk := base
	c.SetNowFunc(func() time.Time { return clk })

	c.SetAllowed(testSubject, relVGet, objectTypeRegistry, testRegistry)

	// Любой положительный дельта-сдвиг (реальный межзапросный интервал) → miss.
	clk = base.Add(time.Millisecond)
	_, hit := c.Get(testSubject, relVGet, objectTypeRegistry, testRegistry)
	require.False(t, hit, "ttl<=0 disables positive caching → every request is a live Check")
}

// ---- behavioural: реальный corelib authz-interceptor поверх registry PermissionMap ----

// revokableAuthz — fake authz.CheckClient, моделирующий revoke AccessBinding: пока
// revoked==false — грантит v_get; после revoke() — ErrHideExistence (объект есть,
// verb'а нет → interceptor маппит в NOT_FOUND, existence-hiding).
type revokableAuthz struct {
	mu      sync.Mutex
	revoked bool
	checks  int
}

func (a *revokableAuthz) revoke() {
	a.mu.Lock()
	a.revoked = true
	a.mu.Unlock()
}

func (a *revokableAuthz) checkCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.checks
}

func (a *revokableAuthz) Check(_ context.Context, _, relation, _ string) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.checks++
	if a.revoked {
		return false, authz.ErrHideExistence
	}
	if relation == relVGet {
		return true, nil
	}
	return false, authz.ErrHideExistence
}

func grantedCtx() context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr-grantee", DisplayName: "grantee"})
}

// interceptorWithCache строит РЕАЛЬНЫЙ corelib authz-interceptor поверх registry
// PermissionMap с переданным кешем + fake CheckClient (мы держим кеш, чтобы управлять
// его часами через SetNowFunc — фабрика строит кеш внутри, поэтому здесь собираем
// InterceptorOptions напрямую тем же способом, что и NewInterceptor).
func interceptorWithCache(cache *authz.Cache, client authz.CheckClient) grpc.UnaryServerInterceptor {
	ic := authz.NewInterceptor(authz.InterceptorOptions{
		ServiceName: "kacho-registry",
		Map:         PermissionMap(),
		Client:      client,
		Cache:       cache,
	})
	return ic.Unary()
}

// TestNewInterceptor_RevokedSubjectDeniedAfterCacheTTL — end-to-end: субъект с
// закешированным allow держит доступ РОВНО в пределах TTL, но после истечения TTL
// (revoke уже произошёл) следующий Get → NOT_FOUND (existence-hiding), handler НЕ
// вызван. Локает «окно ограничено TTL», а не 5s.
func TestNewInterceptor_RevokedSubjectDeniedAfterCacheTTL(t *testing.T) {
	az := &revokableAuthz{}
	const ttl = 2 * time.Second
	c := authzCache(ttl)
	base := time.Now()
	clk := base
	c.SetNowFunc(func() time.Time { return clk })
	inter := interceptorWithCache(c, az)

	ctx := grantedCtx()
	info := &grpc.UnaryServerInfo{FullMethod: testGetMethod}
	req := &registryv1.GetRegistryRequest{RegistryId: testRegistry}
	ran := 0
	h := func(context.Context, any) (any, error) { ran++; return "ok", nil }

	// 1) grant активен → allowed, positive кешируется.
	_, err := inter(ctx, req, info, h)
	require.NoError(t, err, "granted subject allowed")
	require.Equal(t, 1, ran)

	// 2) revoke AccessBinding; В ПРЕДЕЛАХ TTL кешированный allow ещё обслуживается
	// (ограниченное окно — без live Check).
	az.revoke()
	clk = base.Add(1 * time.Second)
	checksBefore := az.checkCount()
	_, err = inter(ctx, req, info, h)
	require.NoError(t, err, "within TTL the cached allow still serves (bounded window)")
	require.Equal(t, 2, ran)
	require.Equal(t, checksBefore, az.checkCount(), "cache hit within TTL → no live Check")

	// 3) за пределами TTL → cache miss → live Check → revoked → NOT_FOUND, handler НЕ вызван.
	clk = base.Add(ttl + time.Second)
	_, err = inter(ctx, req, info, h)
	require.Equal(t, codes.NotFound, status.Code(err), "revoke enforced after cache TTL → NOT_FOUND")
	require.Equal(t, 2, ran, "handler NOT run once revoke enforced")
}

// TestNewInterceptor_ZeroCacheTTL_RevokeEnforcedImmediately — при выключенном
// positive-кеше (CacheTTL=0) revoke энфорсится на СЛЕДУЮЩЕМ запросе (любой реальный
// межзапросный интервал), без ожидания TTL.
func TestNewInterceptor_ZeroCacheTTL_RevokeEnforcedImmediately(t *testing.T) {
	az := &revokableAuthz{}
	c := authzCache(0) // выключен
	base := time.Now()
	clk := base
	c.SetNowFunc(func() time.Time { return clk })
	inter := interceptorWithCache(c, az)

	ctx := grantedCtx()
	info := &grpc.UnaryServerInfo{FullMethod: testGetMethod}
	req := &registryv1.GetRegistryRequest{RegistryId: testRegistry}
	ran := 0
	h := func(context.Context, any) (any, error) { ran++; return "ok", nil }

	// 1) grant активен → allowed.
	_, err := inter(ctx, req, info, h)
	require.NoError(t, err)
	require.Equal(t, 1, ran)

	// 2) revoke; следующий запрос (advance clock на любой реальный интервал) → live
	// Check → NOT_FOUND, handler НЕ вызван.
	az.revoke()
	clk = base.Add(time.Millisecond)
	_, err = inter(ctx, req, info, h)
	require.Equal(t, codes.NotFound, status.Code(err),
		"disabled positive cache → revoke enforced on the next request")
	require.Equal(t, 1, ran, "handler NOT run after revoke")
}
