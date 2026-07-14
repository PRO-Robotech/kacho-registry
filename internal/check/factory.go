// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package check

import (
	"errors"
	"log/slog"
	"time"

	"google.golang.org/grpc"

	"github.com/PRO-Robotech/kacho-corelib/authz"
)

// Options — параметры для NewInterceptor.
type Options struct {
	ServiceName string
	IAMConn     grpc.ClientConnInterface
	Breakglass  bool
	Logger      *slog.Logger

	// CacheTTL — TTL positive-кеша authz-Check интерсептора (ОБА листенера).
	// Ограничивает окно, в течение которого отозванный (revoked) субъект держит
	// закешированный allow ПОСЛЕ удаления AccessBinding: registry НЕ подписан на
	// IAM cache-invalidation (InternalAuthzCacheService.InvalidateSubject бьёт
	// только api-gateway) и db-per-service ⇒ LISTEN/NOTIFY от iam сюда не доходит →
	// revoke-окно = этот TTL + async fga-drain. Короткий дефолт (2s) держит окно
	// узким; 0 → positive-кеш выключен (каждый RPC — живой IAM Check). См. #33.
	CacheTTL time.Duration
}

// disabledCacheTTL — при CacheTTL<=0 positive-кеш «выключается» минимальным TTL:
// запись истекает раньше следующего RPC (монотонные часы строго растут между
// SetAllowed и Get разных запросов), поэтому ни один stale-allow не доживает до
// следующего Check → каждый RPC делает живой IAM Check (немедленный revoke).
// corelib authz.Cache не имеет first-class disabled-режима (NewCache(≤0) → 5s
// дефолт), поэтому «выкл» выражаем так, а не через отдельный no-op тип. См. #33.
const disabledCacheTTL = time.Nanosecond

// authzCache строит positive-decision кеш интерсептора по TTL:
//   - ttl > 0  → authz.NewCache(ttl): positive Check-результаты живут ttl
//     (revoke-окно ≤ ttl + fga-drain).
//   - ttl <= 0 → positive-кеш выключен (disabledCacheTTL): каждый RPC — живой Check.
func authzCache(ttl time.Duration) *authz.Cache {
	if ttl > 0 {
		return authz.NewCache(ttl)
	}
	return authz.NewCache(disabledCacheTTL)
}

// ErrIAMConnNotConfigured — IAM conn = nil И Breakglass=false.
var ErrIAMConnNotConfigured = errors.New("check: IAM connection not configured and Breakglass=false")

// NewInterceptor строит authz-интерсептор registry. Возвращает:
//   - (*authz.Interceptor, nil) — успех; вызывающий навешивает Unary()/Stream().
//   - (nil, ErrIAMConnNotConfigured) — IAM не сконфигурирован И Breakglass=false.
//     Решение за вызывающим: production → fatal; dev → пропустить интерсептор.
func NewInterceptor(opts Options) (*authz.Interceptor, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	// Breakglass → Client=nil (authz bypass); иначе IAM обязателен (fail-closed:
	// nil conn без breakglass = misconfig). Резолвим только Client; остальные поля
	// InterceptorOptions идентичны в обеих ветвях. Тюнинг-кнобы (CheckTimeout /
	// DenyRateLimitPerSec / AllowSystemPrincipal) оставлены на corelib-дефолтах —
	// registry их не конфигурирует, поэтому в литерал не вносятся (иначе — мёртвые
	// pass-through). Cache строится через authzCache(opts.CacheTTL): короткий TTL
	// (или 0 → выкл) ограничивает revoke-окно, т.к. registry не подписан на IAM
	// cache-invalidation (см. authzCache / #33).
	var client authz.CheckClient
	if !opts.Breakglass {
		if opts.IAMConn == nil {
			return nil, ErrIAMConnNotConfigured
		}
		client = NewIAMCheckClient(opts.IAMConn)
	}
	return authz.NewInterceptor(authz.InterceptorOptions{
		ServiceName: opts.ServiceName,
		Map:         PermissionMap(),
		Client:      client,
		Cache:       authzCache(opts.CacheTTL),
		Logger:      opts.Logger,
		Breakglass:  opts.Breakglass,
	}), nil
}
