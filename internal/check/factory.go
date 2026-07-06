// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package check

import (
	"errors"
	"log/slog"

	"google.golang.org/grpc"

	"github.com/PRO-Robotech/kacho-corelib/authz"
)

// Options — параметры для NewInterceptor.
type Options struct {
	ServiceName string
	IAMConn     grpc.ClientConnInterface
	Breakglass  bool
	Logger      *slog.Logger
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
	// pass-through). Cache строится явно (NewCache(0) → corelib TTL-дефолт).
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
		Cache:       authz.NewCache(0),
		Logger:      opts.Logger,
		Breakglass:  opts.Breakglass,
	}), nil
}
