// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package retry — конвенциональные обертки для повторов gRPC-вызовов с
// экспоненциальным backoff. Поверх `kacho-corelib/backoff`.
//
// Использование в cross-service-клиентах:
//
//	var resp *pb.Resp
//	err := retry.OnUnavailable(ctx, func(ctx context.Context) error {
//	    var err error
//	    resp, err = client.Foo(ctx, req)
//	    return err
//	})
//
// retry-y:
//   - OnUnavailable — только при codes.Unavailable (peer downlink, network glitch)
//   - OnAborted — при codes.Aborted (OCC retry)
//   - OnCodes(codes...) — пользовательский набор кодов
package retry

import (
	"context"
	"errors"
	"time"

	cbackoff "github.com/PRO-Robotech/kacho-corelib/backoff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Defaults — стандартные параметры экспоненциального backoff для cross-service
// gRPC-вызовов в Kachō.
//
//   - InitialInterval: 100ms
//   - Multiplier: 2.0
//   - MaxInterval: 5s
//   - MaxElapsed: 30s (после этого retry прекращается, ошибка возвращается)
//
// Этого достаточно для типичных перезапусков peer-Pod-а (rolling-restart 5-15s).
var Defaults = struct {
	InitialInterval     time.Duration
	Multiplier          float64
	MaxInterval         time.Duration
	MaxElapsed          time.Duration
	RandomizationFactor float64
}{
	InitialInterval:     100 * time.Millisecond,
	Multiplier:          2.0,
	MaxInterval:         5 * time.Second,
	MaxElapsed:          30 * time.Second,
	RandomizationFactor: 0.2,
}

// OnUnavailable вызывает fn с retry на codes.Unavailable.
// Ctx-cancel прерывает retry-цикл немедленно.
//
// ВНИМАНИЕ (идемпотентность): применять ТОЛЬКО к идемпотентным вызовам — read'ам
// либо мутациям с ключом идемпотентности. codes.Unavailable может прийти ПОСЛЕ
// того, как peer уже применил мутацию (обрыв на ответе), поэтому слепой retry
// не-идемпотентной мутации (Create/Allocate без idempotency-key) рискует задвоить
// эффект. Для не-идемпотентных мутаций используйте отдельный idempotency-механизм.
func OnUnavailable(ctx context.Context, fn func(ctx context.Context) error) error {
	return OnCodes(ctx, fn, codes.Unavailable)
}

// OnAborted — для OCC-retry (codes.Aborted) при concurrent-обновлениях.
func OnAborted(ctx context.Context, fn func(ctx context.Context) error) error {
	return OnCodes(ctx, fn, codes.Aborted)
}

// OnCodes — retry если grpc-status попадает в один из перечисленных кодов.
// Любой другой error (включая ctx-cancel) — fail-fast.
func OnCodes(ctx context.Context, fn func(ctx context.Context) error, retryCodes ...codes.Code) error {
	bo := cbackoff.ExponentialBackoffBuilder().
		WithInitialInterval(Defaults.InitialInterval).
		WithMultiplier(Defaults.Multiplier).
		WithMaxInterval(Defaults.MaxInterval).
		WithMaxElapsedThreshold(Defaults.MaxElapsed).
		WithRandomizationFactor(Defaults.RandomizationFactor).
		Build()

	for {
		err := fn(ctx)
		if err == nil {
			return nil
		}
		if !shouldRetry(err, retryCodes) {
			return err
		}
		next := bo.NextBackOff()
		if next == cbackoff.Stop {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(next):
			// loop
		}
	}
}

func shouldRetry(err error, retryCodes []codes.Code) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	st, ok := status.FromError(err)
	if !ok {
		return false
	}
	for _, c := range retryCodes {
		if st.Code() == c {
			return true
		}
	}
	return false
}
