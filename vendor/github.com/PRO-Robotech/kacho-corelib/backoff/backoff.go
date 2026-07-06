// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package backoff — exponential / constant / zero backoff helpers.
//
// Использует cenkalti/backoff/v4 как базовую реализацию.
package backoff

import (
	"time"

	"github.com/cenkalti/backoff/v4"
)

type (
	// Backoff — alias на backoff.BackOff.
	Backoff = backoff.BackOff

	// BackOffContext — alias на backoff.BackOffContext.
	BackOffContext = backoff.BackOffContext //nolint:revive
)

var (
	// Stop — sentinel-значение, сигнализирующее «больше не повторять».
	Stop = backoff.Stop

	// WithContext оборачивает Backoff в context-aware вариант.
	WithContext = backoff.WithContext
)

// NewConstantBackOff возвращает backoff с фиксированным интервалом d.
func NewConstantBackOff(d time.Duration) Backoff {
	return &backoff.ConstantBackOff{Interval: d}
}

// ExponentialBackoffBuilder создает builder для exponential backoff.
//
//	bo := backoff.ExponentialBackoffBuilder().
//	    WithInitialInterval(100 * time.Millisecond).
//	    WithMultiplier(2.0).
//	    WithMaxInterval(5 * time.Second).
//	    WithMaxElapsedThreshold(30 * time.Second).
//	    WithRandomizationFactor(0.2).
//	    Build()
func ExponentialBackoffBuilder() exponentialBackoffBuilder { //nolint:revive
	return exponentialBackoffBuilder{inner: backoff.NewExponentialBackOff()}
}

type exponentialBackoffBuilder struct {
	inner *backoff.ExponentialBackOff
}

// Build возвращает построенный exponential backoff. Reset() инициализирует
// currentInterval=InitialInterval и startTime=now — иначе первый NextBackOff
// вернул бы cenkalti-дефолт 500ms, игнорируя сконфигурированный InitialInterval.
func (eb exponentialBackoffBuilder) Build() Backoff {
	ret := new(backoff.ExponentialBackOff)
	*ret = *eb.inner
	ret.Reset()
	return ret
}

// WithRandomizationFactor — фактор jitter в диапазоне [0..1]. Значения вне
// диапазона игнорируются: factor>1 может породить отрицательный интервал
// (мгновенный retry-storm), factor<0 бессмыслен.
func (eb exponentialBackoffBuilder) WithRandomizationFactor(d float64) exponentialBackoffBuilder {
	if d >= 0 && d <= 1 {
		eb.inner.RandomizationFactor = d
	}
	return eb
}

// WithInitialInterval — стартовый интервал.
func (eb exponentialBackoffBuilder) WithInitialInterval(d time.Duration) exponentialBackoffBuilder {
	if d >= 0 {
		eb.inner.InitialInterval = d
	}
	return eb
}

// WithMultiplier — множитель экспоненты (>= 1.0). Значения < 1.0 игнорируются:
// убывающий backoff не имеет смысла и ломает контракт «интервал растет».
func (eb exponentialBackoffBuilder) WithMultiplier(d float64) exponentialBackoffBuilder {
	if d >= 1.0 {
		eb.inner.Multiplier = d
	}
	return eb
}

// WithMaxInterval — максимальная длина интервала между попытками.
func (eb exponentialBackoffBuilder) WithMaxInterval(d time.Duration) exponentialBackoffBuilder {
	if d >= 0 {
		eb.inner.MaxInterval = d
	}
	return eb
}

// WithMaxElapsedThreshold — общий budget на retry. После — Stop.
func (eb exponentialBackoffBuilder) WithMaxElapsedThreshold(d time.Duration) exponentialBackoffBuilder {
	if d >= 0 {
		eb.inner.MaxElapsedTime = d
	}
	return eb
}
