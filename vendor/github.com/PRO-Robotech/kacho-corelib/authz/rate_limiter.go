// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package authz

import (
	"sync"
	"time"
)

// rateLimiter — token-bucket per-Principal на denied-storm protection. При
// flooding `GET /vpc/v1/networks/*` от
// unauthorized user negative cache отсутствует (negative-not-cached) →
// каждый запрос идет в `kacho-iam.Check` → потенциальный DoS на kacho-iam.
//
// Token-bucket per-Principal дает верхнюю границу rate'а Check'ов от одного
// subject'а. По истечении баланса → `ResourceExhausted` без обращения в FGA.
//
// Тhread-safe; eviction inactive subjects через periodic sweep.
type rateLimiter struct {
	mu sync.Mutex

	// ratePerSec — токенов в секунду per subject (например 100).
	// 0 / negative → rate-limit disabled.
	ratePerSec float64
	// burst — burst-size bucket'а (по умолчанию 2x ratePerSec).
	burst float64

	// buckets: subjectID → bucket-state.
	buckets map[string]*bucket

	now func() time.Time
}

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

// newRateLimiter создает лимитер. ratePerSec ≤ 0 → disabled (Allow всегда true).
func newRateLimiter(ratePerSec float64) *rateLimiter {
	if ratePerSec < 0 {
		ratePerSec = 0
	}
	return &rateLimiter{
		ratePerSec: ratePerSec,
		burst:      ratePerSec * 2,
		buckets:    make(map[string]*bucket, 64),
		now:        time.Now,
	}
}

// Allow возвращает true если subjectID может выполнить одну Check'у сейчас.
// Если rate-limit disabled (ratePerSec ≤ 0) — всегда true.
//
// Реализация — стандартный token-bucket: refill по elapsed-time × rate.
func (rl *rateLimiter) Allow(subjectID string) bool {
	if rl.ratePerSec <= 0 {
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := rl.now()
	b, exists := rl.buckets[subjectID]
	if !exists {
		// Новый subject — начинаем с full burst.
		b = &bucket{tokens: rl.burst, lastSeen: now}
		rl.buckets[subjectID] = b
	}
	// Refill.
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens += elapsed * rl.ratePerSec
	if b.tokens > rl.burst {
		b.tokens = rl.burst
	}
	b.lastSeen = now
	if b.tokens < 1.0 {
		return false
	}
	b.tokens -= 1.0
	return true
}

// EvictInactive удаляет subject-bucket'ы, у которых lastSeen старше maxAge.
// Вызывается из background-loop'а раз в minуту, чтобы избежать unbounded
// memory-growth при большом subject-vocabulary.
func (rl *rateLimiter) EvictInactive(maxAge time.Duration) int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := rl.now().Add(-maxAge)
	removed := 0
	for s, b := range rl.buckets {
		if b.lastSeen.Before(cutoff) {
			delete(rl.buckets, s)
			removed++
		}
	}
	return removed
}
