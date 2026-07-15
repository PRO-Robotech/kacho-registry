// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// push_grant_race_integration_test.go — TEST-ONLY (ban #13): concurrent-race + nil-pool
// контракты PushGrantRepo (registry_push_grant, REG-33 immediate-pull). Дополняет
// push_grant_integration_test.go: composite-PK ON CONFLICT DO UPDATE под параллельной
// нагрузкой (re-push contention) + конкурентный Record||Delete (мост vs материализация)
// + Docker-free nil-pool → Unavailable.
package pg_test

import (
	"context"
	stderrors "errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
	kachopg "github.com/PRO-Robotech/kacho-registry/internal/repo/kacho/pg"
)

// TestPushGrant_REG33IP_ConcurrentUpsertSameKey_Idempotent — N goroutine'ов пишут ОДИН И
// ТОТ ЖЕ (registry_id, repo, subject) одновременно (concurrent re-push толкавшего). ON
// CONFLICT DO UPDATE на composite-PK сериализует: все Record'ы успешны, ровно одна строка,
// PushGranted=true. Race-free upsert — не воспроизводится single-threaded тестом.
func TestPushGrant_REG33IP_ConcurrentUpsertSameKey_Idempotent(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewPushGrantRepo(pool, time.Hour)
	ctx := context.Background()

	const n = 32
	var wg sync.WaitGroup
	errs := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = repo.RecordPushGrant(ctx, pgReg, pgRepo, pgSubject)
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		require.NoErrorf(t, err, "concurrent RecordPushGrant #%d обязан быть успешным upsert (не 23505)", i)
	}

	var rows int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_registry.registry_push_grant WHERE registry_id=$1 AND repo=$2 AND subject=$3`,
		pgReg, pgRepo, pgSubject).Scan(&rows))
	require.Equal(t, 1, rows, "concurrent upsert одного ключа → ровно одна строка")

	granted, err := repo.PushGranted(ctx, pgReg, pgRepo, pgSubject)
	require.NoError(t, err)
	require.True(t, granted, "после concurrent upsert push-grant виден")
}

// TestPushGrant_REG33IP_ConcurrentRecordAndDelete_NoError — конкурентные Record (re-push
// освежает мост) и Delete (delete-on-materialized снимает мост) на один ключ: обе операции
// атомарны на row-level, ни одна не ошибается и не блокирует-deadlock'ит. Финальное
// состояние детерминированно НЕ проверяем (гонка «кто последний»), но обе стороны обязаны
// завершиться без ошибки под -race. Локает совместимость двух путей моста.
func TestPushGrant_REG33IP_ConcurrentRecordAndDelete_NoError(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewPushGrantRepo(pool, time.Hour)
	ctx := context.Background()

	const n = 16
	var wg sync.WaitGroup
	recErrs := make([]error, n)
	delErrs := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(2)
		go func(i int) { defer wg.Done(); <-start; recErrs[i] = repo.RecordPushGrant(ctx, pgReg, pgRepo, pgSubject) }(i)
		go func(i int) { defer wg.Done(); <-start; delErrs[i] = repo.DeletePushGrant(ctx, pgReg, pgRepo, pgSubject) }(i)
	}
	close(start)
	wg.Wait()

	for i := 0; i < n; i++ {
		require.NoErrorf(t, recErrs[i], "concurrent Record #%d без ошибки", i)
		require.NoErrorf(t, delErrs[i], "concurrent Delete #%d без ошибки (индексный DELETE, no-op при отсутствии)", i)
	}

	// Ровно 0 или 1 строка — состав целостен (не дубль-PK).
	var rows int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_registry.registry_push_grant WHERE registry_id=$1 AND repo=$2 AND subject=$3`,
		pgReg, pgRepo, pgSubject).Scan(&rows))
	require.LessOrEqual(t, rows, 1, "composite-PK держит ≤1 строку на ключ даже под Record||Delete гонкой")
}

// TestPushGrant_NilPool_Unavailable — nil pool: каждый метод → ErrUnavailable (fail-closed),
// не паникует. Docker-free (выполняется и в -short).
func TestPushGrant_NilPool_Unavailable(t *testing.T) {
	repo := kachopg.NewPushGrantRepo(nil, time.Hour)
	ctx := context.Background()

	require.True(t, stderrors.Is(repo.RecordPushGrant(ctx, pgReg, pgRepo, pgSubject), regerrors.ErrUnavailable),
		"nil pool: RecordPushGrant → ErrUnavailable")

	_, err := repo.PushGranted(ctx, pgReg, pgRepo, pgSubject)
	require.True(t, stderrors.Is(err, regerrors.ErrUnavailable), "nil pool: PushGranted → ErrUnavailable")

	require.True(t, stderrors.Is(repo.DeletePushGrant(ctx, pgReg, pgRepo, pgSubject), regerrors.ErrUnavailable),
		"nil pool: DeletePushGrant → ErrUnavailable")

	_, err = repo.SweepStale(ctx)
	require.True(t, stderrors.Is(err, regerrors.ErrUnavailable), "nil pool: SweepStale → ErrUnavailable")
}
