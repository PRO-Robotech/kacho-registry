// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// pending_blob_race_integration_test.go — TEST-ONLY (ban #13): concurrent-race +
// nil-pool контракты PendingBlobRepo (registry_pending_blob, REG-33 Defect A).
// Дополняет pending_blob_integration_test.go: composite-PK ON CONFLICT DO UPDATE под
// параллельной нагрузкой (data-integrity.md §5 — race не ловится unit-тестом) и
// Docker-free nil-pool → Unavailable (fail-closed, не паника).
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

// TestPendingBlob_REG33A_ConcurrentUpsertSameKey_Idempotent — N goroutine'ов пишут
// ОДИН И ТОТ ЖЕ (registry_id, repo, digest) одновременно. ON CONFLICT DO UPDATE на
// composite-PK сериализует их на DB-уровне: все Record'ы успешны (не 23505), в итоге
// РОВНО одна строка, и BlobUploaded=true. Локает idempotency-под-конкуренцией (race-free
// upsert) — этот путь не воспроизводится single-threaded тестом.
func TestPendingBlob_REG33A_ConcurrentUpsertSameKey_Idempotent(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewPendingBlobRepo(pool, time.Hour)
	ctx := context.Background()

	const n = 32
	var wg sync.WaitGroup
	errs := make([]error, n)
	start := make(chan struct{}) // барьер: максимизировать contention (все стартуют разом)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = repo.RecordUploadedBlob(ctx, pbReg, pbRepo, pbDigest)
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		require.NoErrorf(t, err, "concurrent Record #%d обязан быть успешным upsert (не 23505)", i)
	}

	var rows int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_registry.registry_pending_blob WHERE registry_id=$1 AND repo=$2 AND digest=$3`,
		pbReg, pbRepo, pbDigest).Scan(&rows))
	require.Equal(t, 1, rows, "concurrent upsert одного ключа → ровно одна строка")

	seen, err := repo.BlobUploaded(ctx, pbReg, pbRepo, pbDigest)
	require.NoError(t, err)
	require.True(t, seen, "после concurrent upsert блоб виден")
}

// TestPendingBlob_NilPool_Unavailable — nil pool (composition root не подал pgxpool):
// каждый метод возвращает ErrUnavailable (fail-closed), НЕ паникует. Docker-free
// (не зовёт setupTestDB → выполняется и в -short).
func TestPendingBlob_NilPool_Unavailable(t *testing.T) {
	repo := kachopg.NewPendingBlobRepo(nil, time.Hour)
	ctx := context.Background()

	require.True(t, stderrors.Is(repo.RecordUploadedBlob(ctx, pbReg, pbRepo, pbDigest), regerrors.ErrUnavailable),
		"nil pool: RecordUploadedBlob → ErrUnavailable")

	_, err := repo.BlobUploaded(ctx, pbReg, pbRepo, pbDigest)
	require.True(t, stderrors.Is(err, regerrors.ErrUnavailable), "nil pool: BlobUploaded → ErrUnavailable")

	_, err = repo.SweepStale(ctx)
	require.True(t, stderrors.Is(err, regerrors.ErrUnavailable), "nil pool: SweepStale → ErrUnavailable")
}
