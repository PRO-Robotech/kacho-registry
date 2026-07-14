// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// pending_blob_integration_test.go — integration-тесты PendingBlobRepo
// (registry_pending_blob, REG-33 Defect A) против реального Postgres 16
// (testcontainers, миграция 0003). Проверяет idempotent-upsert, freshness-TTL
// предикат BlobUploaded и TTL-sweep — DB-сторона учёта загруженных блобов.
package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	kachopg "github.com/PRO-Robotech/kacho-registry/internal/repo/kacho/pg"
)

const (
	pbReg    = "regPB00000000000000"
	pbRepo   = "app"
	pbDigest = "sha256:layer0000000000000000000000000000000000000000000000000000000000"
)

// TestPendingBlob_REG33A_UpsertAndFreshRead — Record пишет строку; BlobUploaded в
// пределах TTL видит её; повторный Record того же (reg,repo,digest) идемпотентен
// (upsert, не дубль-PK-ошибка) и освежает uploaded_at.
func TestPendingBlob_REG33A_UpsertAndFreshRead(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewPendingBlobRepo(pool, time.Hour)
	ctx := context.Background()

	// до записи — не загружен.
	got, err := repo.BlobUploaded(ctx, pbReg, pbRepo, pbDigest)
	require.NoError(t, err)
	require.False(t, got, "до Record блоб не числится загруженным")

	require.NoError(t, repo.RecordUploadedBlob(ctx, pbReg, pbRepo, pbDigest))
	got, err = repo.BlobUploaded(ctx, pbReg, pbRepo, pbDigest)
	require.NoError(t, err)
	require.True(t, got, "после Record свежий блоб виден в пределах TTL")

	// идемпотентность: повторный Record того же ключа — upsert, не 23505.
	require.NoError(t, repo.RecordUploadedBlob(ctx, pbReg, pbRepo, pbDigest),
		"повторный Record того же (reg,repo,digest) идемпотентен (ON CONFLICT DO UPDATE)")

	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_registry.registry_pending_blob WHERE registry_id=$1 AND repo=$2 AND digest=$3`,
		pbReg, pbRepo, pbDigest).Scan(&n))
	require.Equal(t, 1, n, "upsert держит ровно одну строку на ключ")
}

// TestPendingBlob_REG33A_PerRepoScoped — строка строго per-(registry,repo): тот же
// digest в другом repo/registry НЕ считается загруженным (иначе cross-repo blob-oracle).
func TestPendingBlob_REG33A_PerRepoScoped(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewPendingBlobRepo(pool, time.Hour)
	ctx := context.Background()

	require.NoError(t, repo.RecordUploadedBlob(ctx, pbReg, pbRepo, pbDigest))

	otherRepo, err := repo.BlobUploaded(ctx, pbReg, "other", pbDigest)
	require.NoError(t, err)
	require.False(t, otherRepo, "тот же digest в другом repo не числится загруженным")

	otherReg, err := repo.BlobUploaded(ctx, "regXX00000000000000", pbRepo, pbDigest)
	require.NoError(t, err)
	require.False(t, otherReg, "тот же digest в другом registry не числится загруженным")
}

// TestPendingBlob_REG33A_TTLFreshnessAndSweep — строка старше TTL: BlobUploaded её НЕ
// видит (freshness-предикат), а SweepStale удаляет. Свежую строку sweep не трогает.
func TestPendingBlob_REG33A_TTLFreshnessAndSweep(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewPendingBlobRepo(pool, time.Hour)
	ctx := context.Background()

	// одна свежая (now) и одна протухшая строка (uploaded_at = 2h назад).
	require.NoError(t, repo.RecordUploadedBlob(ctx, pbReg, pbRepo, pbDigest))
	const staleDigest = "sha256:stale000000000000000000000000000000000000000000000000000000000"
	require.NoError(t, repo.RecordUploadedBlob(ctx, pbReg, pbRepo, staleDigest))
	_, err := pool.Exec(ctx,
		`UPDATE kacho_registry.registry_pending_blob SET uploaded_at = now() - interval '2 hours'
		 WHERE registry_id=$1 AND repo=$2 AND digest=$3`, pbReg, pbRepo, staleDigest)
	require.NoError(t, err)

	// протухшая (2h > TTL=1h) не видна.
	staleSeen, err := repo.BlobUploaded(ctx, pbReg, pbRepo, staleDigest)
	require.NoError(t, err)
	require.False(t, staleSeen, "строка старше TTL не проходит freshness-предикат")

	// свежая видна.
	freshSeen, err := repo.BlobUploaded(ctx, pbReg, pbRepo, pbDigest)
	require.NoError(t, err)
	require.True(t, freshSeen, "свежая строка видна")

	// sweep удаляет только протухшую.
	deleted, err := repo.SweepStale(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(1), deleted, "sweep удаляет ровно одну протухшую строку")

	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_registry.registry_pending_blob`).Scan(&n))
	require.Equal(t, 1, n, "свежая строка переживает sweep")

	freshStill, err := repo.BlobUploaded(ctx, pbReg, pbRepo, pbDigest)
	require.NoError(t, err)
	require.True(t, freshStill, "свежая строка по-прежнему видна после sweep")
}
