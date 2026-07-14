// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// push_grant_integration_test.go — integration-тесты PushGrantRepo
// (registry_push_grant, REG-33 immediate-pull) против реального Postgres 16
// (testcontainers, миграция 0004). Проверяет idempotent-upsert, freshness-TTL
// предикат PushGranted, TTL-sweep и per-(registry,repo,subject) scoping —
// DB-сторону push-ownership кеша.
package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	kachopg "github.com/PRO-Robotech/kacho-registry/internal/repo/kacho/pg"
)

const (
	pgReg     = "regPG00000000000000"
	pgRepo    = "app"
	pgSubject = "service_account:sva00000000000000000"
)

// TestPushGrant_REG33IP_UpsertAndFreshRead — Record пишет строку; PushGranted в пределах
// TTL видит её; повторный Record того же (reg,repo,subject) идемпотентен (upsert, не
// дубль-PK-ошибка) и освежает granted_at.
func TestPushGrant_REG33IP_UpsertAndFreshRead(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewPushGrantRepo(pool, time.Hour)
	ctx := context.Background()

	// до записи — не выдан.
	got, err := repo.PushGranted(ctx, pgReg, pgRepo, pgSubject)
	require.NoError(t, err)
	require.False(t, got, "до Record push-grant не числится")

	require.NoError(t, repo.RecordPushGrant(ctx, pgReg, pgRepo, pgSubject))
	got, err = repo.PushGranted(ctx, pgReg, pgRepo, pgSubject)
	require.NoError(t, err)
	require.True(t, got, "после Record свежий push-grant виден в пределах TTL")

	// идемпотентность: повторный Record того же ключа — upsert, не 23505.
	require.NoError(t, repo.RecordPushGrant(ctx, pgReg, pgRepo, pgSubject),
		"повторный Record того же (reg,repo,subject) идемпотентен (ON CONFLICT DO UPDATE)")

	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_registry.registry_push_grant WHERE registry_id=$1 AND repo=$2 AND subject=$3`,
		pgReg, pgRepo, pgSubject).Scan(&n))
	require.Equal(t, 1, n, "upsert держит ровно одну строку на ключ")
}

// TestPushGrant_REG33IP_PerSubjectRepoScoped — строка строго per-(registry,repo,subject):
// тот же repo, но ДРУГОЙ subject НЕ числится (иначе cross-tenant leak); тот же subject, но
// другой repo/registry — тоже нет.
func TestPushGrant_REG33IP_PerSubjectRepoScoped(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewPushGrantRepo(pool, time.Hour)
	ctx := context.Background()

	require.NoError(t, repo.RecordPushGrant(ctx, pgReg, pgRepo, pgSubject))

	// другой subject на тот же repo — не выдан (ключевой cross-tenant инвариант).
	otherSubject, err := repo.PushGranted(ctx, pgReg, pgRepo, "service_account:sva99999999999999999")
	require.NoError(t, err)
	require.False(t, otherSubject, "тот же repo, другой subject — push-grant не числится (cross-tenant)")

	// тот же subject, другой repo — не выдан.
	otherRepo, err := repo.PushGranted(ctx, pgReg, "other", pgSubject)
	require.NoError(t, err)
	require.False(t, otherRepo, "тот же subject, другой repo — не числится")

	// тот же subject/repo, другой registry — не выдан.
	otherReg, err := repo.PushGranted(ctx, "regXX00000000000000", pgRepo, pgSubject)
	require.NoError(t, err)
	require.False(t, otherReg, "тот же subject/repo, другой registry — не числится")
}

// TestPushGrant_REG33IP_TTLFreshnessAndSweep — строка старше TTL: PushGranted её НЕ видит
// (freshness-предикат), а SweepStale удаляет. Свежую строку sweep не трогает.
func TestPushGrant_REG33IP_TTLFreshnessAndSweep(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewPushGrantRepo(pool, time.Hour)
	ctx := context.Background()

	// одна свежая (now) и одна протухшая строка (granted_at = 2h назад).
	require.NoError(t, repo.RecordPushGrant(ctx, pgReg, pgRepo, pgSubject))
	const staleSubject = "service_account:sva11111111111111111"
	require.NoError(t, repo.RecordPushGrant(ctx, pgReg, pgRepo, staleSubject))
	_, err := pool.Exec(ctx,
		`UPDATE kacho_registry.registry_push_grant SET granted_at = now() - interval '2 hours'
		 WHERE registry_id=$1 AND repo=$2 AND subject=$3`, pgReg, pgRepo, staleSubject)
	require.NoError(t, err)

	// протухшая (2h > TTL=1h) не видна.
	staleSeen, err := repo.PushGranted(ctx, pgReg, pgRepo, staleSubject)
	require.NoError(t, err)
	require.False(t, staleSeen, "строка старше TTL не проходит freshness-предикат")

	// свежая видна.
	freshSeen, err := repo.PushGranted(ctx, pgReg, pgRepo, pgSubject)
	require.NoError(t, err)
	require.True(t, freshSeen, "свежая строка видна")

	// sweep удаляет только протухшую.
	deleted, err := repo.SweepStale(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(1), deleted, "sweep удаляет ровно одну протухшую строку")

	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_registry.registry_push_grant`).Scan(&n))
	require.Equal(t, 1, n, "свежая строка переживает sweep")

	freshStill, err := repo.PushGranted(ctx, pgReg, pgRepo, pgSubject)
	require.NoError(t, err)
	require.True(t, freshStill, "свежая строка по-прежнему видна после sweep")
}

// TestPushGrant_REG33IP_DeleteRemovesExactRow — delete-on-materialized: DeletePushGrant
// удаляет РОВНО строку (registry_id, repo, subject) и ничего больше. После удаления
// PushGranted для неё → false (мост снят); соседние строки (другой subject/repo) целы.
// Локает revoke-safety: как только реальный v_get материализовался и pull снял мост,
// последующий revoke уже не обходится через push-grant.
func TestPushGrant_REG33IP_DeleteRemovesExactRow(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewPushGrantRepo(pool, time.Hour)
	ctx := context.Background()

	const otherSubject = "service_account:sva22222222222222222"
	require.NoError(t, repo.RecordPushGrant(ctx, pgReg, pgRepo, pgSubject))
	require.NoError(t, repo.RecordPushGrant(ctx, pgReg, pgRepo, otherSubject)) // тот же repo, другой subject
	require.NoError(t, repo.RecordPushGrant(ctx, pgReg, "other", pgSubject))   // тот же subject, другой repo

	// удаляем ровно (pgReg, pgRepo, pgSubject).
	require.NoError(t, repo.DeletePushGrant(ctx, pgReg, pgRepo, pgSubject))

	gone, err := repo.PushGranted(ctx, pgReg, pgRepo, pgSubject)
	require.NoError(t, err)
	require.False(t, gone, "удалённая строка больше не числится (мост снят)")

	// соседи целы.
	otherSubj, err := repo.PushGranted(ctx, pgReg, pgRepo, otherSubject)
	require.NoError(t, err)
	require.True(t, otherSubj, "другой subject на тот же repo НЕ затронут удалением")
	otherRepo, err := repo.PushGranted(ctx, pgReg, "other", pgSubject)
	require.NoError(t, err)
	require.True(t, otherRepo, "тот же subject на другой repo НЕ затронут удалением")

	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_registry.registry_push_grant`).Scan(&n))
	require.Equal(t, 2, n, "удалена ровно одна строка")
}

// TestPushGrant_REG33IP_DeleteAbsentRow_NoError — DeletePushGrant несуществующей строки —
// идемпотентный no-op (0 rows, без ошибки): безопасно звать безусловно на allow-ветке pull.
func TestPushGrant_REG33IP_DeleteAbsentRow_NoError(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewPushGrantRepo(pool, time.Hour)
	ctx := context.Background()

	require.NoError(t, repo.DeletePushGrant(ctx, pgReg, pgRepo, pgSubject),
		"удаление отсутствующей строки — дешёвый no-op без ошибки")
}

// TestPushGrant_REG33IP_RepushRefreshesGrant — re-push (повторный Record) освежает granted_at:
// строка, которая была бы протухшей, снова становится свежей → PushGranted=true. Локает
// «re-push держит запись свежей всё push-окно».
func TestPushGrant_REG33IP_RepushRefreshesGrant(t *testing.T) {
	pool := setupTestDB(t)
	// короткий TTL, чтобы «старая» запись протухла без sleep.
	repo := kachopg.NewPushGrantRepo(pool, time.Hour)
	ctx := context.Background()

	require.NoError(t, repo.RecordPushGrant(ctx, pgReg, pgRepo, pgSubject))
	// искусственно состариваем строку до края TTL.
	_, err := pool.Exec(ctx,
		`UPDATE kacho_registry.registry_push_grant SET granted_at = now() - interval '2 hours'
		 WHERE registry_id=$1 AND repo=$2 AND subject=$3`, pgReg, pgRepo, pgSubject)
	require.NoError(t, err)

	stale, err := repo.PushGranted(ctx, pgReg, pgRepo, pgSubject)
	require.NoError(t, err)
	require.False(t, stale, "состаренная строка протухла (freshness)")

	// re-push освежает granted_at → снова свежая.
	require.NoError(t, repo.RecordPushGrant(ctx, pgReg, pgRepo, pgSubject))
	fresh, err := repo.PushGranted(ctx, pgReg, pgRepo, pgSubject)
	require.NoError(t, err)
	require.True(t, fresh, "re-push освежил granted_at → push-grant снова свежий")
}
