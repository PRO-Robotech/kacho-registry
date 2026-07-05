// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// registry_source_version_integration_test.go — outbox source_version обязан быть
// commit-order-monotonic per-object маркером (BIGSERIAL id outbox-строки), а НЕ
// to_jsonb(now()) (now() фиксируется на BEGIN → под конкуренцией мог оказаться в
// обратном commit-порядку). Finding: KAC sec-hardening 2026-07-05.
package pg_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	registry "github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/api/registry"
	"github.com/PRO-Robotech/kacho-registry/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho-registry/internal/repo/kacho/pg"
)

// sourceVersionAndID читает (source_version, id) последней outbox-строки ресурса.
func sourceVersionAndID(t *testing.T, pool *pgxpool.Pool, resourceID string) (int64, int64) {
	t.Helper()
	var srcVer, id int64
	err := pool.QueryRow(context.Background(),
		`SELECT (payload->>'source_version')::bigint, id
		   FROM kacho_registry.registry_outbox
		  WHERE resource_id=$1
		  ORDER BY id DESC LIMIT 1`, resourceID).Scan(&srcVer, &id)
	require.NoError(t, err)
	return srcVer, id
}

// TestRepo_SourceVersion_EqualsOutboxRowID — source_version штампуется BIGSERIAL id
// самой outbox-строки (numeric, commit-order-monotonic), а не timestamp'ом.
func TestRepo_SourceVersion_EqualsOutboxRowID(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewRegistryRepo(pool)
	ctx := context.Background()

	r := newReg("prj-P", "team-images", map[string]string{"env": "prod"})
	_, err := repo.Insert(ctx, r, domain.RegisterIntentForCreate(r, "user", "usr-alice"))
	require.NoError(t, err)

	srcVer, id := sourceVersionAndID(t, pool, r.ID)
	require.Equal(t, id, srcVer, "source_version == outbox row id (numeric monotonic marker)")
}

// TestRepo_SourceVersion_MonotonicAcrossUpdates — последовательные mutation'ы одного
// реестра дают строго растущий source_version (последнее состояние → больший маркер,
// last-source-state-wins в iam-mirror корректен).
func TestRepo_SourceVersion_MonotonicAcrossUpdates(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewRegistryRepo(pool)
	ctx := context.Background()

	r := newReg("prj-P", "team-images", map[string]string{"env": "prod"})
	_, err := repo.Insert(ctx, r, domain.RegisterIntentForCreate(r, "user", "usr-alice"))
	require.NoError(t, err)
	v0, _ := sourceVersionAndID(t, pool, r.ID)

	upd := func(env string) int64 {
		_, uerr := repo.Update(ctx, registry.UpdateSpec{RegistryID: r.ID, ApplyLabels: true, Labels: map[string]string{"env": env}},
			func(rr *domain.Registry) domain.RegisterIntent { return domain.RegisterIntentForUpdate(rr) })
		require.NoError(t, uerr)
		v, _ := sourceVersionAndID(t, pool, r.ID)
		return v
	}
	v1 := upd("staging")
	v2 := upd("canary")
	require.Greater(t, v1, v0, "update-1 source_version strictly increases")
	require.Greater(t, v2, v1, "update-2 source_version strictly increases")
}
