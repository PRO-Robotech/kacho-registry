// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// repository_config_guard_integration_test.go — integration-тесты (testcontainers PG16)
// ACTIVE-guard (A24) + transactional-outbox эмиссии config-overlay Repository (RG-1)
// против реального Postgres 16 с миграцией 0005. Guard/outbox — DB-level инварианты,
// не ловятся unit-тестом. Имена трассируются к RG-1-<Group><NN>.
package pg_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	registry "github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/api/registry"
	"github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/shared/serviceerr"
	"github.com/PRO-Robotech/kacho-registry/internal/domain"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
	kachopg "github.com/PRO-Robotech/kacho-registry/internal/repo/kacho/pg"
)

// markRegistryDeleting переводит реестр в DELETING (CAS forward-only) для A24-guard.
func markRegistryDeleting(t *testing.T, pool *pgxpool.Pool, regID string) {
	t.Helper()
	_, err := kachopg.NewRegistryRepo(pool).MarkDeleting(context.Background(), regID)
	require.NoError(t, err)
}

// RG-1-A24 — overlay-мутации в реестре DELETING → FAILED_PRECONDITION "registry is being
// deleted" (same-tx ACTIVE-guard SELECT registries.status FOR UPDATE). Insert/Update/
// Rekey/Delete — все отвергаются; overlay не создаётся/не меняется.
func TestRepoConfig_RG1A24_ActiveGuard_Deleting(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewRepositoryConfigRepo(pool)
	ctx := context.Background()
	regID := seedRegistry(t, pool, "prj-P", "reg-a24")

	// Pre-seed durable overlay (пока реестр ACTIVE) для Update/Rekey/Delete-проверок.
	_, err := repo.InsertConfig(ctx, newCfg(regID, "keep/svc", domain.VisibilityPrivate, nil))
	require.NoError(t, err)

	markRegistryDeleting(t, pool, regID)

	assertBeingDeleted := func(t *testing.T, err error) {
		t.Helper()
		require.ErrorIs(t, err, regerrors.ErrFailedPrecondition)
		st := status.Convert(serviceerr.ToStatus(err))
		require.Equal(t, codes.FailedPrecondition, st.Code())
		require.Equal(t, "registry is being deleted", st.Message(), "A24 контракт-текст")
	}

	_, ierr := repo.InsertConfig(ctx, newCfg(regID, "new/svc", domain.VisibilityPrivate, nil))
	assertBeingDeleted(t, ierr)
	require.Equal(t, 0, countConfigs(t, pool, regID, "new/svc"), "overlay не создан в DELETING")

	_, uerr := repo.UpdateConfig(ctx, registry.RepositoryConfigUpdate{
		RegistryID: regID, Name: "keep/svc", Description: "x", ApplyDescription: true,
	})
	assertBeingDeleted(t, uerr)

	_, rerr := repo.RekeyConfig(ctx, regID, "keep/svc", "moved/svc")
	assertBeingDeleted(t, rerr)

	derr := repo.DeleteConfig(ctx, regID, "keep/svc")
	assertBeingDeleted(t, derr)
	require.Equal(t, 1, countConfigs(t, pool, regID, "keep/svc"), "overlay сохранён (delete отвергнут)")
}

// RG-1-A01/B01 — outbox-эмиссия в той же writer-tx: InsertConfig с register-intent'ами
// (adopt-owner + public-grant) пишет строки в registry_outbox АТОМАРНО с overlay-INSERT.
func TestRepoConfig_RG1_OutboxEmissionInTx(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewRepositoryConfigRepo(pool)
	ctx := context.Background()
	regID := seedRegistry(t, pool, "prj-P", "reg-outbox")

	before := countAllOutbox(t, pool)
	_, err := repo.InsertConfig(ctx, newCfg(regID, "pub/img", domain.VisibilityPublic, nil),
		registry.OutboxIntent{Event: domain.FGAEventRegister, Intent: domain.RegisterIntentForRepoPush(regID, "pub/img", "prj-P", "service_account:sva-x")},
		registry.OutboxIntent{Event: domain.FGAEventRegister, Intent: domain.RegisterIntentForRepoPublicGrant(regID, "pub/img")},
	)
	require.NoError(t, err)
	require.Equal(t, before+2, countAllOutbox(t, pool), "2 outbox-строки эмитированы атомарно с INSERT")

	// public-grant строка несёт user:* v_get tuple.
	require.True(t, outboxHasWildcardVGet(t, pool, regID, "pub/img"), "user:* v_get intent записан")
}

// countAllOutbox — число всех строк registry_outbox (RG-1 overlay outbox-эмиссия).
func countAllOutbox(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM kacho_registry.registry_outbox`).Scan(&n))
	return n
}

// outboxHasWildcardVGet — есть ли в outbox intent с "user:* v_get registry_repository:<reg>/<repo>".
func outboxHasWildcardVGet(t *testing.T, pool *pgxpool.Pool, regID, repo string) bool {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM kacho_registry.registry_outbox
		 WHERE payload::text LIKE '%user:*%' AND payload::text LIKE '%v_get%'
		   AND resource_id = $1`, regID+"/"+repo).Scan(&n))
	return n > 0
}
