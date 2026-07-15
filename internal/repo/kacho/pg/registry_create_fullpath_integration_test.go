// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package pg_test — integration-тест ПОЛНОГО Create-пути use-case против реального
// Postgres 16 (миграция 0001). Закрывает шов, который repo-only и unit-тесты НЕ
// покрывают: синхронная вставка LRO-строки через corelib operations.Repo
// (CreateWithPrincipal) в таблицу operations + атомарный writer.Insert (registries +
// registry_outbox) + async worker-финализация (MarkDone). Именно этот путь падал на
// живом стенде «internal database error» без лог-строки при зелёном repo-integration —
// сверяет схему operations/registries/outbox 0001 против реальных INSERT-стейтментов.
package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-corelib/operations"

	registry "github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/api/registry"
	"github.com/PRO-Robotech/kacho-registry/internal/domain"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
	kachopg "github.com/PRO-Robotech/kacho-registry/internal/repo/kacho/pg"
)

// stubZotFP — минимальный ZotClient (Create не ходит в zot; заглушки для интерфейса).
type stubZotFP struct{}

func (stubZotFP) ListRepositories(context.Context, registry.RepoListQuery) ([]*domain.Repository, string, error) {
	return nil, "", nil
}
func (stubZotFP) ListTags(context.Context, registry.TagListQuery) ([]*domain.Tag, string, error) {
	return nil, "", nil
}
func (stubZotFP) DeleteTag(context.Context, string, string, string) error { return nil }
func (stubZotFP) NamespaceEmpty(context.Context, string) (bool, error)    { return true, nil }
func (stubZotFP) RemoveNamespace(context.Context, string) error           { return nil }
func (stubZotFP) TriggerGC(context.Context, string) error                 { return nil }
func (stubZotFP) Stats(context.Context, string) (*domain.RegistryStats, error) {
	return &domain.RegistryStats{}, nil
}
func (stubZotFP) RepositoryProjection(context.Context, string, string) (*domain.Repository, error) {
	return nil, nil
}
func (stubZotFP) RepositoryEmpty(context.Context, string, string) (bool, error) { return true, nil }
func (stubZotFP) RenameRepository(context.Context, string, string, string) error {
	return nil
}
func (stubZotFP) ListReferrers(context.Context, string, string, string, string) ([]*domain.Referrer, error) {
	return nil, nil
}

// stubIAMFP — project всегда существует (cross-domain precheck проходит).
type stubIAMFP struct{}

func (stubIAMFP) ProjectExists(context.Context, string) error { return nil }

func aliceCtxFP() context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr-alice", DisplayName: "alice"})
}

// awaitOpDoneFP — детерминированное ожидание финализации LRO-worker'а (poll, не sleep).
func awaitOpDoneFP(t *testing.T, ops operations.Repo, id string) *operations.Operation {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		op, err := ops.Get(context.Background(), id)
		if err == nil && op.Done {
			return op
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("operation %s did not finalize in time", id)
	return nil
}

// REG-01 — полный Create-путь: sync-вставка operations-строки (corelib
// CreateWithPrincipal) + writer.Insert (registries+outbox) + async MarkDone. Проверяет,
// что все три INSERT'а совместимы со схемой миграции 0001 (регресс-гвард против
// live-only «internal database error» на operations-INSERT).
func TestUseCase_REG01_FullCreatePath_OperationsInsert(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewRegistryRepo(pool)
	ops := operations.NewRepo(pool, "kacho_registry")
	uc := registry.New(repo, repo, kachopg.NewRepositoryConfigRepo(pool), stubZotFP{}, stubIAMFP{}, repo, ops, "registry.kacho.local")

	op, err := uc.Create(aliceCtxFP(), registry.CreateSpec{
		ProjectID: "prj-P", Name: "team-images", Description: "CI images",
		Labels: map[string]string{"env": "prod"},
	})
	require.NoError(t, err, "Create must not fail on real schema (operations/registries/outbox INSERT)")
	require.NotNil(t, op)
	require.False(t, op.Done, "async: Operation returned done=false")

	// Sync-путь: LRO-строка операции РЕАЛЬНО вставлена в operations (не «internal
	// database error»). Читаем её тем же corelib repo из БД.
	stored, gerr := ops.Get(context.Background(), op.ID)
	require.NoError(t, gerr, "operations row inserted synchronously (CreateWithPrincipal)")
	require.Equal(t, "user", stored.Principal.Type)
	require.Equal(t, "usr-alice", stored.Principal.ID)
	require.NotNil(t, op.Metadata, "Create metadata (registry_id) заполнена")

	// Async worker финализирует Operation ресурсом (MarkDone).
	done := awaitOpDoneFP(t, ops, op.ID)
	require.Nil(t, done.Error, "worker finalizes success, not error")
	require.NotNil(t, done.Response)

	// Registry реально в БД + ровно один fga.register-intent.
	var createdID string
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT id FROM kacho_registry.registries WHERE project_id=$1 AND name=$2`,
		"prj-P", "team-images").Scan(&createdID))
	require.NotEmpty(t, createdID)
	require.Equal(t, 1, countOutbox(t, pool, createdID, domain.FGAEventRegister))

	// Get round-trip через repo.
	got, err := repo.Get(context.Background(), createdID)
	require.NoError(t, err)
	require.Equal(t, domain.RegistryStatusActive, got.Status)
	require.Equal(t, map[string]string{"env": "prod"}, got.Labels)

	// Sanity: несуществующий id → ErrNotFound (repo-путь не сломан).
	_, err = repo.Get(context.Background(), "regNONEXISTENT0000000")
	require.ErrorIs(t, err, regerrors.ErrNotFound)
}
