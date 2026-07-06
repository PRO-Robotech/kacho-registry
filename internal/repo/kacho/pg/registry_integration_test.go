// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package pg_test — integration-тесты repo-слоя kacho-registry против реального
// Postgres 16 (testcontainers) с применённой миграцией 0001. Проверяет DB-инварианты
// (partial UNIQUE(project_id,name)WHERE status<>'DELETING', CAS forward-only,
// transactional outbox) — включая concurrent-race, который не ловится unit-тестом.
// Имена тестов трассируются к acceptance-сценариям (REG-NN).
package pg_test

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	coredb "github.com/PRO-Robotech/kacho-corelib/db"
	"github.com/PRO-Robotech/kacho-corelib/ids"

	registry "github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/api/registry"
	"github.com/PRO-Robotech/kacho-registry/internal/domain"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
	"github.com/PRO-Robotech/kacho-registry/internal/migrations"
	kachopg "github.com/PRO-Robotech/kacho-registry/internal/repo/kacho/pg"
)

// setupTestDB поднимает изолированный Postgres 16 с применённой миграцией и
// возвращает pool с search_path=kacho_registry,public.
func setupTestDB(t testing.TB) *pgxpool.Pool {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test (testing.Short)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	pgc, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("kacho_registry_test"),
		postgres.WithUsername("registry"),
		postgres.WithPassword("registry"),
		postgres.BasicWaitStrategies(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pgc.Terminate(context.Background()) })

	dsn, err := pgc.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.Up(db, "."))
	_ = db.Close()

	pool, err := coredb.NewPool(context.Background(), withSearchPath(dsn))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

func withSearchPath(dsn string) string {
	const opt = "options=-c%20search_path%3Dkacho_registry%2Cpublic"
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + opt
}

// newReg строит domain.Registry с сгенерированным id (prefix reg).
func newReg(projectID, name string, labels map[string]string) *domain.Registry {
	return &domain.Registry{
		ID:        ids.NewID(ids.PrefixRegistry),
		ProjectID: projectID,
		Name:      name,
		Labels:    labels,
		Status:    domain.RegistryStatusActive,
	}
}

// countOutbox считает строки registry_outbox по event_type для ресурса.
func countOutbox(t *testing.T, pool *pgxpool.Pool, resourceID, eventType string) int {
	t.Helper()
	var n int
	err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM kacho_registry.registry_outbox WHERE resource_id=$1 AND event_type=$2`,
		resourceID, eventType).Scan(&n)
	require.NoError(t, err)
	return n
}

// REG-01/REG-28 — Insert: строка + register-intent в ОДНОЙ tx (atomicity); Get
// round-trip полей; outbox несёт fga.register.
func TestRepo_REG01_InsertGetRoundTrip_OutboxInTx(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewRegistryRepo(pool)
	ctx := context.Background()

	reg := newReg("prj-P", "team-images", map[string]string{"env": "prod"})
	intent := domain.RegisterIntentForCreate(reg, "user", "usr-alice")
	created, err := repo.Insert(ctx, reg, intent)
	require.NoError(t, err)
	require.Equal(t, reg.ID, created.ID)
	require.Equal(t, domain.RegistryStatusActive, created.Status)
	require.False(t, created.CreatedAt.IsZero())

	got, err := repo.Get(ctx, reg.ID)
	require.NoError(t, err)
	require.Equal(t, "team-images", got.Name)
	require.Equal(t, "prj-P", got.ProjectID)
	require.Equal(t, map[string]string{"env": "prod"}, got.Labels)

	// Atomicity: register-intent записан в той же tx, что и строка.
	require.Equal(t, 1, countOutbox(t, pool, reg.ID, domain.FGAEventRegister))
}

// REG-04 — дубликат имени среди ЖИВЫХ реестров project'а → ErrAlreadyExists
// (partial UNIQUE(project_id,name)WHERE status<>'DELETING'). Строка-дубль и её
// outbox-intent НЕ появляются (rollback).
func TestRepo_REG04_DuplicateName_AlreadyExists(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewRegistryRepo(pool)
	ctx := context.Background()

	r1 := newReg("prj-P", "team-images", nil)
	_, err := repo.Insert(ctx, r1, domain.RegisterIntentForCreate(r1, "user", "usr-alice"))
	require.NoError(t, err)

	r2 := newReg("prj-P", "team-images", nil)
	_, err = repo.Insert(ctx, r2, domain.RegisterIntentForCreate(r2, "user", "usr-alice"))
	require.ErrorIs(t, err, regerrors.ErrAlreadyExists)
	require.Equal(t, 0, countOutbox(t, pool, r2.ID, domain.FGAEventRegister), "dup rollback: no outbox row")

	// Разные project'ы с тем же именем — не конфликтуют.
	r3 := newReg("prj-Q", "team-images", nil)
	_, err = repo.Insert(ctx, r3, domain.RegisterIntentForCreate(r3, "user", "usr-alice"))
	require.NoError(t, err)
}

// REG-04 edge — имя, освобождённое переходом в DELETING, немедленно доступно для
// повторного Create (partial-предикат исключает DELETING из индекса).
func TestRepo_REG04_ReCreateNameOverDeleting(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewRegistryRepo(pool)
	ctx := context.Background()

	r1 := newReg("prj-P", "team-images", nil)
	_, err := repo.Insert(ctx, r1, domain.RegisterIntentForCreate(r1, "user", "usr-alice"))
	require.NoError(t, err)

	// Пока ACTIVE — дубль запрещён.
	dup := newReg("prj-P", "team-images", nil)
	_, err = repo.Insert(ctx, dup, domain.RegisterIntentForCreate(dup, "user", "usr-alice"))
	require.ErrorIs(t, err, regerrors.ErrAlreadyExists)

	// Перевод в DELETING освобождает имя.
	_, err = repo.MarkDeleting(ctx, r1.ID)
	require.NoError(t, err)

	r2 := newReg("prj-P", "team-images", nil)
	_, err = repo.Insert(ctx, r2, domain.RegisterIntentForCreate(r2, "user", "usr-alice"))
	require.NoError(t, err, "name freed by DELETING → re-Create allowed")
}

// REG-06 — List: project-scope + cursor-пагинация (created_at,id) ASC + name-filter.
func TestRepo_REG06_ListPaginationFilter(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewRegistryRepo(pool)
	ctx := context.Background()

	// created_at выставляется явными возрастающими значениями (НЕ wall-clock sleep):
	// (created_at,id)-курсор детерминирован без зависимости от разрешения/монотонности
	// системных часов под нагрузкой CI (иначе два now() в одну микросекунду → ORDER BY
	// падает на random-ULID tiebreak и позиционный assert флапает).
	for i, name := range []string{"alpha", "bravo", "charlie"} {
		r := newReg("prj-P", name, nil)
		_, err := repo.Insert(ctx, r, domain.RegisterIntentForCreate(r, "user", "usr-alice"))
		require.NoError(t, err)
		_, err = pool.Exec(ctx,
			`UPDATE kacho_registry.registries SET created_at = $2 WHERE id = $1`,
			r.ID, time.Date(2026, 1, 1, 0, 0, i, 0, time.UTC))
		require.NoError(t, err)
	}
	// Чужой project не течёт.
	other := newReg("prj-Q", "delta", nil)
	_, err := repo.Insert(ctx, other, domain.RegisterIntentForCreate(other, "user", "usr-bob"))
	require.NoError(t, err)

	// Первая страница (size 2) → next-token.
	page1, next, err := repo.List(ctx, registry.ListQuery{ProjectID: "prj-P", PageSize: 2})
	require.NoError(t, err)
	require.Len(t, page1, 2)
	require.NotEmpty(t, next)

	page2, _, err := repo.List(ctx, registry.ListQuery{ProjectID: "prj-P", PageSize: 2, PageToken: next})
	require.NoError(t, err)
	require.Len(t, page2, 1)
	require.Equal(t, "charlie", page2[0].Name)

	// name-filter.
	filtered, _, err := repo.List(ctx, registry.ListQuery{ProjectID: "prj-P", Filter: `name="bravo"`})
	require.NoError(t, err)
	require.Len(t, filtered, 1)
	require.Equal(t, "bravo", filtered[0].Name)

	// garbage page_token → sentinel ErrInvalidArg (repo НЕ форматирует gRPC-статус —
	// маппинг sentinel→gRPC живёт в serviceerr; CLAUDE.md dependency rule).
	_, _, err = repo.List(ctx, registry.ListQuery{ProjectID: "prj-P", PageToken: "!!!garbage"})
	require.ErrorIs(t, err, regerrors.ErrInvalidArg)

	// garbage filter → sentinel ErrInvalidArg тоже (не gRPC-статус из repo).
	_, _, err = repo.List(ctx, registry.ListQuery{ProjectID: "prj-P", Filter: "name=="})
	require.ErrorIs(t, err, regerrors.ErrInvalidArg)
}

// REG-07/REG-40 — MarkDeleting CAS ACTIVE→DELETING (наблюдаемый статус) forward-only;
// Delete физически убирает строку + unregister-intent; Update на DELETING → NotFound.
func TestRepo_REG07_DeleteLifecycle_ForwardOnly(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewRegistryRepo(pool)
	ctx := context.Background()

	r := newReg("prj-P", "team-images", nil)
	_, err := repo.Insert(ctx, r, domain.RegisterIntentForCreate(r, "user", "usr-alice"))
	require.NoError(t, err)

	marked, err := repo.MarkDeleting(ctx, r.ID)
	require.NoError(t, err)
	require.Equal(t, domain.RegistryStatusDeleting, marked.Status)

	// forward-only: Update на DELETING-реестре не находит ACTIVE-строку → NotFound.
	_, err = repo.Update(ctx, registry.UpdateSpec{RegistryID: r.ID, ApplyDescription: true, Description: "x"},
		func(rr *domain.Registry) domain.RegisterIntent { return domain.RegisterIntentForUpdate(rr) })
	require.ErrorIs(t, err, regerrors.ErrNotFound)

	// idempotent forward-only: повторный MarkDeleting на DELETING возвращает строку.
	again, err := repo.MarkDeleting(ctx, r.ID)
	require.NoError(t, err)
	require.Equal(t, domain.RegistryStatusDeleting, again.Status)

	unreg := domain.UnregisterIntentForDelete(r.ID, r.ProjectID)
	require.NoError(t, repo.Delete(ctx, r.ID, unreg))
	require.Equal(t, 1, countOutbox(t, pool, r.ID, domain.FGAEventUnregister))

	_, err = repo.Get(ctx, r.ID)
	require.ErrorIs(t, err, regerrors.ErrNotFound)
}

// REG-31 — concurrent Create одинакового имени: ровно одна tx коммитит, остальные
// ловят 23505 → ErrAlreadyExists (partial UNIQUE race, не ловится unit-тестом).
func TestRepo_REG31_ConcurrentInsert_UniqueRace(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewRegistryRepo(pool)
	ctx := context.Background()

	const n = 8
	var wg sync.WaitGroup
	results := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r := newReg("prj-P", "team-images", nil) // distinct id, SAME (project,name)
			<-start
			_, results[i] = repo.Insert(ctx, r, domain.RegisterIntentForCreate(r, "user", "usr-alice"))
		}(i)
	}
	close(start)
	wg.Wait()

	success, dup := 0, 0
	for _, err := range results {
		switch {
		case err == nil:
			success++
		case errors.Is(err, regerrors.ErrAlreadyExists):
			dup++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	require.Equal(t, 1, success, "exactly one Create commits")
	require.Equal(t, n-1, dup, "the rest get ALREADY_EXISTS")
}

// REG-09 — concurrent Delete: ровно одна tx физически удаляет строку (и эмитит
// ровно один unregister-intent), остальные видят 0 rows → ErrNotFound (никогда 2×
// destructive unregister-дубля).
func TestRepo_REG09_ConcurrentDelete_ExactlyOnce(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewRegistryRepo(pool)
	ctx := context.Background()

	r := newReg("prj-P", "team-images", nil)
	_, err := repo.Insert(ctx, r, domain.RegisterIntentForCreate(r, "user", "usr-alice"))
	require.NoError(t, err)

	const n = 8
	var wg sync.WaitGroup
	results := make([]error, n)
	start := make(chan struct{})
	unreg := domain.UnregisterIntentForDelete(r.ID, r.ProjectID)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, _ = repo.MarkDeleting(ctx, r.ID) // idempotent forward-only
			results[i] = repo.Delete(ctx, r.ID, unreg)
		}(i)
	}
	close(start)
	wg.Wait()

	success := 0
	for _, err := range results {
		if err == nil {
			success++
		} else {
			require.ErrorIs(t, err, regerrors.ErrNotFound)
		}
	}
	require.Equal(t, 1, success, "exactly one physical delete")
	require.Equal(t, 1, countOutbox(t, pool, r.ID, domain.FGAEventUnregister), "exactly one unregister-intent")
}

// REG-36 — Update mutable-полей одним UPDATE RETURNING + mirror-intent с новыми
// labels; label-clear реально очищает метки в персисте.
func TestRepo_REG36_UpdateMutable_LabelClear(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewRegistryRepo(pool)
	ctx := context.Background()

	r := newReg("prj-P", "team-images", map[string]string{"env": "prod"})
	_, err := repo.Insert(ctx, r, domain.RegisterIntentForCreate(r, "user", "usr-alice"))
	require.NoError(t, err)

	// Смена labels + description.
	updated, err := repo.Update(ctx, registry.UpdateSpec{
		RegistryID: r.ID, ApplyLabels: true, Labels: map[string]string{"env": "staging", "team": "core"},
		ApplyDescription: true, Description: "staging CI",
	}, func(rr *domain.Registry) domain.RegisterIntent { return domain.RegisterIntentForUpdate(rr) })
	require.NoError(t, err)
	require.Equal(t, "staging CI", updated.Description)
	require.Equal(t, map[string]string{"env": "staging", "team": "core"}, updated.Labels)
	require.Equal(t, "team-images", updated.Name, "name immutable")

	// Mirror-intent записан (re-register с новыми labels).
	require.GreaterOrEqual(t, countOutbox(t, pool, r.ID, domain.FGAEventRegister), 2)

	// label-clear: пустая карта реально очищает метки (не no-op).
	cleared, err := repo.Update(ctx, registry.UpdateSpec{
		RegistryID: r.ID, ApplyLabels: true, Labels: map[string]string{},
	}, func(rr *domain.Registry) domain.RegisterIntent { return domain.RegisterIntentForUpdate(rr) })
	require.NoError(t, err)
	require.Empty(t, cleared.Labels, "label-clear actually clears (security invariant)")

	got, err := repo.Get(ctx, r.ID)
	require.NoError(t, err)
	require.Empty(t, got.Labels)
}

// REG-14/REG-25 — repo-tuple intent emit: RegisterRepository пишет fga.register-строку
// registry_repository (register-on-first-push), UnregisterRepository — fga.unregister
// (unregister-on-last-tag). У repo нет ресурсной строки (source of truth = zot) —
// проверяем только durable-emit в registry_outbox.
func TestRepo_REG14_RepoTupleIntent_Emit(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewRegistryRepo(pool)
	ctx := context.Background()

	regID := "regREPOTUPLE000000000"
	regIntent := domain.RegisterIntentForRepoPush(regID, "app", "prj-REPOTUPLE", "service_account:sva-ci")
	require.NoError(t, repo.RegisterRepository(ctx, regIntent))
	require.Equal(t, 1, countOutbox(t, pool, regID+"/app", domain.FGAEventRegister),
		"register-on-first-push emits one repo register-intent")

	unregIntent := domain.UnregisterIntentForRepo(regID, "app")
	require.NoError(t, repo.UnregisterRepository(ctx, unregIntent))
	require.Equal(t, 1, countOutbox(t, pool, regID+"/app", domain.FGAEventUnregister),
		"unregister-on-last-tag emits one repo unregister-intent")

	// Пустой tuple-набор → no-op (нечего регистрировать).
	require.NoError(t, repo.RegisterRepository(ctx, domain.RegisterIntent{Kind: "Repository", ResourceID: regID + "/empty"}))
	require.Equal(t, 0, countOutbox(t, pool, regID+"/empty", domain.FGAEventRegister))
}
