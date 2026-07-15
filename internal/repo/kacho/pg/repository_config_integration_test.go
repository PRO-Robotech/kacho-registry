// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Integration-тесты config-overlay Repository (таблица repository_configs, RG-1)
// против реального Postgres 16 (testcontainers) с применённой миграцией 0005.
// Проверяют DB-инварианты overlay (PRIMARY KEY(registry_id,name), visibility CHECK,
// single-statement re-key rename, FK ON DELETE CASCADE) + маппинг SQLSTATE→sentinel
// с точными контракт-текстами (behaviour-level, testing.md §Regression-lock).
// Имена трассируются к acceptance-сценариям RG-1-<Group><NN>.
package pg_test

import (
	"context"
	"testing"
	"time"

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

// seedRegistry вставляет parent-реестр (FK target repository_configs.registry_id) и
// возвращает его id.
func seedRegistry(t *testing.T, pool *pgxpool.Pool, project, name string) string {
	t.Helper()
	repo := kachopg.NewRegistryRepo(pool)
	reg := newReg(project, name, nil)
	created, err := repo.Insert(context.Background(), reg,
		domain.RegisterIntentForCreate(reg, "user", "usr-seed"))
	require.NoError(t, err)
	return created.ID
}

func newCfg(regID, name string, vis domain.Visibility, labels map[string]string) *domain.RepositoryConfig {
	return &domain.RepositoryConfig{
		RegistryID:  regID,
		Name:        name,
		Description: "",
		Labels:      labels,
		Visibility:  vis,
	}
}

// RG-1-A01/A07 — InsertConfig durable-empty overlay → Get round-trip: description/
// labels/visibility/createdAt сохранены; PRIVATE-дефолт; created_at заполнен.
func TestRepoConfig_RG1A01_InsertGetRoundTrip(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewRepositoryConfigRepo(pool)
	ctx := context.Background()

	regID := seedRegistry(t, pool, "prj-P", "reg-a01")
	cfg := &domain.RepositoryConfig{
		RegistryID:  regID,
		Name:        "backend/api",
		Description: "api service images",
		Labels:      map[string]string{"team": "core"},
		Visibility:  domain.VisibilityPrivate,
	}
	before := time.Now().Add(-time.Second)
	got, err := repo.InsertConfig(ctx, cfg)
	require.NoError(t, err)
	require.Equal(t, regID, got.RegistryID)
	require.Equal(t, "backend/api", got.Name)
	require.Equal(t, "api service images", got.Description)
	require.Equal(t, map[string]string{"team": "core"}, got.Labels)
	require.Equal(t, domain.VisibilityPrivate, got.Visibility)
	require.False(t, got.CreatedAt.IsZero(), "created_at заполнен")
	require.True(t, got.CreatedAt.After(before), "created_at свежий")

	// Get по натуральному ключу отдаёт ту же durable-строку (пережила пустоту).
	fetched, err := repo.GetConfig(ctx, regID, "backend/api")
	require.NoError(t, err)
	require.Equal(t, got.Name, fetched.Name)
	require.Equal(t, got.Description, fetched.Description)
	require.Equal(t, got.Labels, fetched.Labels)
	require.Equal(t, domain.VisibilityPrivate, fetched.Visibility)
}

// RG-1-A02 — дубликат overlay (тот же registry_id, name) → PRIMARY KEY 23505 →
// ErrAlreadyExists; behaviour-level: код AlreadyExists + текст "repository already exists".
func TestRepoConfig_RG1A02_DuplicateInsert_AlreadyExists(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewRepositoryConfigRepo(pool)
	ctx := context.Background()
	regID := seedRegistry(t, pool, "prj-P", "reg-a02")

	_, err := repo.InsertConfig(ctx, newCfg(regID, "backend/api", domain.VisibilityPrivate, nil))
	require.NoError(t, err)

	_, err = repo.InsertConfig(ctx, newCfg(regID, "backend/api", domain.VisibilityPrivate, nil))
	require.Error(t, err)
	require.ErrorIs(t, err, regerrors.ErrAlreadyExists)

	st := status.Convert(serviceerr.ToStatus(err))
	require.Equal(t, codes.AlreadyExists, st.Code())
	require.Equal(t, "repository already exists", st.Message(), "точный контракт-текст (A02)")

	// Ровно одна строка (registry_id, name).
	require.Equal(t, 1, countConfigs(t, pool, regID, "backend/api"))
}

// RG-1 — InsertConfig с несуществующим registry_id → FK 23503 → ErrFailedPrecondition
// (реестр отсутствует). NotFound-семантика существования реестра обеспечена FK.
func TestRepoConfig_InsertMissingRegistry_FK_FailedPrecondition(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewRepositoryConfigRepo(pool)
	ctx := context.Background()

	_, err := repo.InsertConfig(ctx, newCfg("regNONEXISTENT", "backend/api", domain.VisibilityPrivate, nil))
	require.Error(t, err)
	require.ErrorIs(t, err, regerrors.ErrFailedPrecondition, "FK 23503 → FailedPrecondition")
	// Никакого leak'а сырого pgx-текста.
	st := status.Convert(serviceerr.ToStatus(err))
	require.Equal(t, codes.FailedPrecondition, st.Code())
	require.NotContains(t, st.Message(), "SQLSTATE")
	require.NotContains(t, st.Message(), "foreign key")
}

// RG-1-D6 — visibility PUBLIC round-trip; DB CHECK-домен {PRIVATE,PUBLIC} закреплён
// миграцией (raw-INSERT недопустимого значения → 23514).
func TestRepoConfig_RG1D6_VisibilityCheckDomain(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewRepositoryConfigRepo(pool)
	ctx := context.Background()
	regID := seedRegistry(t, pool, "prj-P", "reg-vis")

	pub, err := repo.InsertConfig(ctx, newCfg(regID, "public/img", domain.VisibilityPublic, nil))
	require.NoError(t, err)
	require.Equal(t, domain.VisibilityPublic, pub.Visibility)
	got, err := repo.GetConfig(ctx, regID, "public/img")
	require.NoError(t, err)
	require.Equal(t, domain.VisibilityPublic, got.Visibility)

	// DB CHECK: прямой INSERT недопустимого visibility → 23514 (миграция-инвариант).
	_, rawErr := pool.Exec(ctx,
		`INSERT INTO kacho_registry.repository_configs (registry_id, name, visibility) VALUES ($1,$2,$3)`,
		regID, "bad/vis", "WORLD-READABLE")
	require.Error(t, rawErr, "visibility CHECK отвергает значение вне {PRIVATE,PUBLIC}")
	require.Contains(t, rawErr.Error(), "23514", "check_violation")
}

// RG-1-A16 — durable rename: RekeyConfig переносит name-колонку одним UPDATE;
// Get(new) OK, Get(old) → NotFound "repository not found".
func TestRepoConfig_RG1A16_RenameRekey(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewRepositoryConfigRepo(pool)
	ctx := context.Background()
	regID := seedRegistry(t, pool, "prj-P", "reg-a16")

	_, err := repo.InsertConfig(ctx, newCfg(regID, "old/name", domain.VisibilityPrivate,
		map[string]string{"k": "v"}))
	require.NoError(t, err)

	renamed, err := repo.RekeyConfig(ctx, regID, "old/name", "new/name")
	require.NoError(t, err)
	require.Equal(t, "new/name", renamed.Name)
	require.Equal(t, map[string]string{"k": "v"}, renamed.Labels, "config переезжает с именем")

	_, err = repo.GetConfig(ctx, regID, "new/name")
	require.NoError(t, err)

	_, err = repo.GetConfig(ctx, regID, "old/name")
	require.ErrorIs(t, err, regerrors.ErrNotFound)
	st := status.Convert(serviceerr.ToStatus(err))
	require.Equal(t, codes.NotFound, st.Code())
	require.Equal(t, "repository not found", st.Message())
}

// RG-1-A17 — rename в занятое overlay-имя → PK 23505 → ErrAlreadyExists; исходник цел.
func TestRepoConfig_RG1A17_RenameCollision_AlreadyExists(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewRepositoryConfigRepo(pool)
	ctx := context.Background()
	regID := seedRegistry(t, pool, "prj-P", "reg-a17")

	_, err := repo.InsertConfig(ctx, newCfg(regID, "src/a", domain.VisibilityPrivate, nil))
	require.NoError(t, err)
	_, err = repo.InsertConfig(ctx, newCfg(regID, "dst/b", domain.VisibilityPrivate, nil))
	require.NoError(t, err)

	_, err = repo.RekeyConfig(ctx, regID, "src/a", "dst/b")
	require.ErrorIs(t, err, regerrors.ErrAlreadyExists)
	st := status.Convert(serviceerr.ToStatus(err))
	require.Equal(t, codes.AlreadyExists, st.Code())
	require.Equal(t, "repository already exists", st.Message())

	// src/a остался под старым именем без изменений.
	still, err := repo.GetConfig(ctx, regID, "src/a")
	require.NoError(t, err)
	require.Equal(t, "src/a", still.Name)
}

// RG-1 — RekeyConfig несуществующего исходника → NotFound.
func TestRepoConfig_RenameMissingSource_NotFound(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewRepositoryConfigRepo(pool)
	ctx := context.Background()
	regID := seedRegistry(t, pool, "prj-P", "reg-rns")

	_, err := repo.RekeyConfig(ctx, regID, "ghost/x", "new/y")
	require.ErrorIs(t, err, regerrors.ErrNotFound)
}

// RG-1-A09/B01 — UpdateConfig mask-driven: description/labels/visibility применяются
// раздельно по Apply-флагам (single-statement UPDATE); нетронутые поля сохранены.
func TestRepoConfig_RG1A09_UpdateMaskDriven(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewRepositoryConfigRepo(pool)
	ctx := context.Background()
	regID := seedRegistry(t, pool, "prj-P", "reg-upd")

	_, err := repo.InsertConfig(ctx, &domain.RepositoryConfig{
		RegistryID: regID, Name: "backend/api", Description: "v1",
		Labels: map[string]string{"team": "core"}, Visibility: domain.VisibilityPrivate,
	})
	require.NoError(t, err)

	// description+labels (без visibility) — visibility не тронут.
	upd, err := repo.UpdateConfig(ctx, registry.RepositoryConfigUpdate{
		RegistryID: regID, Name: "backend/api",
		Description: "api images v2", ApplyDescription: true,
		Labels: map[string]string{"team": "core", "tier": "gold"}, ApplyLabels: true,
	})
	require.NoError(t, err)
	require.Equal(t, "api images v2", upd.Description)
	require.Equal(t, map[string]string{"team": "core", "tier": "gold"}, upd.Labels)
	require.Equal(t, domain.VisibilityPrivate, upd.Visibility, "visibility не в mask — не тронут")

	// только visibility → PUBLIC (single-statement CAS), description/labels сохранены.
	flip, err := repo.UpdateConfig(ctx, registry.RepositoryConfigUpdate{
		RegistryID: regID, Name: "backend/api",
		Visibility: domain.VisibilityPublic, ApplyVisibility: true,
	})
	require.NoError(t, err)
	require.Equal(t, domain.VisibilityPublic, flip.Visibility)
	require.Equal(t, "api images v2", flip.Description, "description сохранён при visibility-flip")

	// UpdateConfig несуществующего repo → NotFound.
	_, err = repo.UpdateConfig(ctx, registry.RepositoryConfigUpdate{
		RegistryID: regID, Name: "ghost/x", Description: "x", ApplyDescription: true,
	})
	require.ErrorIs(t, err, regerrors.ErrNotFound)
}

// RG-1-A13 — DeleteConfig снимает overlay-строку → Get NotFound; повторный/absent
// Delete → NotFound (0 rows).
func TestRepoConfig_RG1A13_DeleteConfig(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewRepositoryConfigRepo(pool)
	ctx := context.Background()
	regID := seedRegistry(t, pool, "prj-P", "reg-del")

	_, err := repo.InsertConfig(ctx, newCfg(regID, "backend/api", domain.VisibilityPrivate, nil))
	require.NoError(t, err)

	require.NoError(t, repo.DeleteConfig(ctx, regID, "backend/api"))
	_, err = repo.GetConfig(ctx, regID, "backend/api")
	require.ErrorIs(t, err, regerrors.ErrNotFound)

	// Повторный delete → NotFound (single-statement DELETE RETURNING 0 rows).
	require.ErrorIs(t, repo.DeleteConfig(ctx, regID, "backend/api"), regerrors.ErrNotFound)
}

// RG-1-D4-adjacent — FK ON DELETE CASCADE: удаление parent-реестра сносит его overlay
// (SAME-DB cascade, ban #4 — обе таблицы в схеме kacho_registry).
func TestRepoConfig_FKCascadeOnRegistryDelete(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewRepositoryConfigRepo(pool)
	ctx := context.Background()
	regID := seedRegistry(t, pool, "prj-P", "reg-cascade")

	_, err := repo.InsertConfig(ctx, newCfg(regID, "a/b", domain.VisibilityPrivate, nil))
	require.NoError(t, err)
	_, err = repo.InsertConfig(ctx, newCfg(regID, "c/d", domain.VisibilityPublic, nil))
	require.NoError(t, err)

	// Физически удаляем реестр (registry Delete) — overlay-строки должны cascade-исчезнуть.
	regRepo := kachopg.NewRegistryRepo(pool)
	require.NoError(t, regRepo.Delete(ctx, regID, domain.RegisterIntent{}))

	require.Equal(t, 0, countConfigs(t, pool, regID, "a/b"), "overlay cascade-снят с реестром")
	require.Equal(t, 0, countConfigs(t, pool, regID, "c/d"))
}

// RG-1-A20 (overlay-сторона) — ListConfigs возвращает overlay-строки реестра
// (created_at, name) ASC; durable-empty присутствуют (пережили пустоту).
func TestRepoConfig_RG1A20_ListConfigs(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewRepositoryConfigRepo(pool)
	ctx := context.Background()
	regID := seedRegistry(t, pool, "prj-P", "reg-list")

	for _, n := range []string{"cfg/only", "hidden/svc", "zzz/last"} {
		_, err := repo.InsertConfig(ctx, newCfg(regID, n, domain.VisibilityPrivate, nil))
		require.NoError(t, err)
	}
	list, err := repo.ListConfigs(ctx, regID)
	require.NoError(t, err)
	require.Len(t, list, 3, "все durable-строки (включая пустые) присутствуют")
	names := map[string]bool{}
	for _, c := range list {
		names[c.Name] = true
	}
	require.True(t, names["cfg/only"] && names["hidden/svc"] && names["zzz/last"])

	// Другой реестр не течёт в выборку.
	other := seedRegistry(t, pool, "prj-Q", "reg-other")
	empty, err := repo.ListConfigs(ctx, other)
	require.NoError(t, err)
	require.Empty(t, empty)
}

// countConfigs считает строки repository_configs по (registry_id, name).
func countConfigs(t *testing.T, pool *pgxpool.Pool, regID, name string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM kacho_registry.repository_configs WHERE registry_id=$1 AND name=$2`,
		regID, name).Scan(&n))
	return n
}
