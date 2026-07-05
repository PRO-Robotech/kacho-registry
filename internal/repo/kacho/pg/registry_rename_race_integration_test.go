// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// registry_rename_race_integration_test.go — Update-rename onto an existing live
// name арбитрируется той же partial UNIQUE(project_id,name)WHERE status<>'DELETING',
// что и Create-dup: SQLSTATE 23505 → regerrors.ErrAlreadyExists на UPDATE-пути
// (не только на INSERT-пути). Покрывает project-rule #12 п.5 (concurrent-race на
// каждый спорный UNIQUE-путь). Finding: KAC sec-hardening 2026-07-05.
package pg_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	registry "github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/api/registry"
	"github.com/PRO-Robotech/kacho-registry/internal/domain"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
	kachopg "github.com/PRO-Robotech/kacho-registry/internal/repo/kacho/pg"
)

func renameSpec(id, name string) registry.UpdateSpec {
	return registry.UpdateSpec{RegistryID: id, ApplyName: true, Name: name}
}

func mirrorUpdate(rr *domain.Registry) domain.RegisterIntent { return domain.RegisterIntentForUpdate(rr) }

// TestRepo_RenameOntoExistingLiveName_AlreadyExists — Update B.name → A (живое имя
// того же project'а) даёт ErrAlreadyExists; B остаётся неизменным (rollback UPDATE).
func TestRepo_RenameOntoExistingLiveName_AlreadyExists(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewRegistryRepo(pool)
	ctx := context.Background()

	a := newReg("prj-P", "alpha", nil)
	_, err := repo.Insert(ctx, a, domain.RegisterIntentForCreate(a, "user", "usr-alice"))
	require.NoError(t, err)
	b := newReg("prj-P", "bravo", nil)
	_, err = repo.Insert(ctx, b, domain.RegisterIntentForCreate(b, "user", "usr-alice"))
	require.NoError(t, err)

	_, err = repo.Update(ctx, renameSpec(b.ID, "alpha"), mirrorUpdate)
	require.ErrorIs(t, err, regerrors.ErrAlreadyExists, "rename onto live name → ALREADY_EXISTS")

	got, err := repo.Get(ctx, b.ID)
	require.NoError(t, err)
	require.Equal(t, "bravo", got.Name, "failed rename leaves B unchanged")

	// Разные project'ы — то же имя не конфликтует при rename.
	c := newReg("prj-Q", "gamma", nil)
	_, err = repo.Insert(ctx, c, domain.RegisterIntentForCreate(c, "user", "usr-bob"))
	require.NoError(t, err)
	_, err = repo.Update(ctx, renameSpec(c.ID, "alpha"), mirrorUpdate)
	require.NoError(t, err, "rename onto same name in a DIFFERENT project is allowed")
}

// TestRepo_ConcurrentRenameToSameName_ExactlyOne — N реестров одновременно
// переименовываются в одно имя: ровно один коммитит, остальные ловят 23505 →
// ErrAlreadyExists (partial UNIQUE race на UPDATE-пути, не ловится unit-тестом).
func TestRepo_ConcurrentRenameToSameName_ExactlyOne(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewRegistryRepo(pool)
	ctx := context.Background()

	const n = 8
	ids := make([]string, n)
	for i := 0; i < n; i++ {
		r := newReg("prj-P", uniqueName(i), nil)
		_, err := repo.Insert(ctx, r, domain.RegisterIntentForCreate(r, "user", "usr-alice"))
		require.NoError(t, err)
		ids[i] = r.ID
	}

	var wg sync.WaitGroup
	results := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, results[i] = repo.Update(ctx, renameSpec(ids[i], "shared-name"), mirrorUpdate)
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
	require.Equal(t, 1, success, "exactly one rename commits")
	require.Equal(t, n-1, dup, "the rest get ALREADY_EXISTS")
}

func uniqueName(i int) string {
	return "reg-" + string(rune('a'+i))
}
