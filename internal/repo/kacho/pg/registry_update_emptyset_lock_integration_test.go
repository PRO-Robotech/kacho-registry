// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// registry_update_emptyset_lock_integration_test.go — ветка Update с пустым набором
// применяемых полей (все Apply* == false) обязана брать row-lock (SELECT ... FOR UPDATE),
// а не unlocked MVCC-SELECT: иначе её outbox-INSERT (source_version = BIGSERIAL id) мог бы
// получить больший id при stale-снапшоте labels конкурентного реального UPDATE → mirror
// last-source-state-wins откатил бы label-scope.
package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	registry "github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/api/registry"
	"github.com/PRO-Robotech/kacho-registry/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho-registry/internal/repo/kacho/pg"
)

// TestRepo_UpdateEmptySet_LocksMirroredRow — Update с пустым Apply-набором блокируется,
// пока строка реестра залочена конкурентной tx (FOR UPDATE), и завершается после release.
func TestRepo_UpdateEmptySet_LocksMirroredRow(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewRegistryRepo(pool)
	ctx := context.Background()

	r := newReg("prj-P", "team-images", map[string]string{"env": "prod"})
	_, err := repo.Insert(ctx, r, domain.RegisterIntentForCreate(r, "user", "usr-alice"))
	require.NoError(t, err)

	// Внешняя tx удерживает row-lock реестра (как конкурентный реальный UPDATE).
	holder, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = holder.Rollback(ctx) }()
	_, err = holder.Exec(ctx,
		`SELECT id FROM kacho_registry.registries WHERE id=$1 AND status='ACTIVE' FOR UPDATE`, r.ID)
	require.NoError(t, err)

	// Update с ПУСТЫМ Apply-набором (mask без mutable-полей) обязан блокироваться на
	// row-lock той же строки, которую он зеркалит.
	done := make(chan error, 1)
	go func() {
		_, uerr := repo.Update(ctx,
			registry.UpdateSpec{RegistryID: r.ID}, // все Apply* == false → empty-set ветка
			func(rr *domain.Registry) domain.RegisterIntent { return domain.RegisterIntentForUpdate(rr) })
		done <- uerr
	}()
	select {
	case <-done:
		t.Fatal("empty-set Update завершился, пока строка залочена — ветка читает без FOR UPDATE (foot-gun)")
	case <-time.After(500 * time.Millisecond):
		// ожидаемо: заблокирован на row-lock.
	}

	require.NoError(t, holder.Rollback(ctx))
	select {
	case uerr := <-done:
		require.NoError(t, uerr, "после release row-lock empty-set Update завершается")
	case <-time.After(3 * time.Second):
		t.Fatal("empty-set Update не разблокировался после release row-lock")
	}
}
