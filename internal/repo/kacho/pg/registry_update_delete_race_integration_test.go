// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// registry_update_delete_race_integration_test.go — cross-mutation contested-row race:
// конкурентный Update (guarded `UPDATE ... WHERE status='ACTIVE'`) против
// MarkDeleting (CAS ACTIVE→DELETING) + Delete на ОДНОЙ строке. Инвариант DB-уровня:
// row-lock сериализует, поэтому Update, увидевший уже-DELETING (или удалённую) строку,
// получает 0 rows → ErrNotFound — НИКОГДА не «воскрешает» удаляемый реестр и никогда
// не коммитит Update против DELETING/absent строки. Покрывает project-rule #10/#12
// (contested CAS/status-transition путь требует concurrent-goroutine теста).
// Finding: KAC sec-hardening-r4 2026-07-05.
package pg_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	registry "github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/api/registry"
	"github.com/PRO-Robotech/kacho-registry/internal/domain"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
	kachopg "github.com/PRO-Robotech/kacho-registry/internal/repo/kacho/pg"
)

// REG-40 — concurrent Update vs MarkDeleting+Delete на одной ACTIVE-строке. N goroutines
// под release-barrier: половина шлёт Update(labels), половина MarkDeleting→Delete.
// Детерминированные исходы (независимо от interleaving):
//   - каждый Update = либо success (строка была ACTIVE и вернулась со Status=ACTIVE),
//     либо ErrNotFound (строка уже DELETING/удалена) — НИКОГДА другой ошибки и НИКОГДА
//     success с не-ACTIVE строкой (это ловит регресс: снятие предиката status='ACTIVE'
//     из UPDATE ... WHERE → «воскрешение» labels удаляемого реестра / lost-update);
//   - ровно один физический Delete → ровно один unregister-intent;
//   - финально строки нет (Update не может её воскресить — UPDATE не INSERT).
func TestRepo_REG40_ConcurrentUpdateVsDelete_ContestedRow(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewRegistryRepo(pool)
	ctx := context.Background()

	r := newReg("prj-P", "team-images", nil)
	_, err := repo.Insert(ctx, r, domain.RegisterIntentForCreate(r, "user", "usr-alice"))
	require.NoError(t, err)

	const n = 8 // чётное: половина Update, половина Delete
	var wg sync.WaitGroup
	var deleteSuccess int64
	updErrs := make([]error, n)
	updRows := make([]*domain.Registry, n)
	start := make(chan struct{})
	unreg := domain.UnregisterIntentForDelete(r.ID, r.ProjectID)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // одновременный старт: максимизируем окно контеста
			if i%2 == 0 {
				// Update mutable labels — guarded WHERE status='ACTIVE'.
				updRows[i], updErrs[i] = repo.Update(ctx,
					registry.UpdateSpec{RegistryID: r.ID, ApplyLabels: true, Labels: map[string]string{"env": "prod"}},
					mirrorUpdate)
			} else {
				_, _ = repo.MarkDeleting(ctx, r.ID) // idempotent forward-only CAS
				if derr := repo.Delete(ctx, r.ID, unreg); derr == nil {
					atomic.AddInt64(&deleteSuccess, 1)
				}
			}
		}(i)
	}
	close(start)
	wg.Wait()

	// Update-исходы: только nil | ErrNotFound; success обязан вернуть ACTIVE-строку.
	for i := 0; i < n; i += 2 {
		switch {
		case updErrs[i] == nil:
			require.NotNil(t, updRows[i], "successful Update must return a row")
			require.Equal(t, domain.RegistryStatusActive, updRows[i].Status,
				"a committed Update must have observed an ACTIVE row — never a DELETING one (no resurrect/lost-update)")
		case errors.Is(updErrs[i], regerrors.ErrNotFound):
			// строка уже DELETING/удалена — корректный 0-rows исход.
		default:
			t.Fatalf("Update goroutine %d: unexpected error (want nil|ErrNotFound): %v", i, updErrs[i])
		}
	}

	// Ровно один физический Delete → ровно один unregister-intent (никогда 2× destructive).
	require.Equal(t, int64(1), atomic.LoadInt64(&deleteSuccess), "exactly one physical delete commits")
	require.Equal(t, 1, countOutbox(t, pool, r.ID, domain.FGAEventUnregister), "exactly one unregister-intent")

	// Финально строки нет — Update не воскресил удаляемый реестр.
	_, gerr := repo.Get(ctx, r.ID)
	require.ErrorIs(t, gerr, regerrors.ErrNotFound, "contested row is gone; no Update resurrected it")
}
