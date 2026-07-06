// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// registry_repo_intent_lock_race_integration_test.go — repo-scoped register/unregister
// intent'ы (RegisterRepository / UnregisterRepository) НЕ имеют registries-строки для
// row-lock сериализации (source of truth репо = zot). Без явной сериализации две
// конкурентные register/unregister одного repo-объекта могут закоммититься в порядке,
// расходящемся с их BIGSERIAL id (source_version) → iam-mirror last-source-state-wins
// выберет не финально-закоммиченное состояние (dangling authz-объект / непуллимый repo).
// Фикс: pg_advisory_xact_lock(hashtext(resource_id)) в начале emitRepoIntent-tx —
// concurrent register/unregister ОДНОГО repo-объекта сериализуются (второй ждёт commit
// первого → получает больший id), а РАЗНЫЕ repo-объекты не блокируют друг друга.
package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-registry/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho-registry/internal/repo/kacho/pg"
)

// TestRepo_RepoIntent_SerializesOnPerRepoAdvisoryLock — emitRepoIntent обязан брать
// per-repo advisory-xact-lock: пока внешняя tx держит pg_advisory_xact_lock(hashtext(K))
// того же repo-объекта, RegisterRepository(K) блокируется; register ДРУГОГО repo-объекта
// проходит без блокировки; после release внешней tx заблокированный вызов завершается.
func TestRepo_RepoIntent_SerializesOnPerRepoAdvisoryLock(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewRegistryRepo(pool)
	ctx := context.Background()

	const regID = "regX000000000000000"
	sameIntent := domain.RegisterIntentForRepoPush(regID, "app", "prj-P", "service_account:sva-ci")
	otherIntent := domain.RegisterIntentForRepoPush(regID, "other", "prj-P", "service_account:sva-ci")

	// Внешняя tx удерживает advisory-xact-lock того же repo-объекта, что и sameIntent,
	// имитируя in-flight emitRepoIntent, который ещё не закоммитился.
	holder, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = holder.Rollback(ctx) }()
	_, err = holder.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, sameIntent.ResourceID)
	require.NoError(t, err)

	// Register ДРУГОГО repo-объекта не должен блокироваться удержанным lock'ом (per-object).
	otherDone := make(chan error, 1)
	go func() { otherDone <- repo.RegisterRepository(ctx, otherIntent) }()
	select {
	case oerr := <-otherDone:
		require.NoError(t, oerr, "register другого repo-объекта проходит без блокировки")
	case <-time.After(3 * time.Second):
		t.Fatal("register другого repo-объекта заблокировался — advisory-lock должен быть per-object, не глобальным")
	}

	// Register ТОГО ЖЕ repo-объекта обязан заблокироваться, пока внешняя tx держит lock.
	sameDone := make(chan error, 1)
	go func() { sameDone <- repo.RegisterRepository(ctx, sameIntent) }()
	select {
	case <-sameDone:
		t.Fatal("register того же repo-объекта завершился, пока advisory-lock удерживается — сериализации нет")
	case <-time.After(500 * time.Millisecond):
		// ожидаемо: заблокирован на per-repo advisory-lock.
	}

	// Release внешней tx → заблокированный register завершается.
	require.NoError(t, holder.Rollback(ctx))
	select {
	case serr := <-sameDone:
		require.NoError(t, serr, "после release lock register того же repo завершается")
	case <-time.After(3 * time.Second):
		t.Fatal("register не разблокировался после release advisory-lock")
	}
}
