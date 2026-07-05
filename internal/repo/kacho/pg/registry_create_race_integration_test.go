// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Integration-тест конкурентной гонки Create по инварианту partial
// UNIQUE(project_id,name) WHERE status<>'DELETING': N goroutines вставляют реестр
// с ОДИНАКОВЫМИ (project_id, name); арбитр гонки — DB, ровно одна tx коммитит,
// остальные получают 23505 → ErrAlreadyExists (exactly-one-wins, а не software
// check-then-act). Такую гонку unit-тест не ловит — только testcontainers Postgres.
package pg_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-registry/internal/domain"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
	kachopg "github.com/PRO-Robotech/kacho-registry/internal/repo/kacho/pg"
)

// REG-04 — concurrent Create одинакового (project_id, name): N goroutines
// одновременно (release-barrier через закрытие канала) стартуют Insert с distinct
// id, но SAME (project_id, name). partial UNIQUE(project_id,name)WHERE
// status<>'DELETING' — единственный арбитр: ровно одна tx коммитит, остальные n-1
// ловят 23505 → ErrAlreadyExists. Проигравшие откатываются целиком — ни строки в
// registries, ни orphan register-intent в outbox.
func TestRegistry_REG04_ConcurrentCreate_UniqueNameRace(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewRegistryRepo(pool)
	ctx := context.Background()

	const (
		n       = 8
		project = "prj-P"
		name    = "team-images"
	)

	var wg sync.WaitGroup
	var succeeded int64 // atomic-счётчик выигравших Insert
	start := make(chan struct{})
	errs := make([]error, n)
	ids := make([]string, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// distinct id, НАМЕРЕННО одинаковые (project_id, name) — конфликт решает DB.
			reg := newReg(project, name, nil)
			ids[i] = reg.ID
			<-start // одновременный старт: максимизируем окно гонки
			_, err := repo.Insert(ctx, reg, domain.RegisterIntentForCreate(reg, "user", "usr-alice"))
			errs[i] = err
			if err == nil {
				atomic.AddInt64(&succeeded, 1)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	// Ровно одна tx коммитит; остальные — ErrAlreadyExists (маппинг 23505). Любая
	// другая ошибка (например ErrInternal) — сигнал, что арбитром выступил не индекс.
	winner, dup := -1, 0
	for i, err := range errs {
		switch {
		case err == nil:
			winner = i
		case errors.Is(err, regerrors.ErrAlreadyExists):
			dup++
		default:
			t.Fatalf("goroutine %d: unexpected error (ожидался ErrAlreadyExists): %v", i, err)
		}
	}
	require.Equal(t, int64(1), atomic.LoadInt64(&succeeded), "ровно одна конкурентная Create коммитит")
	require.NotEqual(t, -1, winner, "должен быть ровно один победитель")
	require.Equal(t, n-1, dup, "остальные n-1 получают ALREADY_EXISTS (partial UNIQUE — арбитр)")

	// DB-арбитр: в таблице ровно одна строка для (project_id, name).
	var rows int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_registry.registries WHERE project_id=$1 AND name=$2`,
		project, name).Scan(&rows))
	require.Equal(t, 1, rows, "в persist ровно одна строка (project_id, name)")

	// Победитель эмитит ровно один register-intent в ТОЙ ЖЕ writer-tx; проигравшие
	// откатываются целиком — их outbox-строк нет (нет orphan-intent).
	require.Equal(t, 1, countOutbox(t, pool, ids[winner], domain.FGAEventRegister),
		"winner: ровно один register-intent")
	for i, id := range ids {
		if i == winner {
			continue
		}
		require.Equal(t, 0, countOutbox(t, pool, id, domain.FGAEventRegister),
			"loser: rollback — нет orphan register-intent")
	}
}
