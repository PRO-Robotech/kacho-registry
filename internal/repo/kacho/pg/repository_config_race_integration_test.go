// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Integration-тесты конкурентных гонок config-overlay Repository (RG-1) против
// реального Postgres 16 (testcontainers). Арбитр гонки — DB-инвариант (PRIMARY
// KEY(registry_id,name), single-statement re-key/visibility CAS), НЕ software
// check-then-act (ban #10). Такие гонки unit-тест не ловит — только testcontainers
// с release-barrier (закрытие канала — одновременный старт). Гонять под -race.
package pg_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	registry "github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/api/registry"
	"github.com/PRO-Robotech/kacho-registry/internal/domain"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
	kachopg "github.com/PRO-Robotech/kacho-registry/internal/repo/kacho/pg"
)

// RG-1-A04 — N конкурентных InsertConfig одного (registry_id, name): PRIMARY KEY —
// единственный арбитр. Ровно одна tx коммитит, остальные n-1 ловят 23505 →
// ErrAlreadyExists. В persist — ровно одна строка; никакого INTERNAL с pgx-leak.
func TestRepoConfig_RG1A04_ConcurrentCreate_PKRace(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewRepositoryConfigRepo(pool)
	ctx := context.Background()
	regID := seedRegistry(t, pool, "prj-P", "reg-a04")

	const n = 8
	var wg sync.WaitGroup
	var succeeded int64
	start := make(chan struct{})
	errs := make([]error, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := repo.InsertConfig(ctx, newCfg(regID, "svc/x", domain.VisibilityPrivate, nil))
			errs[i] = err
			if err == nil {
				atomic.AddInt64(&succeeded, 1)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	dup := 0
	for i, err := range errs {
		switch {
		case err == nil:
			// winner
		case errorsIs(err, regerrors.ErrAlreadyExists):
			dup++
		default:
			t.Fatalf("goroutine %d: unexpected error (ожидался ErrAlreadyExists): %v", i, err)
		}
	}
	require.Equal(t, int64(1), atomic.LoadInt64(&succeeded), "ровно одна конкурентная Create коммитит")
	require.Equal(t, n-1, dup, "остальные n-1 → ALREADY_EXISTS (PRIMARY KEY — арбитр)")
	require.Equal(t, 1, countConfigs(t, pool, regID, "svc/x"), "в persist ровно одна строка")
}

// RG-1-A18 — конкурентный rename двух разных исходников в ОДНО целевое имя: PK на
// целевом (registry_id, new_name) — арбитр. Ровно один RekeyConfig коммитит, другой
// → ErrAlreadyExists. dst/z соответствует ровно одному источнику; проигравший цел.
func TestRepoConfig_RG1A18_ConcurrentRename_PKRace(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewRepositoryConfigRepo(pool)
	ctx := context.Background()
	regID := seedRegistry(t, pool, "prj-P", "reg-a18")

	_, err := repo.InsertConfig(ctx, newCfg(regID, "src/a", domain.VisibilityPrivate, nil))
	require.NoError(t, err)
	_, err = repo.InsertConfig(ctx, newCfg(regID, "src/c", domain.VisibilityPrivate, nil))
	require.NoError(t, err)

	sources := []string{"src/a", "src/c"}
	var wg sync.WaitGroup
	var succeeded int64
	start := make(chan struct{})
	errs := make([]error, 2)

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, e := repo.RekeyConfig(ctx, regID, sources[i], "dst/z")
			errs[i] = e
			if e == nil {
				atomic.AddInt64(&succeeded, 1)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	dup := 0
	winner := -1
	for i, e := range errs {
		switch {
		case e == nil:
			winner = i
		case errorsIs(e, regerrors.ErrAlreadyExists):
			dup++
		default:
			t.Fatalf("rename %d: unexpected error (ожидался ErrAlreadyExists): %v", i, e)
		}
	}
	require.Equal(t, int64(1), atomic.LoadInt64(&succeeded), "ровно один rename коммитит")
	require.Equal(t, 1, dup, "второй → ALREADY_EXISTS (PK на целевом имени)")
	require.NotEqual(t, -1, winner)

	// dst/z существует ровно один; проигравший источник остался под своим именем.
	require.Equal(t, 1, countConfigs(t, pool, regID, "dst/z"), "целевое имя — ровно одна строка")
	loserSrc := sources[1-winner]
	require.Equal(t, 1, countConfigs(t, pool, regID, loserSrc), "проигравший остался под своим именем")
}

// RG-1-B09 — конкурентный visibility-flip: single-statement UPDATE ... RETURNING
// сериализуется row-lock'ом → терминальное состояние детерминировано (last-writer по
// commit-порядку), без потерянного/расщеплённого значения. Оба update'а успешны;
// финальное DB-значение — чистый член {PRIVATE,PUBLIC} и совпадает с RETURNING одного
// из writer'ов. Под -race фиксирует отсутствие data-race.
func TestRepoConfig_RG1B09_ConcurrentVisibilityFlip_CAS(t *testing.T) {
	pool := setupTestDB(t)
	repo := kachopg.NewRepositoryConfigRepo(pool)
	ctx := context.Background()
	regID := seedRegistry(t, pool, "prj-P", "reg-b09")

	_, err := repo.InsertConfig(ctx, newCfg(regID, "race/img", domain.VisibilityPrivate, nil))
	require.NoError(t, err)

	targets := []domain.Visibility{domain.VisibilityPublic, domain.VisibilityPrivate}
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make([]domain.Visibility, 2)
	errs := make([]error, 2)

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			got, e := repo.UpdateConfig(ctx, registry.RepositoryConfigUpdate{
				RegistryID: regID, Name: "race/img",
				Visibility: targets[i], ApplyVisibility: true,
			})
			errs[i] = e
			if e == nil {
				results[i] = got.Visibility
			}
		}(i)
	}
	close(start)
	wg.Wait()

	require.NoError(t, errs[0])
	require.NoError(t, errs[1], "оба flip'а успешны — нет lost-update ошибки")

	// Финальное DB-значение — единственное, чистое, из {PRIVATE,PUBLIC}, и совпадает с
	// RETURNING одного из writer'ов (нет torn/split state).
	var finalRaw string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT visibility FROM kacho_registry.repository_configs WHERE registry_id=$1 AND name=$2`,
		regID, "race/img").Scan(&finalRaw))
	require.Contains(t, []string{"PRIVATE", "PUBLIC"}, finalRaw, "терминал — чистый CHECK-домен")
	final := domain.VisibilityFromString(finalRaw)
	require.True(t, final == results[0] || final == results[1],
		"терминал совпадает с RETURNING одного из writer'ов (last-writer, без split)")
}

// errorsIs — локальный helper (require.ErrorIs требует *testing.T в горутине;
// в goroutine-цикле собираем ошибки и проверяем sentinel в основном потоке).
func errorsIs(err, target error) bool {
	for e := err; e != nil; {
		if e == target {
			return true
		}
		type wrapped interface{ Unwrap() error }
		w, ok := e.(wrapped)
		if !ok {
			return false
		}
		e = w.Unwrap()
	}
	return false
}
