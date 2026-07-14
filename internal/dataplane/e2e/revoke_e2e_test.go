// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package e2e_test — end-to-end acceptance для REG-33 immediate-pull revoke-safety
// (#33): собирает РЕАЛЬНЫЙ dataplane.Handler поверх РЕАЛЬНОГО PushGrantRepo (testcontainers
// Postgres 16, миграция 0004) и РЕАЛЬНОГО HTTP reverse-proxy (dataplane.NewZotForwarder) в
// httptest-«zot». Прогоняет полный revoke-путь через настоящие OCI HTTP-запросы:
//
//	push (records push-grant) → immediate pull (v_get denied, свежий grant → 200) →
//	v_get материализуется (allow → forward + delete-on-materialized СНИМАЕТ grant в PG) →
//	REVOKE (v_get снова denied, grant уже удалён → 404).
//
// Изолирован в отдельном пакете, чтобы не тащить testcontainers в быстрый unit-пакет
// dataplane. Skips на -short.
package e2e_test

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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

	"github.com/PRO-Robotech/kacho-registry/internal/dataplane"
	"github.com/PRO-Robotech/kacho-registry/internal/migrations"
	kachopg "github.com/PRO-Robotech/kacho-registry/internal/repo/kacho/pg"
)

// ---- минимальные адаптеры под exported-порты dataplane ----------------------

// e2eVerifier — TokenVerifier, всегда возвращающий фиксированный subject.
type e2eVerifier struct{ subject string }

func (v e2eVerifier) Verify(context.Context, string) (string, error) { return v.subject, nil }

// e2eAuthz — Authorizer: push-authority (v_create/v_update) есть ВСЕГДА (толкать можно), а
// read-verb (v_get/v_list) переключается материализацией/ревоком — так один субъект и пушит,
// и попадает под материализацию/revoke именно по read-праву (как реальный FGA-lifecycle).
type e2eAuthz struct {
	mu       sync.Mutex
	vgetOpen bool // v_get/v_list материализован (true) / не материализован либо отозван (false)
}

func (a *e2eAuthz) Check(_ context.Context, _, relation, _ string) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch relation {
	case "v_create", "v_update":
		return true, nil // push-authority субъекта неизменна в сценарии
	case "v_get", "v_list":
		return a.vgetOpen, nil // материализация/revoke read-права
	default:
		return false, nil
	}
}

func (a *e2eAuthz) setVGet(open bool) {
	a.mu.Lock()
	a.vgetOpen = open
	a.mu.Unlock()
}

// e2eBackend — zot-интроспекция: repo «reg-A/app» существует (established), блоб входит в него.
type e2eBackend struct{}

func (e2eBackend) RepoExists(context.Context, string, string) (bool, error) { return true, nil }
func (e2eBackend) BlobInRepo(_ context.Context, _, _, digest string) (bool, error) {
	return digest == "sha256:layer", nil
}
func (e2eBackend) CatalogRepoNames(context.Context) ([]string, error) { return nil, nil }

// ---- testcontainers PG16 + миграции -----------------------------------------

func e2eSetupPG(t *testing.T) *pgxpool.Pool {
	t.Helper()
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

	const searchPath = "options=-c%20search_path%3Dkacho_registry%2Cpublic"
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	pool, err := coredb.NewPool(context.Background(), dsn+sep+searchPath)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

// bearerGet/bearerReq — OCI HTTP-запрос к handler с валидным Bearer.
func bearerReq(t *testing.T, h http.Handler, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	req.Header.Set("Authorization", "Bearer e2e.jwt.token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestE2E_REG33IP_RevokeSafety_RealHandlerRealPGRealForward — полный revoke-путь на реальном
// стеке handler+PG+HTTP-forward. Доказывает: (1) immediate-pull-after-push работает; (2) после
// материализации v_get (allow) delete-on-materialized снимает push-grant в реальном PG;
// (3) последующий REVOKE (v_get denied) → pull 404 — НЕТ 1h stale-bypass (был баг на проде).
func TestE2E_REG33IP_RevokeSafety_RealHandlerRealPGRealForward(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e integration test (testing.Short)")
	}
	pool := e2eSetupPG(t)
	const ttl = time.Minute // короткий 60s-мост (revoke-safe дефолт)
	pgRepo := kachopg.NewPushGrantRepo(pool, ttl)

	// РЕАЛЬНЫЙ HTTP reverse-proxy в httptest-«zot»: 201 на manifest-PUT, 200 на pull.
	var zotHits int
	var zotMu sync.Mutex
	zot := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		zotMu.Lock()
		zotHits++
		zotMu.Unlock()
		if r.Method == http.MethodPut || r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("payload"))
	}))
	defer zot.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	fwd, err := dataplane.NewZotForwarder(zot.URL, logger)
	require.NoError(t, err)

	az := &e2eAuthz{vgetOpen: false} // v_get ещё НЕ материализован (как сразу после push нового repo)
	h := dataplane.New(
		e2eVerifier{subject: "sva-ci"}, az, e2eBackend{}, fwd,
		nil, nil, nil, // repoReg/regLookup/uploads — не нужны для revoke-safety моста
		pgRepo,
		"https://api.kacho.local/iam/token", "registry.kacho.local", logger,
	)

	const fgaSubject = "service_account:sva-ci" // fgaSubject("sva-ci")
	ctx := context.Background()

	// ── шаг 1: PUSH manifest → 201, реальный push-grant записан в PG (detached-ctx, sync). ──
	require.Equal(t, http.StatusCreated,
		bearerReq(t, h, http.MethodPut, "/v2/reg-A/app/manifests/v1").Code)
	granted, err := pgRepo.PushGranted(ctx, "reg-A", "app", fgaSubject)
	require.NoError(t, err)
	require.True(t, granted, "push записал push-grant в реальный PG")
	t.Logf("STEP 1  push manifest → 201; push-grant recorded in PG (granted=%v)", granted)

	// ── шаг 2: IMMEDIATE PULL (v_get ещё DENIED, grant свежий) → 200 через мост. ──
	require.Equal(t, http.StatusOK,
		bearerReq(t, h, http.MethodGet, "/v2/reg-A/app/manifests/v1").Code,
		"immediate-pull-after-push раскрывается через push-grant (v_get не материализован)")
	t.Log("STEP 2  immediate pull (v_get DENIED, fresh grant) → 200  [immediate-pull works]")

	// ── шаг 3: v_get МАТЕРИАЛИЗУЕТСЯ (allow). Pull → 200 + delete-on-materialized снимает grant. ──
	az.setVGet(true)
	require.Equal(t, http.StatusOK,
		bearerReq(t, h, http.MethodGet, "/v2/reg-A/app/manifests/v1").Code,
		"после материализации v_get штатный forward")
	require.Eventually(t, func() bool {
		g, e := pgRepo.PushGranted(ctx, "reg-A", "app", fgaSubject)
		return e == nil && !g
	}, 3*time.Second, 20*time.Millisecond,
		"delete-on-materialized асинхронно снял push-grant из реального PG на v_get-allow pull")
	t.Log("STEP 3  v_get materialized (allow) → pull 200; delete-on-materialized removed grant from PG")

	// ── шаг 4: REVOKE (v_get снова DENIED). Grant удалён → pull ОБЯЗАН 404 (нет stale-bypass). ──
	az.setVGet(false)
	require.Equal(t, http.StatusNotFound,
		bearerReq(t, h, http.MethodGet, "/v2/reg-A/app/manifests/v1").Code,
		"после материализации+revoke: v_get denied, grant удалён → 404 (нет 1h bypass — прод-баг закрыт)")
	require.Equal(t, http.StatusNotFound,
		bearerReq(t, h, http.MethodGet, "/v2/reg-A/app/blobs/sha256:layer").Code,
		"blob того же repo тоже 404 после revoke (revoked субъект не тянет контент repo)")
	t.Log("STEP 4  REVOKE (v_get DENIED, grant deleted) → manifest pull 404, blob pull 404  [revoke ENFORCED]")

	// zot видел форварды только для push + двух authz-раскрытых pull (2), НЕ для 404-путей.
	zotMu.Lock()
	defer zotMu.Unlock()
	require.Equal(t, 3, zotHits, "zot получил push + immediate-pull + materialized-pull; revoked-pull'ы НЕ форвардились")
}
