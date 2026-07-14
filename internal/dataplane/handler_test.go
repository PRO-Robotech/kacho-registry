// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// cancelingForwarder эмулирует single-shot docker/CI push, рвущий соединение сразу
// за ответом: пишет статус и ОТМЕНЯЕТ request-контекст (клиент закрыл connection на
// 201). Регресс-инструмент REG-14e: register-on-first-push обязан пережить эту отмену.
type cancelingForwarder struct {
	status int
	cancel context.CancelFunc
	calls  int
}

func (f *cancelingForwarder) Forward(w http.ResponseWriter, r *http.Request) int {
	f.calls++
	st := f.status
	if st == 0 {
		st = http.StatusOK
	}
	w.WriteHeader(st)
	if f.cancel != nil {
		f.cancel() // клиент закрыл соединение сразу за ответом → r.Context() отменён
	}
	return st
}

// REG-14e — register-on-first-push исполняется на пути ответа ПОСЛЕ Forward. Если
// клиент (single-shot docker/CI push) закрывает соединение сразу за 201, r.Context()
// отменяется. Durable outbox-write owner/parent FGA-tuple и project-lookup ОБЯЗАНЫ
// пережить эту отмену (detached ctx), иначе tuple теряется без ретрая (drainer
// реплеит только закоммиченные строки) → репо непуллим даже владельцем. Регресс-гейт:
// intent эмитится, project резолвится, а наблюдённый в момент emit ctx НЕ отменён.
func TestDataplane_REG14e_PushNewRepo_ClientDisconnectAfterForward_StillRegisters(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_create registry_registry:reg-A": true}}
	be := &fakeBackend{exists: map[string]bool{}}
	rr := &fakeRepoReg{}
	lk := &fakeRegistryLookup{projectByRegistry: map[string]string{"reg-A": "prj-owner"}}
	cf := &cancelingForwarder{status: 201}
	h := newTestHandlerLK(&fakeVerifier{subject: "sva-ci"}, az, be, cf, rr, lk)

	// upload-init (обычный запрос) — repo ещё не существует.
	up := doReq(h, http.MethodPost, "/v2/reg-A/app/blobs/uploads/", true)
	require.Equal(t, 201, up.Code)

	// manifest-PUT с отменяемым контекстом; forwarder отменяет его сразу за 201.
	ctx, cancel := context.WithCancel(context.Background())
	cf.cancel = cancel
	req := httptest.NewRequest(http.MethodPut, "/v2/reg-A/app/manifests/v1", nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer dummy.jwt.token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, 201, rec.Code)

	intents := rr.registered()
	require.Len(t, intents, 1, "register-intent эмитится несмотря на разрыв соединения клиентом")
	require.Equal(t, "prj-owner", intents[0].ParentProjectID,
		"project резолвится на detached-контексте (не теряется при отмене запроса)")
	require.NoError(t, rr.observedCtxErr(),
		"durable-emit исполняется на detached-контексте — отмена запроса не дотягивается до outbox-write")
}

// doReq прогоняет запрос через Handler и возвращает записанный ответ.
func doReq(h *Handler, method, target string, bearer bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	if bearer {
		req.Header.Set("Authorization", "Bearer dummy.jwt.token")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// REG-10 — GET /v2/ без токена → 401 + WWW-Authenticate: Bearer realm=...,service=...
func TestDataplane_REG10_PingNoToken_401Challenge(t *testing.T) {
	h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, &fakeAuthz{}, &fakeBackend{}, &fakeForwarder{}, &fakeRepoReg{})
	rec := doReq(h, http.MethodGet, "/v2/", false)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	wa := rec.Header().Get("WWW-Authenticate")
	require.Contains(t, wa, `realm="https://api.kacho.local/iam/token"`)
	require.Contains(t, wa, `service="registry.kacho.local"`)
}

// REG-10 — любой /v2/ путь без токена → 401 (fail-closed, не 2xx).
func TestDataplane_REG10_AnyPathNoToken_401(t *testing.T) {
	h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, &fakeAuthz{}, &fakeBackend{}, &fakeForwarder{}, &fakeRepoReg{})
	for _, p := range []string{"/v2/reg-A/app/manifests/v1", "/v2/_catalog", "/v2/reg-A/app/blobs/sha256:x", "/v2/reg-A/app/tags/list"} {
		rec := doReq(h, http.MethodGet, p, false)
		require.Equal(t, http.StatusUnauthorized, rec.Code, p)
	}
}

// REG-10 — GET /v2/ с валидным токеном → 200.
func TestDataplane_REG10_PingValidToken_200(t *testing.T) {
	h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, &fakeAuthz{}, &fakeBackend{}, &fakeForwarder{}, &fakeRepoReg{})
	rec := doReq(h, http.MethodGet, "/v2/", true)
	require.Equal(t, http.StatusOK, rec.Code)
}

// REG-13 — истёкший/битый JWT → 401 error="invalid_token" (запрос НЕ доходит до zot).
func TestDataplane_REG13_InvalidToken_401(t *testing.T) {
	fw := &fakeForwarder{}
	h := newTestHandler(&fakeVerifier{err: errors.New("expired")}, &fakeAuthz{}, &fakeBackend{}, fw, &fakeRepoReg{})
	rec := doReq(h, http.MethodGet, "/v2/reg-A/app/manifests/v1", true)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Contains(t, rec.Header().Get("WWW-Authenticate"), `error="invalid_token"`)
	require.Equal(t, 0, fw.count(), "invalid token never reaches zot")
}

// REG-16 — pull манифеста с правами: Check(registry_repository:reg-A/app, v_get)=allow
// → stream-proxy в zot (200).
func TestDataplane_REG16_PullManifest_Allow_Forward(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_get registry_repository:reg-A/app": true}}
	fw := &fakeForwarder{status: 200}
	h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, az, &fakeBackend{}, fw, &fakeRepoReg{})

	rec := doReq(h, http.MethodGet, "/v2/reg-A/app/manifests/v1", true)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, 1, fw.count(), "forwarded to zot")
	// subject построен из JWT sub (service_account:sva-ci).
	require.Equal(t, "service_account:sva-ci", az.checkedObjects()[0].subject)
}

// REG-17 — pull без прав (чужой тенант) → Check deny → 404 (existence-hiding, НЕ 403);
// блоб/манифест не стримится.
func TestDataplane_REG17_PullDeny_404_ExistenceHiding(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{}} // всё deny
	fw := &fakeForwarder{}
	h := newTestHandler(&fakeVerifier{subject: "sva-evil"}, az, &fakeBackend{}, fw, &fakeRepoReg{})

	for _, m := range []string{http.MethodGet, http.MethodHead} {
		rec := doReq(h, m, "/v2/reg-A/app/manifests/v1", true)
		require.Equal(t, http.StatusNotFound, rec.Code, m)
	}
	require.Equal(t, 0, fw.count(), "denied pull not forwarded")
}

// REG-17 revoke — #33: data-plane per-request authz Check НЕ кеширует (Authorizer =
// прямой check.IAMCheckClient), поэтому revoke энфорсится на СЛЕДУЮЩЕМ /v2/-запросе.
// Тот же субъект: request-1 при активном grant → forward (200); после revoke
// (AccessBinding удалён → Check теперь deny) request-2 → 404 (existence-hiding), НЕ
// forward. Локает «revoke promptly enforced» на data-plane (в отличие от gRPC
// control-plane, где окно ограничено KACHO_REGISTRY_AUTHZ_CACHE_TTL).
func TestDataplane_REG17_RevokePromptlyEnforced_404(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_get registry_repository:reg-A/app": true}}
	fw := &fakeForwarder{status: 200}
	h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, az, &fakeBackend{}, fw, &fakeRepoReg{})

	// grant активен → pull проксируется в zot.
	rec := doReq(h, http.MethodGet, "/v2/reg-A/app/manifests/v1", true)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, 1, fw.count())

	// revoke: AccessBinding удалён → Check теперь denies (no stale-allow cache).
	az.mu.Lock()
	az.allow = map[string]bool{}
	az.mu.Unlock()

	// следующий запрос того же субъекта → 404 (existence-hiding), НЕ forwarded.
	rec = doReq(h, http.MethodGet, "/v2/reg-A/app/manifests/v1", true)
	require.Equal(t, http.StatusNotFound, rec.Code, "revoked subject denied on next request")
	require.Equal(t, 1, fw.count(), "revoked pull not forwarded")
}

// REG-17 edge — iam.Check недоступен → fail-closed (не 2xx, не пропускает pull).
func TestDataplane_REG17_CheckUnavailable_FailClosed(t *testing.T) {
	az := &fakeAuthz{err: errors.New("iam down")}
	fw := &fakeForwarder{}
	h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, az, &fakeBackend{}, fw, &fakeRepoReg{})
	rec := doReq(h, http.MethodGet, "/v2/reg-A/app/manifests/v1", true)
	require.NotEqual(t, http.StatusOK, rec.Code)
	require.GreaterOrEqual(t, rec.Code, 400)
	require.Equal(t, 0, fw.count())
}

// REG-14 — push в НОВЫЙ repo: RepoExists=false → Check(registry_registry:reg-A, v_create)
// на upload-запросах allow → forward; на успешном manifest-PUT нового repo →
// RegisterResource-intent (parent-tuple ПЕРВЫМ + owner-tuple pushing-SA).
func TestDataplane_REG14_PushNewRepo_VCreate_Register(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_create registry_registry:reg-A": true}}
	fw := &fakeForwarder{status: 201}
	be := &fakeBackend{exists: map[string]bool{}} // repo ещё не существует
	rr := &fakeRepoReg{}
	h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, az, be, fw, rr)

	// blob-upload нового слоя — v_create@namespace.
	up := doReq(h, http.MethodPost, "/v2/reg-A/app/blobs/uploads/", true)
	require.Equal(t, 201, up.Code)

	// manifest-PUT финализирует новый repo — тот же v_create@namespace + register-intent.
	mf := doReq(h, http.MethodPut, "/v2/reg-A/app/manifests/v1", true)
	require.Equal(t, 201, mf.Code)

	intents := rr.registered()
	require.Len(t, intents, 1, "register-on-first-push emits exactly one intent")
	it := intents[0]
	require.Equal(t, "Repository", it.Kind)
	require.Equal(t, "reg-A/app", it.ResourceID)
	require.GreaterOrEqual(t, len(it.Tuples), 2)
	// parent-tuple ПЕРВЫМ (repo линкуется к namespace раньше owner-tuple).
	require.Equal(t, "parent", it.Tuples[0].Relation)
	require.Equal(t, "registry_repository:reg-A/app", it.Tuples[0].Object)
	require.Equal(t, "registry_registry:reg-A", it.Tuples[0].SubjectID)
	// owner-tuple — pushing SA.
	require.Equal(t, "owner", it.Tuples[1].Relation)
	require.Equal(t, "service_account:sva-ci", it.Tuples[1].SubjectID)
}

// REG-14b — register-on-first-push резолвит project реестра и несёт его в intent как
// ParentProjectID (иначе resource_mirror строка репо пустая → iam-reconciler не
// материализует v_* → образы недоступны даже владельцу). parent-tuple остаётся ПЕРВЫМ.
func TestDataplane_REG14_PushNewRepo_CarriesRegistryProject(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_create registry_registry:reg-A": true}}
	fw := &fakeForwarder{status: 201}
	be := &fakeBackend{exists: map[string]bool{}}
	rr := &fakeRepoReg{}
	lk := &fakeRegistryLookup{projectByRegistry: map[string]string{"reg-A": "prj-owner"}}
	h := newTestHandlerLK(&fakeVerifier{subject: "sva-ci"}, az, be, fw, rr, lk)

	up := doReq(h, http.MethodPost, "/v2/reg-A/app/blobs/uploads/", true)
	require.Equal(t, 201, up.Code)
	mf := doReq(h, http.MethodPut, "/v2/reg-A/app/manifests/v1", true)
	require.Equal(t, 201, mf.Code)

	intents := rr.registered()
	require.Len(t, intents, 1)
	it := intents[0]
	require.Equal(t, "prj-owner", it.ParentProjectID,
		"repo register-intent must carry the owning-project (iam mirror containment)")
	// parent-tuple ПЕРВЫМ (структурная привязка раньше owner-tuple) — не регрессируем.
	require.Equal(t, "parent", it.Tuples[0].Relation)
	require.Equal(t, "registry_repository:reg-A/app", it.Tuples[0].Object)
	// репо не несёт project-tuple (у типа нет project-relation).
	for _, tp := range it.Tuples {
		require.NotEqual(t, "project", tp.Relation, "repo intent must not carry a project-tuple")
	}
	require.Equal(t, 1, lk.calls, "project resolved exactly once on register-on-first-push")
}

// REG-14d — register-on-first-push, но RegistryProjectID-lookup упал (iam/registry
// транзиентно недоступен на post-response пути). Контракт resolveRegistryProject
// (handler.go:230): best-effort — интент ВСЁ РАВНО эмитится (хотя бы структурный
// parent-tuple, не регрессируя ниже прежнего поведения), но с ПУСТЫМ ParentProjectID
// (iam-reconciler тогда не материализует per-object v_*), а сбой наблюдаемо логируется.
// Без теста эта деградирующая ветка меняла бы поведение (skip vs emit) незаметно.
func TestDataplane_REG14d_PushNewRepo_ProjectLookupError_EmitsEmptyProject_Logged(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_create registry_registry:reg-A": true}}
	fw := &fakeForwarder{status: 201}
	be := &fakeBackend{exists: map[string]bool{}}
	rr := &fakeRepoReg{}
	lk := &fakeRegistryLookup{err: errors.New("iam lookup down")}

	var logbuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logbuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h := New(&fakeVerifier{subject: "sva-ci"}, az, be, fw, rr, lk,
		"https://api.kacho.local/iam/token", "registry.kacho.local", logger)

	up := doReq(h, http.MethodPost, "/v2/reg-A/app/blobs/uploads/", true)
	require.Equal(t, 201, up.Code)
	mf := doReq(h, http.MethodPut, "/v2/reg-A/app/manifests/v1", true)
	require.Equal(t, 201, mf.Code, "push 2xx forwarded несмотря на сбой project-lookup")

	intents := rr.registered()
	require.Len(t, intents, 1, "register-intent эмитится даже при сбое project-lookup (best-effort)")
	require.Empty(t, intents[0].ParentProjectID,
		"project-lookup failure → пустой ParentProjectID (не выдумываем project)")
	require.Equal(t, 1, lk.calls, "project-lookup попытан ровно один раз")
	require.Contains(t, logbuf.String(), "register-on-first-push project lookup failed",
		"сбой project-lookup наблюдаемо залогирован (не проглочен)")
}

// REG-18 — push без прав → первый upload-запрос Check(registry_registry:reg-A, v_create)
// deny → 404 (existence-hiding); блоб не принят, register-intent не эмитится.
func TestDataplane_REG18_PushNoRights_404(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{}} // deny
	fw := &fakeForwarder{}
	be := &fakeBackend{exists: map[string]bool{}}
	rr := &fakeRepoReg{}
	h := newTestHandler(&fakeVerifier{subject: "sva-evil"}, az, be, fw, rr)

	rec := doReq(h, http.MethodPost, "/v2/reg-A/app/blobs/uploads/", true)
	require.Equal(t, http.StatusNotFound, rec.Code)
	require.Equal(t, 0, fw.count())
	require.Empty(t, rr.registered())
}

// REG-14c — register-on-first-push emit-failure branch (handler.go:211): успешный
// первый manifest-PUT нового repo, но RegisterRepository durable-emit падает (редкий
// DB-сбой). Контракт log-and-continue: клиент всё равно получает свой 2xx (уже
// отданный ответ не рвём), сбой наблюдаемо логируется, паники нет. Регресс-гейт
// против «push стал рвать клиента» или «сбой проглочен молча».
func TestDataplane_REG14c_RegisterEmitFailure_PushStill2xx_Logged(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_create registry_registry:reg-A": true}}
	fw := &fakeForwarder{status: 201}
	be := &fakeBackend{exists: map[string]bool{}} // новый repo
	rr := &fakeRepoReg{err: errors.New("outbox insert failed")}

	var logbuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logbuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h := New(&fakeVerifier{subject: "sva-ci"}, az, be, fw, rr,
		&fakeRegistryLookup{}, "https://api.kacho.local/iam/token", "registry.kacho.local", logger)

	up := doReq(h, http.MethodPost, "/v2/reg-A/app/blobs/uploads/", true)
	require.Equal(t, 201, up.Code)

	// manifest-PUT: forward успешен (201), register-emit падает — клиент НЕ страдает.
	mf := doReq(h, http.MethodPut, "/v2/reg-A/app/manifests/v1", true)
	require.Equal(t, 201, mf.Code, "push 2xx forwarded несмотря на сбой register-emit")

	require.Len(t, rr.registered(), 1, "register-intent попытан ровно один раз")
	require.Contains(t, logbuf.String(), "register-on-first-push emit failed",
		"сбой durable-emit наблюдаемо залогирован (не проглочен)")
}

// REG-15 — push в СУЩЕСТВУЮЩИЙ repo: verb-map = v_update@registry_repository (НЕ
// namespace v_create). allow → forward; register-intent НЕ эмитится (repo уже есть).
func TestDataplane_REG15_PushExisting_VUpdate(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_update registry_repository:reg-A/app": true}}
	fw := &fakeForwarder{status: 202}
	be := &fakeBackend{exists: map[string]bool{"reg-A/app": true}} // repo существует
	rr := &fakeRepoReg{}
	h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, az, be, fw, rr)

	rec := doReq(h, http.MethodPost, "/v2/reg-A/app/blobs/uploads/", true)
	require.Equal(t, 202, rec.Code)
	require.Equal(t, 1, fw.count())
	require.Empty(t, rr.registered(), "existing repo → no re-register")
	// проверили именно v_update на repo-объекте.
	require.Equal(t, checkCall{"service_account:sva-ci", "v_update", "registry_repository:reg-A/app"}, az.checkedObjects()[0])
}

// REG-15 negative — субъект с namespace v_create, но БЕЗ v_update на существующий repo
// → blob-upload в существующий repo → Check(v_update@repo) deny → 404 (decoupling).
func TestDataplane_REG15_PushExisting_NoRepoUpdate_404(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_create registry_registry:reg-A": true}} // только namespace
	fw := &fakeForwarder{}
	be := &fakeBackend{exists: map[string]bool{"reg-A/app": true}}
	h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{})

	rec := doReq(h, http.MethodPost, "/v2/reg-A/app/blobs/uploads/", true)
	require.Equal(t, http.StatusNotFound, rec.Code)
	require.Equal(t, 0, fw.count())
}

// REG-35 — data-plane HTTP-метод DELETE → 405 Method Not Allowed ДО zot (единственный
// путь удаления — control-plane DeleteTag). Во всех ветках (с правами / чужой / blob).
func TestDataplane_REG35_Delete_405(t *testing.T) {
	az := &fakeAuthz{} // allow-all — 405 всё равно, независимо от прав
	fw := &fakeForwarder{}
	h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, az, &fakeBackend{}, fw, &fakeRepoReg{})

	for _, p := range []string{"/v2/reg-A/app/manifests/sha256:dd", "/v2/reg-A/app/blobs/sha256:dd"} {
		rec := doReq(h, http.MethodDelete, p, true)
		require.Equal(t, http.StatusMethodNotAllowed, rec.Code, p)
	}
	require.Equal(t, 0, fw.count(), "DELETE never reaches zot")
}

// REG-19 — traversal (raw + encoded) → 400; cross-namespace на чужой reg-B без прав →
// Check deny → 404; путь без валидного registry-prefix → 404.
func TestDataplane_REG19_TraversalAndCrossNamespace(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{}} // deny всё (для cross-namespace)
	fw := &fakeForwarder{}
	h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, az, &fakeBackend{}, fw, &fakeRepoReg{})

	require.Equal(t, http.StatusBadRequest, doReq(h, http.MethodGet, "/v2/reg-A/../reg-B/app/manifests/v1", true).Code)
	require.Equal(t, http.StatusBadRequest, doReq(h, http.MethodGet, "/v2/reg-A/%2e%2e/reg-B/app/manifests/v1", true).Code)
	// прямой cross-namespace на reg-B без прав → 404 (existence-hiding).
	require.Equal(t, http.StatusNotFound, doReq(h, http.MethodGet, "/v2/reg-B/app/manifests/v1", true).Code)
	// путь без валидного registry-prefix → 404.
	require.Equal(t, http.StatusNotFound, doReq(h, http.MethodGet, "/v2/app/manifests/v1", true).Code)
	require.Equal(t, 0, fw.count())
}

// REG-23 — GET /v2/_catalog: proxy per-repo listauthz-фильтрует (Check v_list на
// registry_repository:<repo>) — межтенантно + межрепозиторно не течёт.
func TestDataplane_REG23_Catalog_PerRepoFilter(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{
		"v_list registry_repository:reg-A/app": true, // только reg-A/app виден
	}}
	be := &fakeBackend{catalog: []string{"reg-A/app", "reg-A/web", "reg-B/secret"}}
	h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, az, be, &fakeForwarder{}, &fakeRepoReg{})

	rec := doReq(h, http.MethodGet, "/v2/_catalog", true)
	require.Equal(t, http.StatusOK, rec.Code)

	var body struct {
		Repositories []string `json:"repositories"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, []string{"reg-A/app"}, body.Repositories)
}

// REG-23 pagination (CWE-770) — GET /v2/_catalog с `?n=` ограничивает число
// per-repo authz-Check'ов ОКНОМ страницы ДО authz-цикла: запрос не разворачивается в
// N последовательных iam.Check по всему кросс-тенантному каталогу. При n=2 из 5 репо
// проверяется ровно 2, отдаётся ≤2 видимых, а Link-заголовок сигналит следующую
// страницу (rel="next", cursor last=<опаковый offset, НЕ имя репо>).
func TestDataplane_REG23_Catalog_PaginationBoundsChecks(t *testing.T) {
	az := &fakeAuthz{} // allow-all
	be := &fakeBackend{catalog: []string{"reg-A/a", "reg-A/b", "reg-A/c", "reg-B/x", "reg-B/y"}}
	h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, az, be, &fakeForwarder{}, &fakeRepoReg{})

	rec := doReq(h, http.MethodGet, "/v2/_catalog?n=2", true)
	require.Equal(t, http.StatusOK, rec.Code)

	var body struct {
		Repositories []string `json:"repositories"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, []string{"reg-A/a", "reg-A/b"}, body.Repositories, "first page = first n sorted names")
	require.Len(t, az.checkedObjects(), 2, "authz Check count bounded by page size, not whole catalog")

	link := rec.Header().Get("Link")
	require.Contains(t, link, `rel="next"`, "truncated catalog advertises next page")
	require.Contains(t, link, "n=2")
	// Курсор — опаковый offset (позиция 2), НЕ сырое имя окна (иначе existence-oracle).
	require.Contains(t, link, "last="+url.QueryEscape(encodeCatalogCursor(2)), "next cursor = opaque offset")
	require.NotContains(t, link, "reg-A", "cursor must not echo a raw repo name")
}

// REG-23 pagination cursor — опаковый offset-курсор (позиция 2) продолжает со
// следующего имени после окна (window = ["reg-A/c","reg-B/x"]); authz-Check только по окну.
func TestDataplane_REG23_Catalog_PaginationCursor(t *testing.T) {
	az := &fakeAuthz{}
	be := &fakeBackend{catalog: []string{"reg-A/a", "reg-A/b", "reg-A/c", "reg-B/x", "reg-B/y"}}
	h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, az, be, &fakeForwarder{}, &fakeRepoReg{})

	rec := doReq(h, http.MethodGet, "/v2/_catalog?n=2&last="+url.QueryEscape(encodeCatalogCursor(2)), true)
	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		Repositories []string `json:"repositories"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, []string{"reg-A/c", "reg-B/x"}, body.Repositories)
	require.Len(t, az.checkedObjects(), 2)
}

// REG-23 pagination cursor-leak — Link `last=` НЕ должен раскрывать сырое имя репо,
// которое вызывающий не видит (existence-oracle). Каталог целиком чужой на первой
// странице (n=1): курсор обязан быть опаковым (offset), не именем; и пагинация всё
// равно доводит до собственного репо вызывающего (reachability на схлопнутых страницах).
func TestDataplane_REG23_Catalog_CursorDoesNotLeakForeignName(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_list registry_repository:reg-A/mine": true}}
	be := &fakeBackend{catalog: []string{"reg-B/secret", "reg-B/other", "reg-A/mine"}}
	h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, az, be, &fakeForwarder{}, &fakeRepoReg{})

	seenVisible := false
	last := ""
	for i := 0; i < 10; i++ { // ограничитель против бесконечного цикла в тесте
		path := "/v2/_catalog?n=1"
		if last != "" {
			path += "&last=" + url.QueryEscape(last)
		}
		rec := doReq(h, http.MethodGet, path, true)
		require.Equal(t, http.StatusOK, rec.Code)

		var body struct {
			Repositories []string `json:"repositories"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		for _, r := range body.Repositories {
			require.Equal(t, "reg-A/mine", r, "видимым может быть только собственный репо")
			seenVisible = true
		}

		link := rec.Header().Get("Link")
		if link == "" {
			break // хвост каталога
		}
		// Извлекаем cursor last= из Link и проверяем, что он НЕ несёт сырое чужое имя.
		u, err := url.Parse(strings.Trim(strings.SplitN(link, ">", 2)[0], "<"))
		require.NoError(t, err)
		last = u.Query().Get("last")
		require.NotContains(t, last, "reg-B", "cursor must not echo foreign raw repo name")
		require.NotContains(t, last, "secret", "cursor must not echo foreign raw repo name")
		require.NotContains(t, last, "other", "cursor must not echo foreign raw repo name")
	}
	require.True(t, seenVisible, "пагинация обязана доводить до собственного репо через схлопнутые страницы")
}

// REG-23 pagination last page — окно покрывает хвост каталога → без Link (нет
// следующей страницы). authz-фильтр по-прежнему применяется.
func TestDataplane_REG23_Catalog_LastPageNoLink(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_list registry_repository:reg-B/y": true}}
	be := &fakeBackend{catalog: []string{"reg-A/a", "reg-A/b", "reg-B/y"}}
	h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, az, be, &fakeForwarder{}, &fakeRepoReg{})

	rec := doReq(h, http.MethodGet, "/v2/_catalog?n=100", true)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Empty(t, rec.Header().Get("Link"), "full window → no next page")
	var body struct {
		Repositories []string `json:"repositories"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, []string{"reg-B/y"}, body.Repositories)
}

// REG-24 — GET /v2/<repo>/tags/list: v_list на repo allow → forward; без прав → 404.
func TestDataplane_REG24_TagsList(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_list registry_repository:reg-A/app": true}}
	fw := &fakeForwarder{status: 200}
	h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, az, &fakeBackend{}, fw, &fakeRepoReg{})

	require.Equal(t, 200, doReq(h, http.MethodGet, "/v2/reg-A/app/tags/list", true).Code)
	require.Equal(t, http.StatusNotFound, doReq(h, http.MethodGet, "/v2/reg-A/web/tags/list", true).Code)
}

// REG-37 — blob-existence per-repo scope: v_get на repo allow, но <digest> НЕ входит в
// манифесты авторизованного repo → 404 (existence-hiding на blob-уровне). Легитимный
// слой (входит в манифест) → forward.
func TestDataplane_REG37_BlobScope_ForeignDigest_404(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_get registry_repository:reg-A/app": true}}
	fw := &fakeForwarder{status: 200}
	be := &fakeBackend{blobs: map[string]bool{
		"reg-A/app|sha256:own": true, // легитимный слой repo
		// sha256:foreign отсутствует → не принадлежит reg-A/app
	}}
	h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{})

	// чужой блоб → 404, не стримится.
	require.Equal(t, http.StatusNotFound, doReq(h, http.MethodHead, "/v2/reg-A/app/blobs/sha256:foreign", true).Code)
	require.Equal(t, http.StatusNotFound, doReq(h, http.MethodGet, "/v2/reg-A/app/blobs/sha256:foreign", true).Code)
	require.Equal(t, 0, fw.count())

	// свой слой → forward.
	require.Equal(t, 200, doReq(h, http.MethodGet, "/v2/reg-A/app/blobs/sha256:own", true).Code)
	require.Equal(t, 1, fw.count())
}

// REG-37 negative — нет v_get на сам repo → 404 (per-request Check deny, как REG-17),
// blob-scope даже не проверяется.
func TestDataplane_REG37_NoRepoGet_404(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{}}
	be := &fakeBackend{blobs: map[string]bool{"reg-A/app|sha256:own": true}}
	fw := &fakeForwarder{}
	h := newTestHandler(&fakeVerifier{subject: "sva-evil"}, az, be, fw, &fakeRepoReg{})
	require.Equal(t, http.StatusNotFound, doReq(h, http.MethodHead, "/v2/reg-A/app/blobs/sha256:own", true).Code)
	require.Equal(t, 0, fw.count())
}

// REG-20 — cross-repo blob mount exfil-guard: ДВА Check (v_get на src + write-verb на
// dst). v_get(src)=deny → mount 404 (блоб не смонтирован). Оба allow → forward.
// dst — новый repo (fakeBackend без exists) → dst-verb = v_create@registry_registry.
func TestDataplane_REG20_CrossRepoMount_ExfilGuard(t *testing.T) {
	// src deny → 404.
	azDeny := &fakeAuthz{allow: map[string]bool{"v_create registry_registry:reg-A": true}}
	fwDeny := &fakeForwarder{}
	hDeny := newTestHandler(&fakeVerifier{subject: "sva-ci"}, azDeny, &fakeBackend{}, fwDeny, &fakeRepoReg{})
	rec := doReq(hDeny, http.MethodPost, "/v2/reg-A/dst/blobs/uploads/?mount=sha256:x&from=reg-A/src", true)
	require.Equal(t, http.StatusNotFound, rec.Code)
	require.Equal(t, 0, fwDeny.count(), "foreign blob not mounted")

	// оба allow → forward.
	azAllow := &fakeAuthz{allow: map[string]bool{
		"v_get registry_repository:reg-A/src": true,
		"v_create registry_registry:reg-A":    true,
	}}
	fwAllow := &fakeForwarder{status: 201}
	beAllow := &fakeBackend{blobs: map[string]bool{"reg-A/src|sha256:x": true}} // digest — член src-repo (REG-37)
	hAllow := newTestHandler(&fakeVerifier{subject: "sva-ci"}, azAllow, beAllow, fwAllow, &fakeRepoReg{})
	require.Equal(t, 201, doReq(hAllow, http.MethodPost, "/v2/reg-A/dst/blobs/uploads/?mount=sha256:x&from=reg-A/src", true).Code)
	require.Equal(t, 1, fwAllow.count())
}

// REG-20 traversal — cross-repo mount `from` с path-traversal (raw ".." и
// URL-encoded "%2e%2e") → 400 NAME_INVALID ДО любого authz-Check; блоб не
// монтируется, forwarder не вызывается. Закрывает пробел покрытия guard'а
// serveMount (CWE-22 / OWASP A01): без этого теста рефактор, ослабивший
// strings.Contains(from,"..")-проверку, прошёл бы незамеченным.
func TestDataplane_REG20_MountFromTraversal_400(t *testing.T) {
	traversals := []string{
		"reg-A/../reg-B/src", // выход из namespace в чужой reg-B
		"../secret",          // выход выше корня
		"reg-A/%2e%2e/reg-B", // URL-encoded ".." (Query декодирует до "..")
		"%2e%2e/secret",      // URL-encoded ведущий ".."
	}
	for _, from := range traversals {
		az := &fakeAuthz{} // allow-all — 400 всё равно, до Check
		fw := &fakeForwarder{}
		h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, az, &fakeBackend{}, fw, &fakeRepoReg{})
		target := "/v2/reg-A/dst/blobs/uploads/?mount=sha256:x&from=" + from
		rec := doReq(h, http.MethodPost, target, true)
		require.Equal(t, http.StatusBadRequest, rec.Code, from)
		var body struct {
			Errors []struct{ Code string } `json:"errors"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		require.Len(t, body.Errors, 1, from)
		require.Equal(t, "NAME_INVALID", body.Errors[0].Code, from)
		require.Equal(t, 0, fw.count(), "traversal mount never forwarded: "+from)
		require.Empty(t, az.checkedObjects(), "traversal rejected before any authz Check: "+from)
	}
}

// REG-20 cross-registry — mount из ДРУГОГО реестра (from=reg-B/src в dst reg-A/dst):
// exfil-guard делает ДВА Check (v_get на src-объекте reg-B/src И write-verb на
// dst-объекте reg-A/dst). Оба allow → forward; src deny → 404 (чужой блоб из reg-B
// не вытекает в reg-A). dst — новый repo → dst-verb = v_create@registry_registry:reg-A.
func TestDataplane_REG20_CrossRegistryMount_TwoChecks(t *testing.T) {
	// оба allow → forward + ровно два Check на правильные объекты.
	az := &fakeAuthz{allow: map[string]bool{
		"v_get registry_repository:reg-B/src": true,
		"v_create registry_registry:reg-A":    true,
	}}
	fw := &fakeForwarder{status: 201}
	beMember := &fakeBackend{blobs: map[string]bool{"reg-B/src|sha256:x": true}} // digest — член src-repo (REG-37)
	h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, az, beMember, fw, &fakeRepoReg{})
	rec := doReq(h, http.MethodPost, "/v2/reg-A/dst/blobs/uploads/?mount=sha256:x&from=reg-B/src", true)
	require.Equal(t, 201, rec.Code)
	require.Equal(t, 1, fw.count())
	calls := az.checkedObjects()
	require.Len(t, calls, 2, "cross-registry mount checks src AND dst")
	require.Contains(t, calls, checkCall{"service_account:sva-ci", "v_get", "registry_repository:reg-B/src"})
	require.Contains(t, calls, checkCall{"service_account:sva-ci", "v_create", "registry_registry:reg-A"})

	// src (reg-B) deny → 404, блоб чужого реестра не смонтирован.
	azDeny := &fakeAuthz{allow: map[string]bool{"v_create registry_registry:reg-A": true}}
	fwDeny := &fakeForwarder{}
	hDeny := newTestHandler(&fakeVerifier{subject: "sva-ci"}, azDeny, &fakeBackend{}, fwDeny, &fakeRepoReg{})
	recDeny := doReq(hDeny, http.MethodPost, "/v2/reg-A/dst/blobs/uploads/?mount=sha256:x&from=reg-B/src", true)
	require.Equal(t, http.StatusNotFound, recDeny.Code)
	require.Equal(t, 0, fwDeny.count(), "cross-registry blob not mounted without src v_get")
}

// REG-20 dst verb-map (audit-r1) — cross-repo mount dst-Check зеркалит servePush:
// НОВЫЙ dst-repo гейтится v_create@registry_registry (право создать repo в namespace),
// СУЩЕСТВУЮЩИЙ — v_update@registry_repository. Хардкод v_create@registry_repository
// расходился бы с push-путём (verb-mismatch): namespace-creator не смонтировал бы в
// новый repo (silent 404 → полный re-upload), а v_create-only принципал писал бы в
// существующий repo мимо v_update-гейта.
func TestDataplane_REG20_MountDst_VerbMapMirrorsPush(t *testing.T) {
	const mountURL = "/v2/reg-A/dst/blobs/uploads/?mount=sha256:x&from=reg-A/src"

	// dst — НОВЫЙ repo: dst-Check должен быть v_create@registry_registry:reg-A.
	// Принципал с namespace-level v_create (+ v_get на src) → mount проходит.
	azNew := &fakeAuthz{allow: map[string]bool{
		"v_get registry_repository:reg-A/src": true,
		"v_create registry_registry:reg-A":    true,
	}}
	fwNew := &fakeForwarder{status: 201}
	beNew := &fakeBackend{blobs: map[string]bool{"reg-A/src|sha256:x": true}} // digest — член src-repo (REG-37)
	hNew := newTestHandler(&fakeVerifier{subject: "sva-ci"}, azNew, beNew, fwNew, &fakeRepoReg{})
	require.Equal(t, 201, doReq(hNew, http.MethodPost, mountURL, true).Code)
	require.Equal(t, 1, fwNew.count(), "namespace-creator mounts into a brand-new dst repo")
	require.Contains(t, azNew.checkedObjects(),
		checkCall{"service_account:sva-ci", "v_create", "registry_registry:reg-A"})

	// dst — СУЩЕСТВУЮЩИЙ repo: dst-Check должен быть v_update@registry_repository:reg-A/dst.
	beExisting := &fakeBackend{
		exists: map[string]bool{"reg-A/dst": true},
		blobs:  map[string]bool{"reg-A/src|sha256:x": true}, // digest — член src-repo (REG-37)
	}
	azUpd := &fakeAuthz{allow: map[string]bool{
		"v_get registry_repository:reg-A/src":    true,
		"v_update registry_repository:reg-A/dst": true,
	}}
	fwUpd := &fakeForwarder{status: 201}
	hUpd := newTestHandler(&fakeVerifier{subject: "sva-ci"}, azUpd, beExisting, fwUpd, &fakeRepoReg{})
	require.Equal(t, 201, doReq(hUpd, http.MethodPost, mountURL, true).Code)
	require.Equal(t, 1, fwUpd.count(), "v_update holder mounts into an existing dst repo")
	require.Contains(t, azUpd.checkedObjects(),
		checkCall{"service_account:sva-ci", "v_update", "registry_repository:reg-A/dst"})

	// verb-mismatch guard: dst СУЩЕСТВУЕТ, принципал держит только namespace v_create
	// (без v_update на repo) → mount отклонён 404 (нельзя писать в существующий repo
	// мимо v_update), несмотря на v_get(src).
	azMismatch := &fakeAuthz{allow: map[string]bool{
		"v_get registry_repository:reg-A/src": true,
		"v_create registry_registry:reg-A":    true,
	}}
	fwMismatch := &fakeForwarder{}
	hMismatch := newTestHandler(&fakeVerifier{subject: "sva-ci"}, azMismatch, beExisting, fwMismatch, &fakeRepoReg{})
	require.Equal(t, http.StatusNotFound, doReq(hMismatch, http.MethodPost, mountURL, true).Code)
	require.Equal(t, 0, fwMismatch.count(), "v_create-only principal cannot write to an existing repo via mount")
}

// REG-37 mount blob-scope — cross-repo mount обязан проверять, что монтируемый digest
// ДЕЙСТВИТЕЛЬНО входит в src-repo (как serveBlob для GET/HEAD): zot не изолирует блобы
// по repo (content-addressable глобальны), поэтому v_get(src)+v_update(dst) НЕ доказывает
// членство digest'а в src. Без BlobInRepo(from-reg, from-repo, mount-digest) атакующий с
// легальным доступом к своим reg-A/src и reg-A/dst смонтировал бы чужой глобальный блоб.
func TestDataplane_REG37_MountBlobScope_NonMember_404(t *testing.T) {
	const mountURL = "/v2/reg-A/dst/blobs/uploads/?mount=sha256:victim&from=reg-A/src"
	// Оба Check allow, но digest sha256:victim НЕ член reg-A/src (blobs пуст) → 404.
	az := &fakeAuthz{allow: map[string]bool{
		"v_get registry_repository:reg-A/src": true,
		"v_create registry_registry:reg-A":    true,
	}}
	fw := &fakeForwarder{status: 201}
	be := &fakeBackend{} // src-repo не содержит sha256:victim
	h := newTestHandler(&fakeVerifier{subject: "sva-evil"}, az, be, fw, &fakeRepoReg{})
	require.Equal(t, http.StatusNotFound, doReq(h, http.MethodPost, mountURL, true).Code)
	require.Equal(t, 0, fw.count(), "non-member digest not mounted despite two authz allows")

	// Тот же digest, но реально член src-repo → mount проходит (forward).
	beMember := &fakeBackend{blobs: map[string]bool{"reg-A/src|sha256:victim": true}}
	fwOK := &fakeForwarder{status: 201}
	hOK := newTestHandler(&fakeVerifier{subject: "sva-ci"}, az, beMember, fwOK, &fakeRepoReg{})
	require.Equal(t, 201, doReq(hOK, http.MethodPost, mountURL, true).Code)
	require.Equal(t, 1, fwOK.count(), "member digest mounts")
}

// helper: убеждаемся, что Authorization без "Bearer " схемы → 401.
func TestDataplane_MalformedAuthHeader_401(t *testing.T) {
	h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, &fakeAuthz{}, &fakeBackend{}, &fakeForwarder{}, &fakeRepoReg{})
	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.True(t, strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Bearer "))
}
