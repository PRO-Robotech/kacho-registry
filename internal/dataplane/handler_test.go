// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package dataplane

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

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
// страницу (rel="next", cursor last=<последнее имя окна>).
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
	require.Contains(t, link, "last=reg-A%2Fb", "next cursor = last name of window")
	require.Contains(t, link, "n=2")
}

// REG-23 pagination cursor — `?n=2&last=reg-A/b` продолжает со следующего имени после
// курсора (окно = ["reg-A/c","reg-B/x"]); authz-Check только по окну.
func TestDataplane_REG23_Catalog_PaginationCursor(t *testing.T) {
	az := &fakeAuthz{}
	be := &fakeBackend{catalog: []string{"reg-A/a", "reg-A/b", "reg-A/c", "reg-B/x", "reg-B/y"}}
	h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, az, be, &fakeForwarder{}, &fakeRepoReg{})

	rec := doReq(h, http.MethodGet, "/v2/_catalog?n=2&last=reg-A/b", true)
	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		Repositories []string `json:"repositories"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, []string{"reg-A/c", "reg-B/x"}, body.Repositories)
	require.Len(t, az.checkedObjects(), 2)
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

// REG-20 — cross-repo blob mount exfil-guard: ДВА Check (v_get на src + v_create на dst).
// v_get(src)=deny → mount 404 (блоб не смонтирован). Оба allow → forward.
func TestDataplane_REG20_CrossRepoMount_ExfilGuard(t *testing.T) {
	// src deny → 404.
	azDeny := &fakeAuthz{allow: map[string]bool{"v_create registry_repository:reg-A/dst": true}}
	fwDeny := &fakeForwarder{}
	hDeny := newTestHandler(&fakeVerifier{subject: "sva-ci"}, azDeny, &fakeBackend{}, fwDeny, &fakeRepoReg{})
	rec := doReq(hDeny, http.MethodPost, "/v2/reg-A/dst/blobs/uploads/?mount=sha256:x&from=reg-A/src", true)
	require.Equal(t, http.StatusNotFound, rec.Code)
	require.Equal(t, 0, fwDeny.count(), "foreign blob not mounted")

	// оба allow → forward.
	azAllow := &fakeAuthz{allow: map[string]bool{
		"v_get registry_repository:reg-A/src":    true,
		"v_create registry_repository:reg-A/dst": true,
	}}
	fwAllow := &fakeForwarder{status: 201}
	hAllow := newTestHandler(&fakeVerifier{subject: "sva-ci"}, azAllow, &fakeBackend{}, fwAllow, &fakeRepoReg{})
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
// exfil-guard делает ДВА Check (v_get на src-объекте reg-B/src И v_create на
// dst-объекте reg-A/dst). Оба allow → forward; src deny → 404 (чужой блоб из reg-B
// не вытекает в reg-A).
func TestDataplane_REG20_CrossRegistryMount_TwoChecks(t *testing.T) {
	// оба allow → forward + ровно два Check на правильные объекты.
	az := &fakeAuthz{allow: map[string]bool{
		"v_get registry_repository:reg-B/src":    true,
		"v_create registry_repository:reg-A/dst": true,
	}}
	fw := &fakeForwarder{status: 201}
	h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, az, &fakeBackend{}, fw, &fakeRepoReg{})
	rec := doReq(h, http.MethodPost, "/v2/reg-A/dst/blobs/uploads/?mount=sha256:x&from=reg-B/src", true)
	require.Equal(t, 201, rec.Code)
	require.Equal(t, 1, fw.count())
	calls := az.checkedObjects()
	require.Len(t, calls, 2, "cross-registry mount checks src AND dst")
	require.Contains(t, calls, checkCall{"service_account:sva-ci", "v_get", "registry_repository:reg-B/src"})
	require.Contains(t, calls, checkCall{"service_account:sva-ci", "v_create", "registry_repository:reg-A/dst"})

	// src (reg-B) deny → 404, блоб чужого реестра не смонтирован.
	azDeny := &fakeAuthz{allow: map[string]bool{"v_create registry_repository:reg-A/dst": true}}
	fwDeny := &fakeForwarder{}
	hDeny := newTestHandler(&fakeVerifier{subject: "sva-ci"}, azDeny, &fakeBackend{}, fwDeny, &fakeRepoReg{})
	recDeny := doReq(hDeny, http.MethodPost, "/v2/reg-A/dst/blobs/uploads/?mount=sha256:x&from=reg-B/src", true)
	require.Equal(t, http.StatusNotFound, recDeny.Code)
	require.Equal(t, 0, fwDeny.count(), "cross-registry blob not mounted without src v_get")
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
