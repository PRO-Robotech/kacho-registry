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
	"time"

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

// ForwardCapture — cancelingForwarder не используется на blob-finalize пути, но обязан
// удовлетворять интерфейсу Forwarder.
func (f *cancelingForwarder) ForwardCapture(r *http.Request) CapturedResponse {
	f.calls++
	st := f.status
	if st == 0 {
		st = http.StatusOK
	}
	return CapturedResponse{Status: st, Header: http.Header{}}
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
	h := New(&fakeVerifier{subject: "sva-ci"}, az, be, fw, rr, lk, &fakeUploadRecorder{}, &fakePushGrantRecorder{},
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
// deny → 403 DENIED (docker-стандарт push-отказа, existence-hiding униформностью); блоб не
// принят, register-intent не эмитится.
func TestDataplane_REG18_PushNoRights_403Denied(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{}} // deny
	fw := &fakeForwarder{}
	be := &fakeBackend{exists: map[string]bool{}}
	rr := &fakeRepoReg{}
	h := newTestHandler(&fakeVerifier{subject: "sva-evil"}, az, be, fw, rr)

	rec := doReq(h, http.MethodPost, "/v2/reg-A/app/blobs/uploads/", true)
	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Equal(t, "DENIED", pushDenyCode(t, rec))
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
		&fakeRegistryLookup{}, &fakeUploadRecorder{}, &fakePushGrantRecorder{}, "https://api.kacho.local/iam/token", "registry.kacho.local", logger)

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
// → blob-upload в существующий repo → Check(v_update@repo) deny → 403 DENIED (decoupling;
// push-deny униформно 403).
func TestDataplane_REG15_PushExisting_NoRepoUpdate_403Denied(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_create registry_registry:reg-A": true}} // только namespace
	fw := &fakeForwarder{}
	be := &fakeBackend{exists: map[string]bool{"reg-A/app": true}}
	h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{})

	rec := doReq(h, http.MethodPost, "/v2/reg-A/app/blobs/uploads/", true)
	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Equal(t, "DENIED", pushDenyCode(t, rec))
	require.Equal(t, 0, fw.count())
}

// pushDenyBody декодирует OCI-error-body и возвращает первый code (для проверки DENIED).
func pushDenyCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Errors []struct{ Code, Message string } `json:"errors"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Len(t, body.Errors, 1)
	return body.Errors[0].Code
}

// REG-DENY — push authz-deny отдаёт docker-стандартный 403 DENIED (а НЕ 404 name-unknown):
// «name unknown: not found» на push, который caller не вправе писать, путает легитимного-но-
// неавторизованного/отозванного толкавшего; все крупные реестры возвращают 403 denied. Меняем
// ТОЛЬКО push-путь (servePush + serveMount deny). Existence-hiding СОХРАНЁН униформностью:
// КАЖДЫЙ push-deny → 403 (repo существует ИЛИ нет — не различить), точно как было с 404-uniform.
// RED до фикса: servePush deny отдаёт 404 NAME_UNKNOWN. Pull-deny остаётся 404 (отдельный кейс ниже).
func TestDataplane_REGDENY_PushAuthzDeny_403Denied_Uniform(t *testing.T) {
	// (1) blob-upload init в НЕСУЩЕСТВУЮЩИЙ repo, v_create denied → 403 DENIED.
	azNew := &fakeAuthz{allow: map[string]bool{}} // deny
	fwNew := &fakeForwarder{}
	hNew := newTestHandler(&fakeVerifier{subject: "sva-evil"}, azNew, &fakeBackend{exists: map[string]bool{}}, fwNew, &fakeRepoReg{})
	recNew := doReq(hNew, http.MethodPost, "/v2/reg-A/app/blobs/uploads/", true)
	require.Equal(t, http.StatusForbidden, recNew.Code, "push-deny нового repo → 403 (не 404)")
	require.Equal(t, "DENIED", pushDenyCode(t, recNew), "docker-стандартный code DENIED")
	require.Equal(t, 0, fwNew.count())

	// (2) manifest-PUT в СУЩЕСТВУЮЩИЙ repo, v_update denied → 403 DENIED (та же униформа).
	azExisting := &fakeAuthz{allow: map[string]bool{}} // deny
	fwExisting := &fakeForwarder{}
	hExisting := newTestHandler(&fakeVerifier{subject: "sva-evil"}, azExisting, &fakeBackend{exists: map[string]bool{"reg-A/app": true}}, fwExisting, &fakeRepoReg{})
	recExisting := doReq(hExisting, http.MethodPut, "/v2/reg-A/app/manifests/v1", true)
	require.Equal(t, http.StatusForbidden, recExisting.Code, "push-deny существующего repo → 403")
	require.Equal(t, "DENIED", pushDenyCode(t, recExisting))

	// Униформность existence-hiding: несуществующий (v_create-deny) И существующий (v_update-deny)
	// дают ОДИНАКОВЫЙ 403 → атакующий не отличает exists-denied от nonexistent (как 404-uniform).
	require.Equal(t, recNew.Code, recExisting.Code,
		"exists-denied и nonexistent-denied неразличимы (оба 403) — existence-hiding сохранён")
}

// REG-DENY — mount authz-deny (src ИЛИ dst) → 403 DENIED (push-путь). Blob-scope miss и
// traversal остаются на своих кодах (404 / 400) — это НЕ authz-deny.
func TestDataplane_REGDENY_MountAuthzDeny_403Denied(t *testing.T) {
	// src deny (v_get на src denied), dst v_create allow → 403 DENIED.
	az := &fakeAuthz{allow: map[string]bool{"v_create registry_registry:reg-A": true}}
	fw := &fakeForwarder{}
	h := newTestHandler(&fakeVerifier{subject: "sva-evil"}, az, &fakeBackend{}, fw, &fakeRepoReg{})
	rec := doReq(h, http.MethodPost, "/v2/reg-A/dst/blobs/uploads/?mount=sha256:x&from=reg-A/src", true)
	require.Equal(t, http.StatusForbidden, rec.Code, "mount src-deny → 403 denied")
	require.Equal(t, "DENIED", pushDenyCode(t, rec))
	require.Equal(t, 0, fw.count())
}

// REG-DENY regression — PULL/read authz-deny остаётся 404 NAME_UNKNOWN (read-side
// existence-hiding для content-discovery не меняется); fail-closed (Check error) → 503.
func TestDataplane_REGDENY_PullDenyStays404_FailClosed503(t *testing.T) {
	// pull manifest deny → 404 (не 403): read-путь existence-hiding сохранён.
	azDeny := &fakeAuthz{allow: map[string]bool{}}
	h404 := newTestHandler(&fakeVerifier{subject: "sva-evil"}, azDeny, &fakeBackend{exists: map[string]bool{"reg-A/app": true}}, &fakeForwarder{}, &fakeRepoReg{})
	require.Equal(t, http.StatusNotFound, doReq(h404, http.MethodGet, "/v2/reg-A/app/manifests/v1", true).Code,
		"pull-deny остаётся 404 NAME_UNKNOWN (read-side existence-hiding)")

	// push Check-error (зависимость недоступна) → fail-closed 503, НЕ 403/404.
	azErr := &fakeAuthz{err: errors.New("iam down")}
	rec := doReq(newTestHandler(&fakeVerifier{subject: "sva-ci"}, azErr, &fakeBackend{}, &fakeForwarder{}, &fakeRepoReg{}),
		http.MethodPost, "/v2/reg-A/app/blobs/uploads/", true)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, "push Check-error → fail-closed 503")
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
	// src deny → 403 DENIED (mount — push-путь).
	azDeny := &fakeAuthz{allow: map[string]bool{"v_create registry_registry:reg-A": true}}
	fwDeny := &fakeForwarder{}
	hDeny := newTestHandler(&fakeVerifier{subject: "sva-ci"}, azDeny, &fakeBackend{}, fwDeny, &fakeRepoReg{})
	rec := doReq(hDeny, http.MethodPost, "/v2/reg-A/dst/blobs/uploads/?mount=sha256:x&from=reg-A/src", true)
	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Equal(t, "DENIED", pushDenyCode(t, rec))
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

	// src (reg-B) deny → 403 DENIED, блоб чужого реестра не смонтирован.
	azDeny := &fakeAuthz{allow: map[string]bool{"v_create registry_registry:reg-A": true}}
	fwDeny := &fakeForwarder{}
	hDeny := newTestHandler(&fakeVerifier{subject: "sva-ci"}, azDeny, &fakeBackend{}, fwDeny, &fakeRepoReg{})
	recDeny := doReq(hDeny, http.MethodPost, "/v2/reg-A/dst/blobs/uploads/?mount=sha256:x&from=reg-B/src", true)
	require.Equal(t, http.StatusForbidden, recDeny.Code)
	require.Equal(t, "DENIED", pushDenyCode(t, recDeny))
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
	// (без v_update на repo) → mount отклонён 403 DENIED (нельзя писать в существующий repo
	// мимо v_update), несмотря на v_get(src).
	azMismatch := &fakeAuthz{allow: map[string]bool{
		"v_get registry_repository:reg-A/src": true,
		"v_create registry_registry:reg-A":    true,
	}}
	fwMismatch := &fakeForwarder{}
	hMismatch := newTestHandler(&fakeVerifier{subject: "sva-ci"}, azMismatch, beExisting, fwMismatch, &fakeRepoReg{})
	recMismatch := doReq(hMismatch, http.MethodPost, mountURL, true)
	require.Equal(t, http.StatusForbidden, recMismatch.Code)
	require.Equal(t, "DENIED", pushDenyCode(t, recMismatch))
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

// REG-33A (#33 Defect A) — push-time blob HEAD/GET только-что-загруженного блоба,
// которого ещё НЕТ ни в одном манифесте repo (первый push пишет блобы ДО манифеста),
// НЕ должен отдавать 404. serveBlob гейтит на BlobInRepo (digest ∈ манифест repo), но
// на первом push repoTags пуст → BlobInRepo=false → раньше отдавал 404 на блоб, который
// docker только что успешно запушил (201) → docker видит «unknown blob» и рвёт push. Фикс:
// если BlobInRepo=false, но writer реально загрузил ЭТОТ digest в ЭТОТ repo (durable
// pending-blob record в пределах TTL) → forward (200), не 404. RED до фикса: 404.
func TestDataplane_REG33A_BlobHead_UploadedNotYetInManifest_Revealed(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_get registry_repository:reg-A/app": true}}
	fw := &fakeForwarder{status: 200}
	be := &fakeBackend{} // блоб ещё НЕ в манифесте repo → BlobInRepo=false
	// но writer загрузил sha256:fresh именно в reg-A/app (pending-blob record).
	up := &fakeUploadRecorder{uploaded: map[string]bool{
		uploadCacheKey("reg-A", "app", "sha256:fresh"): true,
	}}
	h := newTestHandlerU(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{}, up)

	require.Equal(t, http.StatusOK, doReq(h, http.MethodHead, "/v2/reg-A/app/blobs/sha256:fresh", true).Code,
		"HEAD только-что-загруженного (но ещё не в манифесте) блоба должен форвардиться, не 404")
	require.Equal(t, http.StatusOK, doReq(h, http.MethodGet, "/v2/reg-A/app/blobs/sha256:fresh", true).Code,
		"GET того же блоба тоже форвардится")
	require.Equal(t, 2, fw.count(), "оба запроса проксированы в zot")
}

// REG-33A regression-lock (REG-37 сохранён) — блоб, который НЕ загружен в этот repo И
// НЕ входит в его манифесты, обязан ОСТАВАТЬСЯ 404 (existence-hiding). Это ключевой
// security-инвариант: pending-reveal не должен превратиться в тот самый cross-tenant
// blob-leak, ради закрытия которого существует BlobInRepo (zot дедуплицирует блобы
// глобально — HEAD чужого глобального блоба из любого repo вернул бы 200). Должен быть
// ЗЕЛЁНЫМ и до, и после фикса.
func TestDataplane_REG33A_BlobHead_NotUploadedNotInManifest_Still404(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_get registry_repository:reg-A/app": true}}
	fw := &fakeForwarder{}
	be := &fakeBackend{}        // не в манифесте
	up := &fakeUploadRecorder{} // не загружен в этот repo
	h := newTestHandlerU(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{}, up)

	require.Equal(t, http.StatusNotFound, doReq(h, http.MethodHead, "/v2/reg-A/app/blobs/sha256:foreign", true).Code)
	require.Equal(t, http.StatusNotFound, doReq(h, http.MethodGet, "/v2/reg-A/app/blobs/sha256:foreign", true).Code)
	require.Equal(t, 0, fw.count(), "чужой блоб не проксируется")
}

// REG-33A cross-repo regression-lock — pending-record строго per-repo: блоб, загруженный
// в reg-A/app, НЕ должен раскрываться из ДРУГОГО repo (reg-A/other или reg-B/app), даже
// если у вызывающего есть v_get на тот другой repo. Иначе pending-reveal стал бы
// cross-repo blob-oracle. Должен быть ЗЕЛЁНЫМ и до, и после фикса.
func TestDataplane_REG33A_BlobHead_UploadedToOtherRepo_Still404(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{
		"v_get registry_repository:reg-A/other": true,
		"v_get registry_repository:reg-B/app":   true,
	}}
	fw := &fakeForwarder{}
	be := &fakeBackend{}
	// digest загружен только в reg-A/app.
	up := &fakeUploadRecorder{uploaded: map[string]bool{
		uploadCacheKey("reg-A", "app", "sha256:secret"): true,
	}}
	h := newTestHandlerU(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{}, up)

	require.Equal(t, http.StatusNotFound, doReq(h, http.MethodHead, "/v2/reg-A/other/blobs/sha256:secret", true).Code,
		"блоб reg-A/app не раскрывается из reg-A/other")
	require.Equal(t, http.StatusNotFound, doReq(h, http.MethodHead, "/v2/reg-B/app/blobs/sha256:secret", true).Code,
		"блоб reg-A/app не раскрывается из reg-B/app")
	require.Equal(t, 0, fw.count())
}

// REG-33A — blob PUT-finalize (routeUpload, PUT, ?digest=<d>) с 2xx от zot ОБЯЗАН
// синхронно записать (registryID, repo, digest) ДО релея 201 клиенту (docker может
// сделать HEAD сразу за 201 — строка должна закоммититься первой). Запись идёт на
// detached-контексте (переживает отмену запроса). RED до фикса: finalize идёт
// стриминговым Forward, RecordUploadedBlob не зовётся → recordedKeys пуст.
func TestDataplane_REG33A_BlobPutFinalize_RecordsUploadedBlob(t *testing.T) {
	// finalize нового repo гейтится v_create@namespace; последующий push-time HEAD того
	// же блоба гейтится v_get@repo (авторизация repo здесь дана — тест изолирует именно
	// blob-scope reveal, а не materialization per-repo verbs, см. Defect B).
	az := &fakeAuthz{allow: map[string]bool{
		"v_create registry_registry:reg-A":    true,
		"v_get registry_repository:reg-A/app": true,
	}}
	fw := &fakeForwarder{status: 201}
	be := &fakeBackend{exists: map[string]bool{}} // новый repo → verb-map v_create@namespace
	up := &fakeUploadRecorder{}
	h := newTestHandlerU(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{}, up)

	rec := doReq(h, http.MethodPut, "/v2/reg-A/app/blobs/uploads/upl-uuid-1?digest=sha256:layerA", true)
	require.Equal(t, 201, rec.Code, "blob-finalize 2xx релеится клиенту")
	require.Equal(t, []uploadKey{{"reg-A", "app", "sha256:layerA"}}, up.recordedKeys(),
		"finalize записывает (reg,repo,digest) ровно один раз")
	require.NoError(t, up.observedRecCtxErr(),
		"durable-запись исполняется на detached-контексте (переживает отмену запроса)")

	// records → последующий HEAD раскрывает блоб (BlobInRepo=false, но pending=true) →
	// форвардится в zot (fake echoes fw.status), НЕ 404.
	headCode := doReq(h, http.MethodHead, "/v2/reg-A/app/blobs/sha256:layerA", true).Code
	require.NotEqual(t, http.StatusNotFound, headCode, "записанный блоб раскрывается по HEAD, не 404")
	require.Less(t, headCode, 400, "HEAD форвардится в zot после записи pending-строки")
}

// REG-33A — finalize в СУЩЕСТВУЮЩИЙ repo (verb-map v_update) тоже записывает блоб.
func TestDataplane_REG33A_BlobPutFinalize_ExistingRepo_Records(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_update registry_repository:reg-A/app": true}}
	fw := &fakeForwarder{status: 201}
	be := &fakeBackend{exists: map[string]bool{"reg-A/app": true}}
	up := &fakeUploadRecorder{}
	h := newTestHandlerU(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{}, up)

	rec := doReq(h, http.MethodPut, "/v2/reg-A/app/blobs/uploads/upl-2?digest=sha256:layerB", true)
	require.Equal(t, 201, rec.Code)
	require.Equal(t, []uploadKey{{"reg-A", "app", "sha256:layerB"}}, up.recordedKeys())
}

// REG-33A — монолитный blob-upload одним POST /blobs/uploads/?digest=<d> (без mount)
// тоже финализирует блоб → записывается. (docker/moby идёт POST→PUT, но OCI допускает
// single-POST; guard не должен зависеть от клиента.)
func TestDataplane_REG33A_BlobPostMonolithicFinalize_Records(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_create registry_registry:reg-A": true}}
	fw := &fakeForwarder{status: 201}
	be := &fakeBackend{exists: map[string]bool{}}
	up := &fakeUploadRecorder{}
	h := newTestHandlerU(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{}, up)

	rec := doReq(h, http.MethodPost, "/v2/reg-A/app/blobs/uploads/?digest=sha256:mono", true)
	require.Equal(t, 201, rec.Code)
	require.Equal(t, []uploadKey{{"reg-A", "app", "sha256:mono"}}, up.recordedKeys())
}

// REG-33A — blob-finalize с НЕ-2xx от zot (напр. 400 digest-invalid: контент не совпал
// с ?digest) НЕ записывает pending-строку (writer не доказал владение контентом) и
// релеит ответ zot как есть.
func TestDataplane_REG33A_BlobPutFinalize_ZotReject_NoRecord(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_create registry_registry:reg-A": true}}
	fw := &fakeForwarder{status: 400}
	be := &fakeBackend{exists: map[string]bool{}}
	up := &fakeUploadRecorder{}
	h := newTestHandlerU(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{}, up)

	rec := doReq(h, http.MethodPut, "/v2/reg-A/app/blobs/uploads/upl-3?digest=sha256:bad", true)
	require.Equal(t, 400, rec.Code, "не-2xx zot релеится как есть")
	require.Empty(t, up.recordedKeys(), "не-2xx finalize не записывает pending-строку")
}

// REG-33A — durable-запись blob-finalize упала (транзиентный DB-сбой). Мы НЕ можем
// безопасно отдать 201, который клиент запомнит, а следующий HEAD вернёт 404 (реинтро
// Defect A). Fail-closed: 503, 201 НЕ релеится → push ретраится (upload идемпотентен;
// на ретрае zot уже дедуплицировал блоб). Регресс-гейт против «record fail тихо
// проглочен, 201 отдан».
func TestDataplane_REG33A_BlobPutFinalize_RecordError_FailClosed(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_create registry_registry:reg-A": true}}
	fw := &fakeForwarder{status: 201}
	be := &fakeBackend{exists: map[string]bool{}}
	up := &fakeUploadRecorder{recErr: errors.New("pg down")}
	h := newTestHandlerU(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{}, up)

	rec := doReq(h, http.MethodPut, "/v2/reg-A/app/blobs/uploads/upl-4?digest=sha256:x", true)
	require.GreaterOrEqual(t, rec.Code, 500, "record-сбой → fail-closed 5xx, не 201")
	require.NotEqual(t, 201, rec.Code, "201 не релеится при незакоммиченной pending-строке")
}

// REG-33A — неавторизованный blob-finalize отклоняется verb-map Check'ом (v_create/
// v_update) ДО ForwardCapture: 403 DENIED (push-deny униформно), блоб в zot не уходит,
// pending не пишется. Записываем ТОЛЬКО после passed-authz.
func TestDataplane_REG33A_BlobPutFinalize_NoRights_403Denied_NoRecord(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{}} // deny всё
	fw := &fakeForwarder{status: 201}
	be := &fakeBackend{exists: map[string]bool{}}
	up := &fakeUploadRecorder{}
	h := newTestHandlerU(&fakeVerifier{subject: "sva-evil"}, az, be, fw, &fakeRepoReg{}, up)

	rec := doReq(h, http.MethodPut, "/v2/reg-A/app/blobs/uploads/upl-5?digest=sha256:x", true)
	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Equal(t, "DENIED", pushDenyCode(t, rec))
	require.Equal(t, 0, fw.count(), "неавторизованный finalize не проксируется")
	require.Empty(t, up.recordedKeys(), "неавторизованный finalize не пишет pending-строку")
}

// REG-33B (#33 Defect B — deadlock) — push-time blob HEAD/GET нового repo. На первом
// push blob-upload гейтится v_create@registry_registry (namespace), но per-object
// registry_repository authz-объект материализуется ТОЛЬКО на успешном manifest-PUT
// (register-on-first-push). Docker делает HEAD блоба ДО манифеста → v_get@repo denies
// (объект ещё не существует) → serveBlob раньше отдавал 404 ДО pending-record проверки →
// docker рвёт push «unknown blob». Круговой дедлок: repo не материализован ⟸ манифест не
// запушен ⟸ blob HEAD 404 ⟸ repo не материализован. Фикс: на v_get-deny fallback раскрывает
// блоб ⟺ (a) repo ещё НЕ материализован (RepoExists=false), (b) caller держит
// v_create@namespace (то же право, что авторизовало upload), (c) ЭТОТ digest доказуемо
// загружен в ЭТОТ repo (pending-record). RED до фикса: 404. После фикса: forward (200).
func TestDataplane_REG33B_BlobHead_NewRepoVGetDenied_PushContextReveals(t *testing.T) {
	// НОВЫЙ repo: v_get@repo НЕ материализован (denied), но caller держит
	// v_create@namespace И блоб загружен в этот repo (pending) → deadlock-фикс раскрывает.
	az := &fakeAuthz{allow: map[string]bool{"v_create registry_registry:reg-A": true}}
	fw := &fakeForwarder{status: 200}
	be := &fakeBackend{exists: map[string]bool{}} // repo ещё не материализован (RepoExists=false)
	up := &fakeUploadRecorder{uploaded: map[string]bool{
		uploadCacheKey("reg-A", "app", "sha256:fresh"): true,
	}}
	h := newTestHandlerU(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{}, up)

	require.Equal(t, http.StatusOK, doReq(h, http.MethodHead, "/v2/reg-A/app/blobs/sha256:fresh", true).Code,
		"push-time HEAD нового repo раскрывается через push-context fallback, не 404")
	require.Equal(t, http.StatusOK, doReq(h, http.MethodGet, "/v2/reg-A/app/blobs/sha256:fresh", true).Code,
		"GET того же блоба тоже раскрывается (тот же тенант, свой только-что-загруженный блоб)")
	require.Equal(t, 2, fw.count(), "оба запроса проксированы в zot через fallback")
}

// REG-33B cross-tenant regression (REG-37 сохранён) — v_get@repo denied И caller НЕ
// держит v_create на ЭТОТ registry (право только на ДРУГОЙ реестр). Даже если блоб
// глобально существует в zot и «в pending» — fallback denies → 404. Ключевой
// security-инвариант: fallback раскрывает ТОЛЬКО блобы того, кто может пушить в этот
// registry (v_create = тот же проект/тенант). Cross-tenant caller лишён v_create → 404.
func TestDataplane_REG33B_BlobHead_CrossTenant_NoVCreate_Still404(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_create registry_registry:reg-OTHER": true}}
	fw := &fakeForwarder{}
	be := &fakeBackend{exists: map[string]bool{}}
	up := &fakeUploadRecorder{uploaded: map[string]bool{
		uploadCacheKey("reg-A", "app", "sha256:fresh"): true, // блоб реально загружен в reg-A/app
	}}
	h := newTestHandlerU(&fakeVerifier{subject: "sva-evil"}, az, be, fw, &fakeRepoReg{}, up)

	require.Equal(t, http.StatusNotFound, doReq(h, http.MethodHead, "/v2/reg-A/app/blobs/sha256:fresh", true).Code,
		"cross-tenant HEAD без v_create на этот registry → 404 (не раскрываем)")
	require.Equal(t, http.StatusNotFound, doReq(h, http.MethodGet, "/v2/reg-A/app/blobs/sha256:fresh", true).Code,
		"cross-tenant GET тоже 404")
	require.Equal(t, 0, fw.count(), "cross-tenant блоб не проксируется")
}

// REG-33B regression — v_get denied, v_create@namespace allowed, но блоб НЕ в pending
// (writer не загружал ЭТОТ digest в ЭТОТ repo). Fallback denies → 404: право пушить в
// namespace НЕ раскрывает произвольный глобальный блоб — нужен доказанный upload именно
// этого контента в этот repo (zot проверил digest на finalize).
func TestDataplane_REG33B_BlobHead_VCreateAllowed_NotInPending_Still404(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_create registry_registry:reg-A": true}}
	fw := &fakeForwarder{}
	be := &fakeBackend{exists: map[string]bool{}}
	up := &fakeUploadRecorder{} // ничего не загружено → pending=false
	h := newTestHandlerU(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{}, up)

	require.Equal(t, http.StatusNotFound, doReq(h, http.MethodHead, "/v2/reg-A/app/blobs/sha256:notmine", true).Code,
		"v_create есть, но блоб не в pending → 404")
	require.Equal(t, http.StatusNotFound, doReq(h, http.MethodGet, "/v2/reg-A/app/blobs/sha256:notmine", true).Code)
	require.Equal(t, 0, fw.count(), "не-загруженный блоб не раскрывается")
}

// REG-33B regression — repo УЖЕ материализован (RepoExists=true), но caller лишён v_get
// (чужой/revoked reader). Fallback НЕ применяется: exists=true → это ЛЕГИТИМНЫЙ deny
// established repo, а не first-push дедлок. 404 даже при наличии v_create И pending-record
// (иначе fallback стал бы обходом revoke на established repo).
func TestDataplane_REG33B_BlobHead_RepoExists_VGetDenied_Still404(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_create registry_registry:reg-A": true}}
	fw := &fakeForwarder{}
	be := &fakeBackend{exists: map[string]bool{"reg-A/app": true}} // established repo
	up := &fakeUploadRecorder{uploaded: map[string]bool{
		uploadCacheKey("reg-A", "app", "sha256:x"): true,
	}}
	h := newTestHandlerU(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{}, up)

	require.Equal(t, http.StatusNotFound, doReq(h, http.MethodHead, "/v2/reg-A/app/blobs/sha256:x", true).Code,
		"established repo + v_get denied → 404, fallback не применяется (не обход revoke)")
	require.Equal(t, http.StatusNotFound, doReq(h, http.MethodGet, "/v2/reg-A/app/blobs/sha256:x", true).Code)
	require.Equal(t, 0, fw.count())
}

// REG-33B regression — established repo, v_get ALLOWED → forward штатным путём БЕЗ
// fallback: ровно один authz-Check (v_get), никаких лишних RepoExists/v_create на
// hot pull-пути. Локает «нулевая добавленная стоимость на established pull».
func TestDataplane_REG33B_BlobHead_EstablishedRepo_VGetAllowed_NoFallbackCost(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_get registry_repository:reg-A/app": true}}
	fw := &fakeForwarder{status: 200}
	be := &fakeBackend{blobs: map[string]bool{"reg-A/app|sha256:own": true}} // блоб входит в манифест
	up := &fakeUploadRecorder{}
	h := newTestHandlerU(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{}, up)

	require.Equal(t, http.StatusOK, doReq(h, http.MethodGet, "/v2/reg-A/app/blobs/sha256:own", true).Code)
	require.Equal(t, 1, fw.count())
	require.Len(t, az.checkedObjects(), 1,
		"established pull делает ровно один Check (v_get) — fallback не трогается, нулевая добавленная стоимость")
}

// REG-33B — зависимость fallback недоступна на v_get-deny ветке: RepoExists падает →
// fail-closed 503 (не гадаем 404/200 при недоступном zot). Exercised именно ветка
// fallback (v_get denied без az.err, ошибка приходит из RepoExists внутри fallback).
func TestDataplane_REG33B_BlobHead_FallbackRepoExistsError_FailClosed(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{}} // v_get denied (без az-ошибки)
	fw := &fakeForwarder{}
	be := &fakeBackend{existsErr: errors.New("zot down")}
	up := &fakeUploadRecorder{}
	h := newTestHandlerU(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{}, up)

	rec := doReq(h, http.MethodHead, "/v2/reg-A/app/blobs/sha256:x", true)
	require.GreaterOrEqual(t, rec.Code, 500, "fallback RepoExists error → fail-closed 5xx")
	require.NotEqual(t, http.StatusNotFound, rec.Code, "недоступность зависимости не маскируется под 404")
	require.Equal(t, 0, fw.count())
}

// REG-33B — v_create Check внутри fallback падает → fail-closed 503 (не 404/200).
func TestDataplane_REG33B_BlobHead_FallbackVCreateCheckError_FailClosed(t *testing.T) {
	// v_get denied через allow-map (Check(v_get)=false, без ошибки), но v_create-Check
	// падает. fakeAuthz.err применяется ко ВСЕМ Check — поэтому используем backend без
	// ошибок и специальный authz, который ошибается только на v_create.
	az := &vCreateErrAuthz{allowGet: false, vCreateErr: errors.New("iam down")}
	fw := &fakeForwarder{}
	be := &fakeBackend{exists: map[string]bool{}}
	up := &fakeUploadRecorder{}
	h := newTestHandlerU(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{}, up)

	rec := doReq(h, http.MethodHead, "/v2/reg-A/app/blobs/sha256:x", true)
	require.GreaterOrEqual(t, rec.Code, 500, "fallback v_create Check error → fail-closed 5xx")
	require.Equal(t, 0, fw.count())
}

// REG-33B — pending-record проверка внутри fallback падает → fail-closed 503.
func TestDataplane_REG33B_BlobHead_FallbackPendingError_FailClosed(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_create registry_registry:reg-A": true}}
	fw := &fakeForwarder{}
	be := &fakeBackend{exists: map[string]bool{}}
	up := &fakeUploadRecorder{getErr: errors.New("pg down")}
	h := newTestHandlerU(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{}, up)

	rec := doReq(h, http.MethodHead, "/v2/reg-A/app/blobs/sha256:x", true)
	require.GreaterOrEqual(t, rec.Code, 500, "fallback pending-check error → fail-closed 5xx")
	require.Equal(t, 0, fw.count())
}

// ============================================================================
// REG-33 immediate-pull (#33): push-ownership fallback — собственный `docker pull`
// толкавшего сразу за push НЕ должен возвращать 404, пока async register-on-first-push
// не материализовал per-repo v_get в FGA (~10-15s на проде). На успешном manifest-PUT
// пишется push-grant (registryID, repo, subject); pull-path раскрывает repo ИМЕННО
// толкавшему, пока FGA не догнал. Ключ по subject → чужой subject/тенант → 404 (REG-37).
// ============================================================================

// REG-33IP — pull манифеста repo, который caller только что запушил (push-grant есть),
// но v_get@repo ещё DENIED (не материализован) → раньше 404, после фикса форвардится (200).
// RED до фикса: servePullOnly отдаёт 404 на v_get-deny без консультации push-grant.
func TestDataplane_REG33IP_PullManifest_PushGrantedVGetDenied_Reveals(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{}} // v_get denied (ещё не материализован)
	fw := &fakeForwarder{status: 200}
	pgr := &fakePushGrantRecorder{granted: map[string]bool{
		pushGrantCacheKey("reg-A", "app", "service_account:sva-ci"): true,
	}}
	h := newTestHandlerPG(&fakeVerifier{subject: "sva-ci"}, az, &fakeBackend{}, fw, &fakeRepoReg{}, &fakeUploadRecorder{}, pgr)

	require.Equal(t, http.StatusOK, doReq(h, http.MethodGet, "/v2/reg-A/app/manifests/v1", true).Code,
		"толкавший тянет свой только-что-запушенный repo в окне материализации → forward, не 404")
	require.Equal(t, http.StatusOK, doReq(h, http.MethodHead, "/v2/reg-A/app/manifests/v1", true).Code,
		"HEAD того же манифеста тоже раскрывается")
	require.Equal(t, 2, fw.count(), "оба запроса проксированы через push-ownership fallback")
}

// REG-33IP — tags/list репо толкавшего с v_list DENIED, но push-grant есть → forward.
func TestDataplane_REG33IP_TagsList_PushGrantedVListDenied_Reveals(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{}} // v_list denied
	fw := &fakeForwarder{status: 200}
	pgr := &fakePushGrantRecorder{granted: map[string]bool{
		pushGrantCacheKey("reg-A", "app", "service_account:sva-ci"): true,
	}}
	h := newTestHandlerPG(&fakeVerifier{subject: "sva-ci"}, az, &fakeBackend{}, fw, &fakeRepoReg{}, &fakeUploadRecorder{}, pgr)
	require.Equal(t, http.StatusOK, doReq(h, http.MethodGet, "/v2/reg-A/app/tags/list", true).Code,
		"tags/list собственного только-что-запушенного repo раскрывается через push-grant")
	require.Equal(t, 1, fw.count())
}

// REG-33IP — blob GET/HEAD собственного repo: v_get DENIED, repo УЖЕ материализован в zot
// (RepoExists=true → pushContextRevealsBlob неприменим), push-grant есть, блоб — член
// манифеста (BlobInRepo=true) → forward. Это ключевой путь `docker pull`: после манифеста
// docker тянет config+слои. RED до фикса: serveBlob 404 (pushContextRevealsBlob=false,
// push-owner fallback отсутствует).
func TestDataplane_REG33IP_Blob_PushGrantedVGetDenied_MemberBlob_Reveals(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{}} // v_get denied
	fw := &fakeForwarder{status: 200}
	be := &fakeBackend{
		exists: map[string]bool{"reg-A/app": true},            // repo материализован в zot (манифест запушен)
		blobs:  map[string]bool{"reg-A/app|sha256:own": true}, // блоб входит в манифест repo
	}
	pgr := &fakePushGrantRecorder{granted: map[string]bool{
		pushGrantCacheKey("reg-A", "app", "service_account:sva-ci"): true,
	}}
	h := newTestHandlerPG(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{}, &fakeUploadRecorder{}, pgr)

	require.Equal(t, http.StatusOK, doReq(h, http.MethodGet, "/v2/reg-A/app/blobs/sha256:own", true).Code,
		"толкавший тянет член-блоб своего repo в окне материализации → forward")
	require.Equal(t, http.StatusOK, doReq(h, http.MethodHead, "/v2/reg-A/app/blobs/sha256:own", true).Code)
	require.Equal(t, 2, fw.count())
}

// REG-33IP security regression (REG-37 сохранён) — push-grant раскрывает repo, но serveBlob
// ДОПОЛНИТЕЛЬНО держит blob-scope: чужой глобальный content-addressable блоб, которого НЕТ
// ни в манифесте repo, ни среди загруженных в него, ОБЯЗАН оставаться 404 даже для толкавшего.
// Иначе push-grant стал бы cross-tenant blob-oracle (zot дедуплицирует блобы глобально).
// Должен быть ЗЕЛЁНЫМ после фикса (до фикса — тоже 404, т.к. fallback отсутствует).
func TestDataplane_REG33IP_Blob_PushGranted_ForeignBlob_Still404(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{}} // v_get denied
	fw := &fakeForwarder{}
	be := &fakeBackend{exists: map[string]bool{"reg-A/app": true}} // repo материализован, но digest не член
	pgr := &fakePushGrantRecorder{granted: map[string]bool{
		pushGrantCacheKey("reg-A", "app", "service_account:sva-ci"): true,
	}}
	up := &fakeUploadRecorder{} // и не загружен в этот repo
	h := newTestHandlerPG(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{}, up, pgr)

	require.Equal(t, http.StatusNotFound, doReq(h, http.MethodGet, "/v2/reg-A/app/blobs/sha256:foreign", true).Code,
		"push-grant раскрывает repo, но НЕ произвольный глобальный блоб (REG-37 сохранён)")
	require.Equal(t, http.StatusNotFound, doReq(h, http.MethodHead, "/v2/reg-A/app/blobs/sha256:foreign", true).Code)
	require.Equal(t, 0, fw.count())
}

// REG-33IP — успешный manifest-PUT НОВОГО repo записывает push-grant (keyed by pushing
// subject) на detached-контексте. RED до фикса: RecordPushGrant не зовётся → recordedKeys пуст.
func TestDataplane_REG33IP_RecordPushGrant_OnManifestPut_NewRepo(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_create registry_registry:reg-A": true}}
	fw := &fakeForwarder{status: 201}
	be := &fakeBackend{exists: map[string]bool{}} // новый repo
	pgr := &fakePushGrantRecorder{}
	h := newTestHandlerPG(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{}, &fakeUploadRecorder{}, pgr)

	up := doReq(h, http.MethodPost, "/v2/reg-A/app/blobs/uploads/", true)
	require.Equal(t, 201, up.Code)
	require.Empty(t, pgr.recordedKeys(), "blob-upload init не пишет push-grant (только manifest-PUT)")

	mf := doReq(h, http.MethodPut, "/v2/reg-A/app/manifests/v1", true)
	require.Equal(t, 201, mf.Code)
	require.Equal(t, []pushGrantKey{{"reg-A", "app", "service_account:sva-ci"}}, pgr.recordedKeys(),
		"успешный manifest-PUT пишет push-grant ровно один раз, keyed by pushing subject")
	require.NoError(t, pgr.observedRecCtxErr(),
		"push-grant пишется на detached-контексте (переживает разрыв соединения клиентом на 201)")
}

// REG-33IP — re-push в СУЩЕСТВУЮЩИЙ repo тоже пишет/освежает push-grant (не только новый repo).
func TestDataplane_REG33IP_RecordPushGrant_OnManifestPut_ExistingRepo(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_update registry_repository:reg-A/app": true}}
	fw := &fakeForwarder{status: 201}
	be := &fakeBackend{exists: map[string]bool{"reg-A/app": true}} // существующий repo (re-push)
	pgr := &fakePushGrantRecorder{}
	h := newTestHandlerPG(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{}, &fakeUploadRecorder{}, pgr)

	mf := doReq(h, http.MethodPut, "/v2/reg-A/app/manifests/v2", true)
	require.Equal(t, 201, mf.Code)
	require.Equal(t, []pushGrantKey{{"reg-A", "app", "service_account:sva-ci"}}, pgr.recordedKeys(),
		"re-push существующего repo тоже пишет/освежает push-grant")
}

// REG-33IP — manifest-PUT, отвергнутый zot (не-2xx), НЕ пишет push-grant.
func TestDataplane_REG33IP_ManifestPut_ZotReject_NoRecord(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_create registry_registry:reg-A": true}}
	fw := &fakeForwarder{status: 400} // zot отверг манифест
	be := &fakeBackend{exists: map[string]bool{}}
	pgr := &fakePushGrantRecorder{}
	h := newTestHandlerPG(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{}, &fakeUploadRecorder{}, pgr)
	mf := doReq(h, http.MethodPut, "/v2/reg-A/app/manifests/v1", true)
	require.Equal(t, 400, mf.Code)
	require.Empty(t, pgr.recordedKeys(), "не-2xx manifest-PUT не пишет push-grant")
}

// REG-33IP — запись push-grant упала (транзиентный DB-сбой). В отличие от blob-finalize
// (Defect A, fail-closed), push-grant — НЕ критичный путь: manifest уже в zot, push
// по сути завершён. Log-and-continue (как register-on-first-push emit failure): клиент
// получает свой 2xx, сбой наблюдаемо логируется. Худший исход — немедленный pull может
// разок упереться в pre-fix окно материализации (не НОВАЯ регрессия). RED-инвариант:
// НЕ fail-closed на push (не рвём завершённый push из-за сбоя вспомогательного кеша).
func TestDataplane_REG33IP_RecordPushGrantFailure_PushStill2xx_Logged(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_create registry_registry:reg-A": true}}
	fw := &fakeForwarder{status: 201}
	be := &fakeBackend{exists: map[string]bool{}}
	pgr := &fakePushGrantRecorder{recErr: errors.New("pg down")}
	var logbuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logbuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h := New(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{}, &fakeRegistryLookup{}, &fakeUploadRecorder{}, pgr,
		"https://api.kacho.local/iam/token", "registry.kacho.local", logger)

	mf := doReq(h, http.MethodPut, "/v2/reg-A/app/manifests/v1", true)
	require.Equal(t, 201, mf.Code, "push 2xx форвардится несмотря на сбой push-grant record (кеш, не критичный путь)")
	require.Contains(t, logbuf.String(), "push-grant record failed", "сбой push-grant record наблюдаемо залогирован")
}

// REG-33IP regression — non-pusher субъект с v_get DENIED и БЕЗ push-grant → остаётся 404
// (легитимный revoke / cross-tenant). Мост НЕ ослабляет existence-hiding для не-толкавших.
func TestDataplane_REG33IP_NonPusher_VGetDenied_NoPushGrant_Still404(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{}} // v_get/v_list denied
	fw := &fakeForwarder{}
	be := &fakeBackend{exists: map[string]bool{"reg-A/app": true}}
	pgr := &fakePushGrantRecorder{} // нет push-grant для этого субъекта
	h := newTestHandlerPG(&fakeVerifier{subject: "sva-evil"}, az, be, fw, &fakeRepoReg{}, &fakeUploadRecorder{}, pgr)

	require.Equal(t, http.StatusNotFound, doReq(h, http.MethodGet, "/v2/reg-A/app/manifests/v1", true).Code,
		"non-pusher без push-grant → 404 (revoke/cross-tenant сохранён)")
	require.Equal(t, http.StatusNotFound, doReq(h, http.MethodGet, "/v2/reg-A/app/tags/list", true).Code)
	require.Equal(t, http.StatusNotFound, doReq(h, http.MethodGet, "/v2/reg-A/app/blobs/sha256:x", true).Code)
	require.Equal(t, 0, fw.count())
}

// REG-33IP regression (cross-tenant, ключевой инвариант) — push-grant СУЩЕСТВУЕТ, но для
// ДРУГОГО субъекта (легитимного толкавшего sva-ci); чужой sva-evil с v_get DENIED тянет тот
// же repo → 404. Доказывает subject-keying: мост раскрывает ТОЛЬКО собственный repo
// толкавшего, не «любой недавно запушенный repo».
func TestDataplane_REG33IP_CrossSubject_PushGrantForOther_Still404(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{}} // v_get denied для sva-evil
	fw := &fakeForwarder{}
	be := &fakeBackend{exists: map[string]bool{"reg-A/app": true}}
	pgr := &fakePushGrantRecorder{granted: map[string]bool{
		pushGrantCacheKey("reg-A", "app", "service_account:sva-ci"): true, // grant для ЛЕГИТИМНОГО толкавшего
	}}
	h := newTestHandlerPG(&fakeVerifier{subject: "sva-evil"}, az, be, fw, &fakeRepoReg{}, &fakeUploadRecorder{}, pgr)

	require.Equal(t, http.StatusNotFound, doReq(h, http.MethodGet, "/v2/reg-A/app/manifests/v1", true).Code,
		"push-grant кейован по subject → чужой субъект не раскрывается (cross-tenant / REG-37)")
	require.Equal(t, http.StatusNotFound, doReq(h, http.MethodGet, "/v2/reg-A/app/blobs/sha256:own", true).Code)
	require.Equal(t, 0, fw.count())
}

// REG-33IP regression — established repo, v_get ALLOWED → forward штатным путём БЕЗ
// консультации push-grant (нулевая добавленная стоимость на hot established-pull).
func TestDataplane_REG33IP_EstablishedRepo_VGetAllowed_NoFallbackCost(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_get registry_repository:reg-A/app": true}}
	fw := &fakeForwarder{status: 200}
	pgr := &fakePushGrantRecorder{granted: map[string]bool{
		pushGrantCacheKey("reg-A", "app", "service_account:sva-ci"): true,
	}}
	h := newTestHandlerPG(&fakeVerifier{subject: "sva-ci"}, az, &fakeBackend{}, fw, &fakeRepoReg{}, &fakeUploadRecorder{}, pgr)

	require.Equal(t, http.StatusOK, doReq(h, http.MethodGet, "/v2/reg-A/app/manifests/v1", true).Code)
	require.Equal(t, 1, fw.count())
	require.Equal(t, 0, pgr.getCalls,
		"established v_get-allowed pull НЕ консультирует push-grant fallback (нулевая добавленная стоимость)")
}

// REG-33IP — push-grant fallback недоступен на pull-path (PushGranted падает) → fail-closed
// 5xx (не гадаем 404/200 при недоступной БД). servePullOnly-ветка.
func TestDataplane_REG33IP_PullManifest_PushGrantFallbackError_FailClosed(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{}} // v_get denied (без az-ошибки)
	fw := &fakeForwarder{}
	pgr := &fakePushGrantRecorder{getErr: errors.New("pg down")}
	h := newTestHandlerPG(&fakeVerifier{subject: "sva-ci"}, az, &fakeBackend{}, fw, &fakeRepoReg{}, &fakeUploadRecorder{}, pgr)

	rec := doReq(h, http.MethodGet, "/v2/reg-A/app/manifests/v1", true)
	require.GreaterOrEqual(t, rec.Code, 500, "push-grant fallback error → fail-closed 5xx")
	require.NotEqual(t, http.StatusNotFound, rec.Code, "недоступность зависимости не маскируется под 404")
	require.Equal(t, 0, fw.count())
}

// REG-33IP — push-grant fallback недоступен на serveBlob push-owner ветке → fail-closed 5xx.
func TestDataplane_REG33IP_Blob_PushGrantFallbackError_FailClosed(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{}} // v_get denied
	fw := &fakeForwarder{}
	be := &fakeBackend{exists: map[string]bool{"reg-A/app": true}} // materialized → pushContextRevealsBlob=false, доходим до push-owner
	pgr := &fakePushGrantRecorder{getErr: errors.New("pg down")}
	h := newTestHandlerPG(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{}, &fakeUploadRecorder{}, pgr)

	rec := doReq(h, http.MethodHead, "/v2/reg-A/app/blobs/sha256:x", true)
	require.GreaterOrEqual(t, rec.Code, 500, "serveBlob push-owner fallback error → fail-closed 5xx")
	require.Equal(t, 0, fw.count())
}

// ============================================================================
// REG-33 immediate-pull revoke-safety (#33): push-grant-мост обязан жить ТОЛЬКО окно
// материализации per-repo authz, а НЕ переживать revoke до истечения TTL. Два ограничителя:
//   (1) delete-on-materialized — как только pull-path v_get/v_list ALLOW'нул (реальный
//       per-repo authz материализовался в FGA), push-grant удаляется; последующий revoke →
//       v_get denies → записи нет → 404;
//   (2) короткий TTL-backstop (config, отдельные тесты) — ограничивает худший случай.
// Регресс (до фикса, LIVE на проде): push-grant (TTL=1h) раскрывал repo и ПОСЛЕ revoke до
// 1h — отозванный субъект тянул образ (в т.ч. чужой контент в том же repo) → stale-access leak.
// ============================================================================

// waitDelete детерминированно ждёт async delete-on-materialized (goroutine хендлера шлёт ключ
// в delCh); timeout → чистый провал (не hang). Возвращает удалённый ключ.
func waitDelete(t *testing.T, ch <-chan pushGrantKey) pushGrantKey {
	t.Helper()
	select {
	case k := <-ch:
		return k
	case <-time.After(2 * time.Second):
		t.Fatal("delete-on-materialized не сработал: DeletePushGrant не вызван на v_get/v_list-allow pull")
		return pushGrantKey{}
	}
}

// REG-33IP revoke-safety (a): pull манифеста с v_get ALLOWED (per-repo authz материализовался)
// → forward 200 И delete-on-materialized снимает push-grant (reg,repo,subject) на detached-ctx.
// RED до фикса: allow-ветка servePullOnly не зовёт DeletePushGrant → waitDelete таймаутит.
func TestDataplane_REG33IP_DeleteOnMaterialized_Manifest_VGetAllowed_DropsPushGrant(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_get registry_repository:reg-A/app": true}} // материализован
	fw := &fakeForwarder{status: 200}
	pgr := &fakePushGrantRecorder{
		granted: map[string]bool{pushGrantCacheKey("reg-A", "app", "service_account:sva-ci"): true},
		delCh:   make(chan pushGrantKey, 1),
	}
	h := newTestHandlerPG(&fakeVerifier{subject: "sva-ci"}, az, &fakeBackend{}, fw, &fakeRepoReg{}, &fakeUploadRecorder{}, pgr)

	require.Equal(t, http.StatusOK, doReq(h, http.MethodGet, "/v2/reg-A/app/manifests/v1", true).Code,
		"v_get ALLOWED → штатный forward")
	require.Equal(t, pushGrantKey{"reg-A", "app", "service_account:sva-ci"}, waitDelete(t, pgr.delCh),
		"v_get-allow снимает push-grant-мост ровно для (reg,repo,subject)")
	require.NoError(t, pgr.observedDelCtxErr(),
		"delete идёт на detached-ctx (переживает разрыв соединения клиентом за pull-ответом)")
	require.Equal(t, []pushGrantKey{{"reg-A", "app", "service_account:sva-ci"}}, pgr.deletedKeys())
	require.Equal(t, 1, fw.count())
}

// REG-33IP revoke-safety — blob GET с v_get ALLOWED (member-блоб) тоже снимает push-grant.
func TestDataplane_REG33IP_DeleteOnMaterialized_Blob_VGetAllowed_DropsPushGrant(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_get registry_repository:reg-A/app": true}}
	fw := &fakeForwarder{status: 200}
	be := &fakeBackend{
		exists: map[string]bool{"reg-A/app": true},
		blobs:  map[string]bool{"reg-A/app|sha256:own": true},
	}
	pgr := &fakePushGrantRecorder{
		granted: map[string]bool{pushGrantCacheKey("reg-A", "app", "service_account:sva-ci"): true},
		delCh:   make(chan pushGrantKey, 1),
	}
	h := newTestHandlerPG(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{}, &fakeUploadRecorder{}, pgr)

	require.Equal(t, http.StatusOK, doReq(h, http.MethodGet, "/v2/reg-A/app/blobs/sha256:own", true).Code)
	require.Equal(t, pushGrantKey{"reg-A", "app", "service_account:sva-ci"}, waitDelete(t, pgr.delCh),
		"blob v_get-allow тоже снимает push-grant-мост")
	require.Equal(t, 1, fw.count())
}

// REG-33IP revoke-safety — tags/list с v_list ALLOWED снимает push-grant (per-repo authz
// материализовался — v_list и v_get деривят из одного owner-tuple, мост больше не нужен).
func TestDataplane_REG33IP_DeleteOnMaterialized_TagsList_VListAllowed_DropsPushGrant(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_list registry_repository:reg-A/app": true}}
	fw := &fakeForwarder{status: 200}
	pgr := &fakePushGrantRecorder{
		granted: map[string]bool{pushGrantCacheKey("reg-A", "app", "service_account:sva-ci"): true},
		delCh:   make(chan pushGrantKey, 1),
	}
	h := newTestHandlerPG(&fakeVerifier{subject: "sva-ci"}, az, &fakeBackend{}, fw, &fakeRepoReg{}, &fakeUploadRecorder{}, pgr)

	require.Equal(t, http.StatusOK, doReq(h, http.MethodGet, "/v2/reg-A/app/tags/list", true).Code)
	require.Equal(t, pushGrantKey{"reg-A", "app", "service_account:sva-ci"}, waitDelete(t, pgr.delCh),
		"v_list-allow снимает push-grant-мост")
}

// REG-33IP revoke-safety (b) — ГЛАВНЫЙ security-регресс: после того как реальный v_get разок
// ALLOW'нул (delete-on-materialized снял мост), REVOKE (v_get снова DENIED) → pull ОБЯЗАН 404.
// До фикса push-grant (в пределах TTL) пережил бы revoke и раскрывал repo → stale-access leak.
// RED до фикса: pull#1 не снимает мост (waitDelete таймаутит); будь мост жив — pull#2 дал бы 200.
func TestDataplane_REG33IP_RevokeAfterMaterialized_VGetDenied_404(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_get registry_repository:reg-A/app": true}} // сперва материализован
	fw := &fakeForwarder{status: 200}
	be := &fakeBackend{exists: map[string]bool{"reg-A/app": true}}
	pgr := &fakePushGrantRecorder{
		granted: map[string]bool{pushGrantCacheKey("reg-A", "app", "service_account:sva-ci"): true},
		delCh:   make(chan pushGrantKey, 1),
	}
	h := newTestHandlerPG(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{}, &fakeUploadRecorder{}, pgr)

	// pull#1: v_get ALLOWED (материализовался) → forward + delete-on-materialized снимает мост.
	require.Equal(t, http.StatusOK, doReq(h, http.MethodGet, "/v2/reg-A/app/manifests/v1", true).Code,
		"pull#1 (v_get материализован) форвардится")
	waitDelete(t, pgr.delCh) // дождаться, пока async-delete снимет push-grant

	// admin REVOKES доступ → v_get снова DENIED. Мост уже снят → pull ОБЯЗАН 404 (без обхода).
	az.setAllow(map[string]bool{})
	require.Equal(t, http.StatusNotFound, doReq(h, http.MethodGet, "/v2/reg-A/app/manifests/v1", true).Code,
		"после материализации+revoke push-grant снят → v_get-deny → 404 (нет 1h stale-bypass)")
	require.Equal(t, http.StatusNotFound, doReq(h, http.MethodGet, "/v2/reg-A/app/blobs/sha256:own", true).Code,
		"blob того же repo тоже 404 после revoke (revoked субъект не тянет чужой контент repo)")
	require.Equal(t, 1, fw.count(), "форвардился только pull#1; после revoke — ни одного forward")
}

// REG-33IP revoke-safety — сбой delete-on-materialized (транзиентный DB down) НЕ рвёт уже
// авторизованный pull: DeletePushGrant — фоновое gardening (мост всё равно ограничен TTL),
// поэтому log-and-continue. Allowed pull остаётся 200; сбой наблюдаемо логируется.
func TestDataplane_REG33IP_DeleteOnMaterializedFailure_PullStill2xx_Logged(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_get registry_repository:reg-A/app": true}}
	fw := &fakeForwarder{status: 200}
	pgr := &fakePushGrantRecorder{
		granted: map[string]bool{pushGrantCacheKey("reg-A", "app", "service_account:sva-ci"): true},
		delErr:  errors.New("pg down"),
	}
	logbuf := &syncBuffer{} // потокобезопасно: delete-on-materialized логирует из детач-goroutine
	logger := slog.New(slog.NewTextHandler(logbuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h := New(&fakeVerifier{subject: "sva-ci"}, az, &fakeBackend{}, fw, &fakeRepoReg{}, &fakeRegistryLookup{}, &fakeUploadRecorder{}, pgr,
		"https://api.kacho.local/iam/token", "registry.kacho.local", logger)

	require.Equal(t, http.StatusOK, doReq(h, http.MethodGet, "/v2/reg-A/app/manifests/v1", true).Code,
		"allowed pull форвардится 200 несмотря на сбой фонового delete-on-materialized")
	require.Eventually(t, func() bool {
		return strings.Contains(logbuf.String(), "push-grant delete-on-materialized failed")
	}, 2*time.Second, 10*time.Millisecond, "сбой delete-on-materialized наблюдаемо логируется")
}

// REG-33IP revoke-safety regression (keep-green) — на v_get-DENIED pull, обслуженном через
// push-owner мост (материализация ещё НЕ догнала), push-grant НЕ удаляется: мост ещё нужен.
// Удаление здесь сломало бы immediate-pull (следующий pull до материализации снова 404).
func TestDataplane_REG33IP_PushOwnerBridge_VGetDenied_NoDelete(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{}} // v_get denied (ещё не материализован)
	fw := &fakeForwarder{status: 200}
	pgr := &fakePushGrantRecorder{granted: map[string]bool{
		pushGrantCacheKey("reg-A", "app", "service_account:sva-ci"): true,
	}}
	h := newTestHandlerPG(&fakeVerifier{subject: "sva-ci"}, az, &fakeBackend{}, fw, &fakeRepoReg{}, &fakeUploadRecorder{}, pgr)

	require.Equal(t, http.StatusOK, doReq(h, http.MethodGet, "/v2/reg-A/app/manifests/v1", true).Code,
		"immediate-pull толкавшего (v_get denied, свежий push-grant) всё ещё раскрывается")
	require.Empty(t, pgr.deletedKeys(), "мост НЕ снимается, пока v_get не материализовался (immediate-pull сохранён)")
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
