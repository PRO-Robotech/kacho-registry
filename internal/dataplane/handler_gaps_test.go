// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package dataplane

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// handler_gaps_test.go — TEST-ONLY (ban #13): дозакрывает непокрытые decision-пути
// auth-proxy хендлера, локая НАБЛЮДАЕМОЕ поведение (HTTP-статус, existence-hiding,
// fail-closed), а не реализацию. Прод-код не трогается. Дополняет handler_test.go
// (который покрывает allow/deny/reveal/push-grant/revoke) следующими классами:
//   - fail-closed 503 на КАЖДОЙ недоступной внешней зависимости (Check/RepoExists/
//     BlobInRepo/pending/CatalogRepoNames) на всех push/pull/mount/catalog-ветках;
//   - method-guard'ы read-маршрутов (не-read verb → 404 existence-hiding, не forward);
//   - routeReferrers pull (v_get) — раньше вообще не exercised;
//   - serveMount edge (from без repo-сегмента → 404);
//   - blob-finalize chunk-PATCH (стриминг, без pending-записи);
//   - breakglass (verifier==nil / authz==nil) и nil-recorder graceful-disable контракты;
//   - writeCaptured relay заголовков zot + дефолт статуса (blob-finalize).

// ---- custom test doubles (не пересекаются с fakes_test.go) -----------------

// captureForwarder — Forwarder, чей ForwardCapture возвращает ЗАРАНЕЕ заданный
// CapturedResponse (статус/заголовки/тело zot). Нужен, чтобы изолированно проверить
// writeCaptured (relay заголовков + дефолт статуса), не гоняя реальный reverse-proxy.
type captureForwarder struct {
	captured CapturedResponse
	fwCalls  int
	capCalls int
}

func (f *captureForwarder) Forward(w http.ResponseWriter, r *http.Request) int {
	f.fwCalls++
	w.WriteHeader(http.StatusOK)
	return http.StatusOK
}

func (f *captureForwarder) ForwardCapture(r *http.Request) CapturedResponse {
	f.capCalls++
	return f.captured
}

// srcAllowDstErrAuthz — Authorizer: v_get(src) allow, любой другой relation → err.
// Изолирует ветку serveMount «dst-check error» (первый src-Check проходит, dst-Check
// падает) — fakeAuthz.err применился бы уже к src-Check и до dst бы не дошло.
type srcAllowDstErrAuthz struct{ err error }

func (a *srcAllowDstErrAuthz) Check(ctx context.Context, subject, relation, object string) (bool, error) {
	if relation == relVGet {
		return true, nil
	}
	return false, a.err
}

// ============================================================================
// Fail-closed: недоступность внешней зависимости → 503 (никогда не 404/200/2xx).
// architecture.md: любой сбой authz-Check / zot-интроспекции fail-closed'ится, иначе
// скомпрометированный/деградированный peer открыл бы доступ «на всякий случай».
// ============================================================================

// TestDataplane_FailClosed_DependencyUnavailable_503 — таблица непокрытых fail-closed
// веток: каждая внешняя ошибка (Check/RepoExists/BlobInRepo/pending/catalog) обязана
// дать 503, НЕ 404 (не маскировать недоступность под existence-hiding) и НЕ forward.
func TestDataplane_FailClosed_DependencyUnavailable_503(t *testing.T) {
	depErr := errors.New("dependency down")

	t.Run("serveBlob initial v_get Check error", func(t *testing.T) {
		fw := &fakeForwarder{}
		az := &fakeAuthz{err: depErr}
		h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, az, &fakeBackend{}, fw, &fakeRepoReg{})
		rec := doReq(h, http.MethodGet, "/v2/reg-A/app/blobs/sha256:x", true)
		require.Equal(t, http.StatusServiceUnavailable, rec.Code, "blob Check error → fail-closed 503")
		require.Equal(t, 0, fw.count())
	})

	t.Run("serveBlobScoped BlobInRepo error", func(t *testing.T) {
		fw := &fakeForwarder{}
		az := &fakeAuthz{allow: map[string]bool{"v_get registry_repository:reg-A/app": true}}
		be := &fakeBackend{blobErr: depErr} // v_get прошёл, но blob-scope introspection падает
		h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{})
		rec := doReq(h, http.MethodGet, "/v2/reg-A/app/blobs/sha256:x", true)
		require.Equal(t, http.StatusServiceUnavailable, rec.Code, "blob-scope check error → fail-closed 503")
		require.Equal(t, 0, fw.count())
	})

	t.Run("serveBlobScoped pending-blob check error", func(t *testing.T) {
		fw := &fakeForwarder{}
		az := &fakeAuthz{allow: map[string]bool{"v_get registry_repository:reg-A/app": true}}
		be := &fakeBackend{} // BlobInRepo=false → идём в pending-проверку
		up := &fakeUploadRecorder{getErr: depErr}
		h := newTestHandlerU(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{}, up)
		rec := doReq(h, http.MethodGet, "/v2/reg-A/app/blobs/sha256:x", true)
		require.Equal(t, http.StatusServiceUnavailable, rec.Code, "pending-blob check error → fail-closed 503")
		require.Equal(t, 0, fw.count())
	})

	t.Run("servePush RepoExists error", func(t *testing.T) {
		fw := &fakeForwarder{}
		az := &fakeAuthz{} // allow-all — ошибка приходит из RepoExists ДО verb-map Check
		be := &fakeBackend{existsErr: depErr}
		h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{})
		rec := doReq(h, http.MethodPost, "/v2/reg-A/app/blobs/uploads/", true)
		require.Equal(t, http.StatusServiceUnavailable, rec.Code, "push RepoExists error → fail-closed 503")
		require.Equal(t, 0, fw.count())
	})

	t.Run("serveMount src check error", func(t *testing.T) {
		fw := &fakeForwarder{}
		az := &fakeAuthz{err: depErr} // первый Check в mount — src v_get — падает
		h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, az, &fakeBackend{}, fw, &fakeRepoReg{})
		rec := doReq(h, http.MethodPost, "/v2/reg-A/dst/blobs/uploads/?mount=sha256:x&from=reg-A/src", true)
		require.Equal(t, http.StatusServiceUnavailable, rec.Code, "mount src check error → fail-closed 503")
		require.Equal(t, 0, fw.count())
	})

	t.Run("serveMount dst RepoExists error", func(t *testing.T) {
		fw := &fakeForwarder{}
		az := &fakeAuthz{allow: map[string]bool{"v_get registry_repository:reg-A/src": true}} // src allow
		be := &fakeBackend{existsErr: depErr}                                                  // dst RepoExists падает
		h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{})
		rec := doReq(h, http.MethodPost, "/v2/reg-A/dst/blobs/uploads/?mount=sha256:x&from=reg-A/src", true)
		require.Equal(t, http.StatusServiceUnavailable, rec.Code, "mount dst RepoExists error → fail-closed 503")
		require.Equal(t, 0, fw.count())
	})

	t.Run("serveMount dst check error", func(t *testing.T) {
		fw := &fakeForwarder{}
		az := &srcAllowDstErrAuthz{err: depErr} // src v_get allow, dst v_create → error
		be := &fakeBackend{}                        // dst new → v_create-Check падает
		h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{})
		rec := doReq(h, http.MethodPost, "/v2/reg-A/dst/blobs/uploads/?mount=sha256:x&from=reg-A/src", true)
		require.Equal(t, http.StatusServiceUnavailable, rec.Code, "mount dst check error → fail-closed 503")
		require.Equal(t, 0, fw.count())
	})

	t.Run("serveMount blob-scope (BlobInRepo) error", func(t *testing.T) {
		fw := &fakeForwarder{}
		az := &fakeAuthz{allow: map[string]bool{
			"v_get registry_repository:reg-A/src": true,
			"v_create registry_registry:reg-A":    true,
		}}
		be := &fakeBackend{blobErr: depErr} // оба Check allow, но mount-blob-scope introspection падает
		h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{})
		rec := doReq(h, http.MethodPost, "/v2/reg-A/dst/blobs/uploads/?mount=sha256:x&from=reg-A/src", true)
		require.Equal(t, http.StatusServiceUnavailable, rec.Code, "mount blob-scope error → fail-closed 503")
		require.Equal(t, 0, fw.count())
	})

	t.Run("serveCatalog CatalogRepoNames error", func(t *testing.T) {
		fw := &fakeForwarder{}
		be := &fakeBackend{catalogErr: depErr}
		h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, &fakeAuthz{}, be, fw, &fakeRepoReg{})
		rec := doReq(h, http.MethodGet, "/v2/_catalog", true)
		require.Equal(t, http.StatusServiceUnavailable, rec.Code, "catalog read error → fail-closed 503")
	})

	t.Run("serveCatalog per-repo Check error", func(t *testing.T) {
		fw := &fakeForwarder{}
		az := &fakeAuthz{err: depErr}                          // per-repo listauthz Check падает
		be := &fakeBackend{catalog: []string{"reg-A/app"}}     // ≥1 имя → errgroup запускает Check
		h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{})
		rec := doReq(h, http.MethodGet, "/v2/_catalog", true)
		require.Equal(t, http.StatusServiceUnavailable, rec.Code, "catalog filter Check error → fail-closed 503")
	})
}

// ============================================================================
// Method-guard'ы read-маршрутов: не-read HTTP-verb на read-route → 404 existence-hiding
// (НЕ forward, НЕ 200, НЕ 405). Локает «на read-путях обслуживаются только GET/HEAD;
// всё прочее неотличимо от несуществующего» — не даём проксировать неожиданный метод в zot.
// ============================================================================

// TestDataplane_MethodGuard_ReadRoutes_NonReadVerb_404 — таблица непокрытых method-guard
// веток. authz allow-all: 404 приходит ИМЕННО из method-guard (до/вне authz), не из deny.
func TestDataplane_MethodGuard_ReadRoutes_NonReadVerb_404(t *testing.T) {
	cases := []struct {
		name, method, target string
	}{
		{"manifest OPTIONS", http.MethodOptions, "/v2/reg-A/app/manifests/v1"},
		{"blob POST", http.MethodPost, "/v2/reg-A/app/blobs/sha256:x"},
		{"blob OPTIONS", http.MethodOptions, "/v2/reg-A/app/blobs/sha256:x"},
		{"tags/list POST", http.MethodPost, "/v2/reg-A/app/tags/list"},
		{"referrers POST", http.MethodPost, "/v2/reg-A/app/referrers/sha256:x"},
		{"ping POST", http.MethodPost, "/v2/"},
		{"catalog POST", http.MethodPost, "/v2/_catalog"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fw := &fakeForwarder{status: 200}
			h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, &fakeAuthz{}, &fakeBackend{}, fw, &fakeRepoReg{})
			rec := doReq(h, c.method, c.target, true)
			require.Equal(t, http.StatusNotFound, rec.Code, "%s → 404 existence-hiding", c.name)
			require.Equal(t, 0, fw.count(), "%s never forwarded to zot", c.name)
		})
	}
}

// ============================================================================
// routeReferrers — GET/HEAD /v2/<reg>/<repo>/referrers/<digest>: read-путь, гейтится
// v_get на repo-объекте (servePullOnly relVGet). Раньше вообще не exercised.
// ============================================================================

// TestDataplane_Referrers_VGet_AllowForward_DenyHide — referrers pull: v_get allow →
// forward; deny → 404 (existence-hiding, как manifest/blob/tags read-путь).
func TestDataplane_Referrers_VGet_AllowForward_DenyHide(t *testing.T) {
	// allow → forward.
	azAllow := &fakeAuthz{allow: map[string]bool{"v_get registry_repository:reg-A/app": true}}
	fwAllow := &fakeForwarder{status: 200}
	hAllow := newTestHandler(&fakeVerifier{subject: "sva-ci"}, azAllow, &fakeBackend{}, fwAllow, &fakeRepoReg{})
	require.Equal(t, http.StatusOK, doReq(hAllow, http.MethodGet, "/v2/reg-A/app/referrers/sha256:x", true).Code,
		"referrers pull с v_get allow → forward")
	require.Equal(t, 1, fwAllow.count())
	require.Equal(t, checkCall{"service_account:sva-ci", "v_get", "registry_repository:reg-A/app"},
		azAllow.checkedObjects()[0], "referrers гейтится v_get на repo-объекте")

	// deny → 404 existence-hiding, не forward.
	azDeny := &fakeAuthz{allow: map[string]bool{}}
	fwDeny := &fakeForwarder{}
	hDeny := newTestHandler(&fakeVerifier{subject: "sva-evil"}, azDeny, &fakeBackend{}, fwDeny, &fakeRepoReg{})
	require.Equal(t, http.StatusNotFound, doReq(hDeny, http.MethodGet, "/v2/reg-A/app/referrers/sha256:x", true).Code,
		"referrers pull без v_get → 404 existence-hiding")
	require.Equal(t, 0, fwDeny.count())
}

// ============================================================================
// serveMount edge: `from` без repo-сегмента (нет '/') → 404 existence-hiding.
// ============================================================================

// TestDataplane_Mount_FromWithoutRepoSegment_404 — оба authz-Check проходят, но `from`
// не адресует реальный блоб (нет '/' → strings.Cut !ok) → 404, не forward. Без repo-
// сегмента from не именует блоб — раскрывать нечего.
func TestDataplane_Mount_FromWithoutRepoSegment_404(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{
		"v_get registry_repository:regonly": true, // src-Check по repositoryObjectFull("regonly")
		"v_create registry_registry:reg-A":  true, // dst new repo
	}}
	fw := &fakeForwarder{}
	h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, az, &fakeBackend{}, fw, &fakeRepoReg{})
	rec := doReq(h, http.MethodPost, "/v2/reg-A/dst/blobs/uploads/?mount=sha256:x&from=regonly", true)
	require.Equal(t, http.StatusNotFound, rec.Code, "from без repo-сегмента → 404 existence-hiding")
	require.Equal(t, 0, fw.count())
}

// ============================================================================
// blob-finalize chunk-PATCH: routeUpload + PATCH (без ?digest) — это chunk-загрузка,
// НЕ finalize. Идёт стриминговым Forward, pending-строка НЕ пишется (только PUT/POST
// с ?digest финализируют блоб). Локает isBlobFinalize-дискриминацию.
// ============================================================================

// TestDataplane_BlobUpload_ChunkPatch_StreamsNoRecord — PATCH-чанк в новый repo:
// v_create allow → стриминговый forward (не буферизованный finalize), pending пуст.
func TestDataplane_BlobUpload_ChunkPatch_StreamsNoRecord(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_create registry_registry:reg-A": true}}
	fw := &fakeForwarder{status: 202}
	be := &fakeBackend{exists: map[string]bool{}} // новый repo
	up := &fakeUploadRecorder{}
	h := newTestHandlerU(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{}, up)

	rec := doReq(h, http.MethodPatch, "/v2/reg-A/app/blobs/uploads/upl-chunk-1", true)
	require.Equal(t, 202, rec.Code, "chunk-PATCH стримится в zot")
	require.Equal(t, 1, fw.count(), "chunk-PATCH форвардится (стриминг, не буферизованный finalize)")
	require.Empty(t, up.recordedKeys(), "chunk-PATCH (без ?digest) не финализирует блоб → pending не пишется")
}

// ============================================================================
// Breakglass (аварийный режим): verifier==nil → AuthN bypass (subject "bootstrap");
// authz==nil → AuthZ bypass (allow). Документированный контракт New (только аварийно).
// ============================================================================

// TestDataplane_Breakglass_NilVerifier_NilAuthz_Bypasses — обе стадии nil: запрос БЕЗ
// токена проходит (AuthN bypass) и форвардится (AuthZ bypass). Локает breakglass-ветки.
func TestDataplane_Breakglass_NilVerifier_NilAuthz_Bypasses(t *testing.T) {
	fw := &fakeForwarder{status: 200}
	h := New(nil, nil, &fakeBackend{}, fw, &fakeRepoReg{},
		&fakeRegistryLookup{}, &fakeUploadRecorder{}, &fakePushGrantRecorder{},
		"https://api.kacho.local/iam/token", "registry.kacho.local", nil)

	// БЕЗ Authorization-заголовка: verifier==nil → authenticate bypass; authz==nil → allow.
	rec := doReq(h, http.MethodGet, "/v2/reg-A/app/manifests/v1", false)
	require.Equal(t, http.StatusOK, rec.Code, "breakglass (nil verifier+authz) → запрос без токена форвардится")
	require.Equal(t, 1, fw.count())
}

// ============================================================================
// nil-recorder graceful-disable: uploads==nil / pushGrants==nil / regLookup==nil —
// соответствующая фича выключена (no-op), без паники. Документированный контракт New.
// ============================================================================

// TestDataplane_NilRecorders_PushAndPull_Disabled — все три recorder'а nil:
//   - push нового repo: register-intent эмитится с ПУСТЫМ ParentProjectID (regLookup nil),
//     push-grant не пишется (pushGrants nil), паники нет;
//   - established pull с v_get allow + член-блоб: forward, dropPushGrant no-op (pushGrants nil);
//   - established pull с v_get deny: pushOwnerRevealsRepo no-op (pushGrants nil) → 404.
func TestDataplane_NilRecorders_PushAndPull_Disabled(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{
		"v_create registry_registry:reg-A":   true,
		"v_get registry_repository:reg-A/app": true,
	}}
	fw := &fakeForwarder{status: 201}
	be := &fakeBackend{exists: map[string]bool{}}
	rr := &fakeRepoReg{}
	// uploads=nil, pushGrants=nil, regLookup=nil — все опциональные фичи выключены.
	h := New(&fakeVerifier{subject: "sva-ci"}, az, be, fw, rr,
		nil, nil, nil, "https://api.kacho.local/iam/token", "registry.kacho.local", nil)

	require.Equal(t, 201, doReq(h, http.MethodPost, "/v2/reg-A/app/blobs/uploads/", true).Code)
	require.Equal(t, 201, doReq(h, http.MethodPut, "/v2/reg-A/app/manifests/v1", true).Code,
		"push нового repo проходит при выключенных recorder'ах")
	intents := rr.registered()
	require.Len(t, intents, 1, "register-intent эмитится (repoReg задан)")
	require.Empty(t, intents[0].ParentProjectID, "regLookup==nil → пустой ParentProjectID (фича выключена, не паника)")

	// established pull, v_get allow, член-блоб → forward; dropPushGrantMaterialized no-op (pushGrants nil).
	beEst := &fakeBackend{
		exists: map[string]bool{"reg-A/app": true},
		blobs:  map[string]bool{"reg-A/app|sha256:own": true},
	}
	fwEst := &fakeForwarder{status: 200}
	hEst := New(&fakeVerifier{subject: "sva-ci"}, az, beEst, fwEst, rr,
		nil, nil, nil, "https://api.kacho.local/iam/token", "registry.kacho.local", nil)
	require.Equal(t, http.StatusOK, doReq(hEst, http.MethodGet, "/v2/reg-A/app/blobs/sha256:own", true).Code,
		"established member-blob pull форвардится при nil pushGrants (dropPushGrant no-op)")

	// established pull, v_get deny → pushOwnerRevealsRepo no-op (pushGrants nil) → 404.
	azDeny := &fakeAuthz{allow: map[string]bool{}}
	fwDeny := &fakeForwarder{}
	hDeny := New(&fakeVerifier{subject: "sva-ci"}, azDeny, beEst, fwDeny, rr,
		nil, nil, nil, "https://api.kacho.local/iam/token", "registry.kacho.local", nil)
	require.Equal(t, http.StatusNotFound, doReq(hDeny, http.MethodGet, "/v2/reg-A/app/blobs/sha256:own", true).Code,
		"v_get deny + nil pushGrants → push-owner мост выключен → 404")
	require.Equal(t, 0, fwDeny.count())
}

// TestDataplane_NilUploads_BlobNotInManifest_404 — uploads==nil (pending-tracking
// выключен): established pull, v_get allow, блоб НЕ в манифесте → blobUploadedToRepo
// (uploads nil → false) → 404. Локает «без upload-tracking не раскрываем незамапленный
// блоб» (REG-33 Defect A выключен, но REG-37 существование-hiding сохранён).
func TestDataplane_NilUploads_BlobNotInManifest_404(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_get registry_repository:reg-A/app": true}}
	fw := &fakeForwarder{}
	be := &fakeBackend{} // BlobInRepo=false
	// uploads==nil → blobUploadedToRepo короткозамыкает в false.
	h := New(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{},
		&fakeRegistryLookup{}, nil, &fakePushGrantRecorder{},
		"https://api.kacho.local/iam/token", "registry.kacho.local", nil)

	require.Equal(t, http.StatusNotFound, doReq(h, http.MethodGet, "/v2/reg-A/app/blobs/sha256:x", true).Code,
		"nil uploads + блоб не в манифесте → 404 (pending-reveal выключен, existence-hiding сохранён)")
	require.Equal(t, 0, fw.count())
}

// TestDataplane_New_EmptyRealmService_AppliesDefaults — New с пустыми realm/service
// подставляет дефолтный IAM /token realm и service-audience; challenge их несёт. Локает
// дефолт-ветки конструктора (наблюдаемо — через WWW-Authenticate).
func TestDataplane_New_EmptyRealmService_AppliesDefaults(t *testing.T) {
	h := New(&fakeVerifier{subject: "sva-ci"}, &fakeAuthz{}, &fakeBackend{}, &fakeForwarder{}, &fakeRepoReg{},
		&fakeRegistryLookup{}, &fakeUploadRecorder{}, &fakePushGrantRecorder{}, "", "", nil)
	rec := doReq(h, http.MethodGet, "/v2/", false) // без токена → challenge
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	wa := rec.Header().Get("WWW-Authenticate")
	require.Contains(t, wa, `realm="https://api.kacho.local/iam/token"`, "пустой realm → дефолт")
	require.Contains(t, wa, `service="registry.kacho.local"`, "пустой service → дефолт")
}

// ============================================================================
// writeCaptured — blob-finalize relay буферизованного ответа zot: заголовки
// (Location / Docker-Content-Digest, на которые docker полагается при финализации)
// копируются 1:1, статус 0 → дефолт 200. Ранее непокрыто (fake возвращал пустой Header).
// ============================================================================

// TestDataplane_WriteCaptured_RelaysZotHeaders_DefaultsStatus — blob-finalize с
// заголовками zot в CapturedResponse: клиент получает те же заголовки; статус 0 → 200.
func TestDataplane_WriteCaptured_RelaysZotHeaders_DefaultsStatus(t *testing.T) {
	az := &fakeAuthz{allow: map[string]bool{"v_create registry_registry:reg-A": true}}
	be := &fakeBackend{exists: map[string]bool{}}

	t.Run("2xx finalize relays zot headers and records", func(t *testing.T) {
		hdr := http.Header{}
		hdr.Set("Location", "/v2/reg-A/app/blobs/sha256:layerA")
		hdr.Set("Docker-Content-Digest", "sha256:layerA")
		fw := &captureForwarder{captured: CapturedResponse{Status: 201, Header: hdr, Body: nil}}
		up := &fakeUploadRecorder{}
		h := newTestHandlerU(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{}, up)

		rec := doReq(h, http.MethodPut, "/v2/reg-A/app/blobs/uploads/upl-1?digest=sha256:layerA", true)
		require.Equal(t, 201, rec.Code, "captured zot-статус релеится клиенту")
		require.Equal(t, "/v2/reg-A/app/blobs/sha256:layerA", rec.Header().Get("Location"),
			"zot Location-заголовок релеится (docker полагается на него)")
		require.Equal(t, "sha256:layerA", rec.Header().Get("Docker-Content-Digest"),
			"zot Docker-Content-Digest релеится 1:1")
		require.NotEmpty(t, up.recordedKeys(), "2xx finalize пишет pending-строку")
	})

	t.Run("status 0 defaults to 200 (headers still relayed)", func(t *testing.T) {
		hdr := http.Header{}
		hdr.Set("Docker-Content-Digest", "sha256:mono")
		// Status 0 → forwardBlobFinalize не считает это 2xx (не пишет pending), writeCaptured
		// дефолтит статус до 200 и всё равно копирует заголовки.
		fw := &captureForwarder{captured: CapturedResponse{Status: 0, Header: hdr, Body: nil}}
		up := &fakeUploadRecorder{}
		h := newTestHandlerU(&fakeVerifier{subject: "sva-ci"}, az, be, fw, &fakeRepoReg{}, up)

		rec := doReq(h, http.MethodPut, "/v2/reg-A/app/blobs/uploads/upl-2?digest=sha256:mono", true)
		require.Equal(t, http.StatusOK, rec.Code, "captured статус 0 → дефолт 200")
		require.Equal(t, "sha256:mono", rec.Header().Get("Docker-Content-Digest"), "заголовки релеятся и при дефолт-статусе")
	})
}
