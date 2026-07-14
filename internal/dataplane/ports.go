// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package dataplane — data-plane OCI auth-proxy kacho-registry: отдельный
// HTTP-листенер, реализующий Docker Registry v2 / OCI Distribution token-auth flow
// перед общим zot-бэкендом.
//
// AuthN входного токена — Hydra JWKS (RS256/ES256); authZ — per-request Check.
//
// Поверхность и инвариант (security.md — authN+authZ на КАЖДОМ запросе):
//   - AuthN: клиент без Bearer-JWT → 401 + WWW-Authenticate (realm = /iam/token-шим).
//     Docker сам идёт в realm (token-шим), получает Hydra-issued identity-JWT и
//     повторяет с `Authorization: Bearer <jwt>`. Proxy верифицирует JWT по Hydra JWKS
//     (RS256/ES256).
//   - AuthZ: КАЖДЫЙ /v2/-запрос проходит per-request InternalIAMService.Check
//     (Вариант B — identity-only токен, без pre-issued scope; авторизация — здесь).
//     Deny → 404 (existence-hiding: не раскрывать существование чужого repo/блоба).
//   - После passed-authz — reverse-proxy запроса в zot (stream, chunked upload).
//
// Транспорт-слой чистой архитектуры: определяет узкие порты (TokenVerifier,
// Authorizer, Backend, Forwarder, RepoRegistrar) и оркестрирует parse→verify→
// authz→forward; не тянет pgx/grpc-stubs напрямую (адаптеры инжектятся из
// composition root). registry_repository owner-tuple lifecycle (register-on-first-
// push) идёт через RepoRegistrar → registry_outbox → fga-proxy drainer.
package dataplane

import (
	"context"
	"net/http"

	"github.com/PRO-Robotech/kacho-registry/internal/domain"
)

// TokenVerifier — верификация Hydra-issued Bearer-JWT по Hydra JWKS (RS256/ES256;
// энфорс exp/aud/iss). Возвращает identity (`sub` — Hydra client_id ↔ Kachō principal,
// напр. SA "sva…"); scope в токене НЕТ (identity-only, авторизация — per-request
// Check). Ошибка → 401 (invalid_token). Реализуется clients/jwks.Verifier.
type TokenVerifier interface {
	Verify(ctx context.Context, rawToken string) (subject string, err error)
}

// Authorizer — per-request InternalIAMService.Check (fga subject/relation/object).
// subject — FGA subject-строка ("service_account:sva…"), relation — verb-relation
// (v_get/v_list/v_create/v_update), object — FGA object-строка. Реализуется
// check.IAMCheckClient. nil → breakglass (authz bypass).
type Authorizer interface {
	Check(ctx context.Context, subject, relation, object string) (bool, error)
}

// Backend — read-side zot-интроспекция для authz-решений (не сам reverse-proxy):
//   - RepoExists — repo зарегистрирован (push-new vs push-existing verb-map).
//   - BlobInRepo — <digest> входит в манифест(ы) авторизованного repo (blob-scope
//     existence-hiding: чужой блоб недостижим через blob-HEAD/GET).
//   - CatalogRepoNames — полный zot-каталог (per-repo listauthz-фильтр _catalog).
//
// Реализуется clients/zot.Client. Ошибка (zot недоступен) → fail-closed.
type Backend interface {
	RepoExists(ctx context.Context, registryID, repo string) (bool, error)
	BlobInRepo(ctx context.Context, registryID, repo, digest string) (bool, error)
	CatalogRepoNames(ctx context.Context) ([]string, error)
}

// Forwarder — reverse-proxy запроса в zot (stream тела/заголовков/range, chunked
// upload). Возвращает HTTP-статус, записанный клиенту (register-on-first-push
// эмитится только на успешном manifest-PUT). Ошибка zot → 502/503 (fail-closed).
//
// ForwardCapture — тот же round-trip в zot, но ОТВЕТ (status+headers+body)
// БУФЕРИЗУЕТСЯ в память, а не стримится клиенту напрямую. Нужен ровно для
// blob PUT-finalize (REG-33 Defect A): даёт caller'у отреагировать на исход zot
// (durable-запись факта аплоада блоба в этот repo) ДО того, как клиент увидит 2xx —
// docker может сделать HEAD блоба сразу за 201, поэтому строка обязана закоммититься
// первой. Ответ blob-finalize — только статус+заголовки, пустое тело → буфер тривиален
// (тело запроса при этом по-прежнему стримится в zot, ReverseProxy не буферизует его).
// Стриминговый Forward остаётся для всех прочих маршрутов (blob GET, chunk PATCH,
// manifest PUT).
type Forwarder interface {
	Forward(w http.ResponseWriter, r *http.Request) int
	ForwardCapture(r *http.Request) CapturedResponse
}

// CapturedResponse — буферизованный ответ zot (ForwardCapture): статус, заголовки и
// (пустое для blob-finalize) тело. Релеится клиенту через writeCaptured ПОСЛЕ того,
// как caller выполнил durable-побочку (RecordUploadedBlob).
type CapturedResponse struct {
	Status int
	Header http.Header
	Body   []byte
}

// UploadRecorder — durable per-repo учёт фактически загруженных блобов (REG-33 Defect A).
// На успешном blob PUT-finalize data-plane записывает (registryID, repo, digest), чтобы
// последующий push-time blob HEAD/GET раскрыл только что загруженный блоб ДО того, как
// он попадёт в какой-либо манифест repo — НЕ пере-открывая cross-tenant blob-leak (zot
// дедуплицирует content-addressable блобы глобально: HEAD чужого глобального блоба из
// любого repo даёт 200). REG-37 сохранён: раскрываются ТОЛЬКО блобы, которые
// авторизованный writer реально загрузил в ЭТОТ repo (zot проверил digest на finalize —
// значит writer владеет контентом); подделать запись аплоада для чужого контента нельзя.
//
// Реализуется pg.PendingBlobRepo. nil → no-op (запись не ведётся, reveal не выдаётся).
type UploadRecorder interface {
	// RecordUploadedBlob идемпотентно (upsert) фиксирует, что <digest> загружен в
	// <registryID>/<repo>. ОБЯЗАН закоммититься ДО того, как caller отпустит 2xx
	// blob-finalize клиенту (иначе немедленный HEAD за 201 гонку проиграет).
	RecordUploadedBlob(ctx context.Context, registryID, repo, digest string) error
	// BlobUploaded сообщает, был ли <digest> загружен в <registryID>/<repo> в пределах
	// freshness-TTL (протухшие строки игнорируются и подметаются sweeper'ом).
	BlobUploaded(ctx context.Context, registryID, repo, digest string) (bool, error)
}

// RepoRegistrar — эмит register-intent нового repo (register-on-first-push):
// registry_repository:<reg>/<repo> parent+owner tuple → registry_outbox →
// fga-proxy drainer (идемпотентно). Реализуется pg.RegistryRepo. nil → no-op.
type RepoRegistrar interface {
	RegisterRepository(ctx context.Context, intent domain.RegisterIntent) error
}

// RegistryLookup — резолв owning-project реестра по id (control-plane read). Нужен
// register-on-first-push, чтобы intent репо нёс ParentProjectID (containment scope в
// iam-mirror; без него reconciler не материализует per-object v_* → репо непуллим
// даже владельцем). Реализуется pg.RegistryRepo. nil → интент без project (best-effort).
type RegistryLookup interface {
	RegistryProjectID(ctx context.Context, registryID string) (string, error)
}
