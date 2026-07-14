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

// PushGrantRecorder — durable per-subject учёт push-ownership репозитория (REG-33
// immediate-pull, #33). На успешном manifest-PUT data-plane записывает (registryID, repo,
// subject) — факт «этот субъект только что запушил этот repo». Пока async-материализация
// per-repo authz не догнала (register-on-first-push → registry_outbox → fga-proxy drainer →
// IAM RegisterResource → FGA reconciler), собственный `docker pull` толкавшего упирается в
// v_get@registry_repository-deny → 404. Pull-path консультируется с этой записью как
// fallback: v_get denied, НО субъект доказуемо запушил repo → раскрываем (мост на окно
// материализации). Ключ по SUBJECT — раскрывается ТОЛЬКО собственный только-что-запушенный
// repo толкавшего; чужой субъект/тенант записи не имеет → остаётся 404 (REG-37 сохранён,
// не cross-tenant leak).
//
// Revoke-safety (мост живёт ТОЛЬКО окно материализации, НЕ переживает revoke): мост обязан
// перестать раскрывать repo, как только реальный per-repo authz заработал ИЛИ доступ отозван.
// Два ограничителя (оба обязательны):
//   - delete-on-materialized (первичный): как только pull-path v_get/v_list Check ALLOW'нул
//     (реальный per-repo authz материализовался в FGA), запись (registryID, repo, subject)
//     удаляется (DeletePushGrant) — мост схлопывается к нулю. Последующий revoke → v_get
//     denies → записи нет → 404. Без этого push-grant (в пределах TTL) раскрывал бы repo и
//     ПОСЛЕ revoke — до истечения TTL (stale/cross-tenant-ish access leak).
//   - TTL-backstop: короткий freshness-TTL (config PushGrantTTL) ограничивает худший случай,
//     если delete-on-materialized не сработал (толкавший ни разу не пул(нул) после
//     материализации) — окно обхода revoke ≤ TTL, а не 1h.
//
// serveBlob дополнительно держит blob-scope (REG-37): push-grant раскрывает repo, но НЕ
// произвольный глобальный content-addressable блоб.
//
// Реализуется pg.PushGrantRepo. nil → no-op (запись не ведётся, fallback не выдаётся).
type PushGrantRecorder interface {
	// RecordPushGrant идемпотентно (upsert) фиксирует, что <subject> запушил
	// <registryID>/<repo>, освежая granted_at (re-push держит запись свежей). ОБЯЗАН
	// закоммититься до того, как последующий `docker pull` толкавшего дойдёт до pull-path
	// (иначе немедленный pull проиграет гонку с материализацией).
	RecordPushGrant(ctx context.Context, registryID, repo, subject string) error
	// PushGranted сообщает, держит ли <subject> свежий push-grant на <registryID>/<repo>
	// (granted_at в пределах TTL; протухшие игнорируются и подметаются sweeper'ом).
	PushGranted(ctx context.Context, registryID, repo, subject string) (bool, error)
	// DeletePushGrant удаляет push-grant-строку (registryID, repo, subject) — вызывается на
	// pull-path, как только реальный per-repo v_get/v_list Check ALLOW'нул (per-repo authz
	// материализовался в FGA): мост больше не нужен и обязан ПЕРЕСТАТЬ раскрывать repo, иначе
	// после последующего revoke он (в пределах TTL) продолжал бы отдавать доступ (stale-access
	// leak). Привязывает время жизни моста к «пока реальный v_get не заработал разок». Идемпотентен:
	// DELETE без совпадения — дешёвый индексный no-op (безопасно звать безусловно на allow-ветке).
	DeletePushGrant(ctx context.Context, registryID, repo, subject string) error
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
