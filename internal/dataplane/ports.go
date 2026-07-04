// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package dataplane — data-plane OCI auth-proxy kacho-registry: отдельный
// HTTP-листенер, реализующий Docker Registry v2 / OCI Distribution token-auth flow
// перед общим zot-бэкендом.
//
// Поверхность и инвариант (security.md — authN+authZ на КАЖДОМ запросе):
//   - AuthN: клиент без Bearer-JWT → 401 + WWW-Authenticate (realm = IAM /token).
//     Docker сам идёт в realm (IAM /token), получает identity-JWT и повторяет с
//     `Authorization: Bearer <jwt>`. Proxy верифицирует JWT по IAM JWKS (RS256).
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

// TokenVerifier — верификация Bearer-JWT по IAM JWKS (RS256; энфорс exp/aud/iss).
// Возвращает identity (`sub` — Kachō principal id, напр. SA "sva…"); scope в токене
// НЕТ (identity-only, авторизация — per-request Check). Ошибка → 401 (invalid_token).
// Реализуется clients/jwks.Verifier.
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
type Forwarder interface {
	Forward(w http.ResponseWriter, r *http.Request) int
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
