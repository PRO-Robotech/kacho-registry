# kacho-registry — CLAUDE.md

Registry-специфичный CLAUDE.md. Базовые правила Kachō (`.claude/rules/*`) — локальная
копия, синхронизируемая из workspace (`./sync-tooling.sh`; источник истины —
`kacho-workspace/.claude/rules/`, копию здесь не редактировать). `@import` ниже делает
репо самодостаточным и при standalone-клоне.

## Базовые правила Kachō (@import — синканная копия из workspace)

@.claude/rules/00-kacho-core.md
@.claude/rules/api-conventions.md
@.claude/rules/polyrepo.md
@.claude/rules/architecture.md
@.claude/rules/data-integrity.md
@.claude/rules/security.md
@.claude/rules/git-youtrack.md
@.claude/rules/testing.md
@.claude/rules/integration-pitfalls.md
@.claude/rules/vault.md
@.claude/rules/ai-tooling.md
@.claude/rules/licensing-and-comments.md
@.claude/rules/publication-readiness.md
@.claude/rules/publication-runbook.md

> **Происхождение:** новый leaf-сервис (OCI/Docker registry поверх zot + IAM),
> написан на проверенных паттернах `kacho-geo` (dual-listener leaf) и `kacho-nlb`
> (полный CRUD→Operation + fga-proxy outbox). Где видишь «как в geo» / «как в nlb» —
> буквально смотри одноимённый файл в `../kacho-geo/` / `../kacho-nlb/`.

## 0. Что за сервис

Registry — tenant-namespace реестра образов над общим zot-бэкендом. Три поверхности,
**все под authN+authZ-инвариантом** (`security.md`):

- **Control-plane gRPC** (public :9090): `RegistryService` — sync `Get`/`List`/
  `ListRepositories`/`ListTags` + async `Create`/`Update`/`Delete`/`DeleteTag` (→ `Operation`).
- **Internal admin gRPC** (:9091, mTLS): `InternalRegistryService` — `TriggerGarbageCollection`
  / `GetRegistryStats` (infra-проекция, никогда не на external endpoint).
- **Data-plane auth-proxy** (`registry.kacho.local`, Docker Registry v2/OCI): реализуется
  rpc-implementer'ом (per-request Check, existence-hiding, listauthz).

## 1. Идентификаторы и REST

| Ресурс | ID prefix | БД | REST namespace |
|---|---|---|---|
| Registry | `reg` | `kacho_registry` | `/registries/v1/registries` |

- LRO operation-id prefix — `reo` (opsproxy-роутинг в api-gateway).
- Env-переменные — `KACHO_REGISTRY_*`.

## 2. Скелет vs реализация

Скелет (этот scaffold) собирается и `go test ./...` проходит; все RPC отвечают
`codes.Unimplemented`. Порты use-case (`internal/apps/kacho/api/registry`:
`RegistryReader`/`RegistryWriter` CQRS, `ZotClient`, `IAMClient`) — анкеры для
`rpc-implementer` (строгий TDD: proto→migration→repo(pgx)→handler→outbox→tests). Data-plane
proto НЕ содержится в сервисе — stubs импортируются из `proto/gen/go/kacho/cloud/registry/v1`.

## 3. Authz-регистрации (новый тип ресурса — проверить ВСЕ, память grabli #3)

1. FGA-модель: `type registry_registry` + `type registry_repository` в iam `fga_model.fga`.
2. Service `PermissionMap` (`internal/check/permission_map.go`) — per-RPC verb-relations.
3. corelib `validate` prefix `reg` (id-валидация).
4. iam `moduleObjectDomain`: object-prefix `registry_` == имя сервиса → mapping НЕ нужен.
5. `fga_writer@iam_fgaproxy:system` для registry-SA (seed в openfga-bootstrap).
6. api-gateway List-exempt parity (non-member List → 200+empty).
