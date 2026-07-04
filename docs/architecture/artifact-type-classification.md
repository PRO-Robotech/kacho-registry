# Классификация типа артефакта образа (artifact_type)

`Repository.artifact_type` — output-only проекция, отличающая **контейнерный образ**
(docker/OCI image) от **Helm-чарта** (и прочих OCI-артефактов). Нужна UI-фильтру
«docker-образы vs helm-чарты». Значение классифицируется на request-path в
`ZotClient.ListRepositories` (source of truth — zot; в БД не хранится).

## Дискриминатор

Тип определяется **`config.mediaType`** манифеста, НЕ top-level manifest media-type:
контейнерный образ и helm-чарт несут одинаковый top-level
`application/vnd.oci.image.manifest.v1+json` — различие только в конфиге.

| config.mediaType | artifact_type |
|---|---|
| `application/vnd.cncf.helm.config.v1+json` | HELM_CHART |
| `application/vnd.docker.container.image.v1+json` | CONTAINER_IMAGE |
| `application/vnd.oci.image.config.v1+json` | CONTAINER_IMAGE |
| (config пуст) + top-level index/manifest-list | CONTAINER_IMAGE (multi-arch) |
| иной непустой config.mediaType | OTHER |
| нет тегов / манифест непрочитан | UNSPECIFIED |

Алгоритм — чистая доменная функция `domain.ClassifyArtifact(configMediaType,
manifestMediaType)` (config-приоритет над top-level, first-match); zot-адаптер лишь
извлекает два media-type-поля из тела манифеста и делегирует.

## By-design tradeoffs

**Best-effort по одному репрезентативному тегу.** Классификация читает манифест
ОДНОГО тега (`latest` если есть, иначе последний в отсортированном списке). Репо
практически тип-стабилен, поэтому одного репрезентанта достаточно. **Mixed-repo**
(например `latest`=helm, `sig`=cosign, или мёртвый `latest`→404 при живых
container-тегах) классифицируется по репрезентанту — это осознанный компромисс, НЕ
латентный баг. Per-tag `artifact_type` намеренно НЕ вводится (это GET-манифест на
каждый тег, N×M).

**Fail-closed сохранён.** Полный отказ zot (`_catalog`/`tags/list` 5xx) → `ErrUnavailable`
ДО классификации (существующие fail-closed чтения). Ошибка чтения манифеста
репрезентанта (404/5xx/decode) → `UNSPECIFIED` (best-effort, список НЕ падает).
Классификатор НИКОГДА не роняет `ListRepositories` и не маскирует недоступность
частичной проекцией.

**Perf.** Классификация добавляет **один GET-манифест на каждый репо** в
`ListRepositories` (sequential, без кэша; ранее список читал только
`_catalog`+`tags/list`). Приемлемо для internal/cluster-local zot и ограниченного
namespace. Кэш/parallelize + отложенная классификация ПОСЛЕ authz-фильтра/пагинации —
возможная оптимизация (сейчас классифицируются и репо, которые caller не получит).

**Фильтр — client-side.** UI грузит ВСЕ страницы `ListRepositories` (follow
`next_page_token`) и фильтрует по artifact_type на клиенте. Server-side
filter-параметр не введён (namespace ограничен, load-all покрывает). Если появится
deep-пагинация большого масштаба — facet потребует server-side support.
