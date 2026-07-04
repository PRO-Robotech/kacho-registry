// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package zot — adapter-клиент к zot (data/registry-API). Реализует порт
// registry.ZotClient: проекции Repository/Tag на request-path, удаление тегов,
// GC, инфра-статистику namespace. zot никогда не публично достижим — клиент
// ходит на internal-endpoint (localhost/cluster, mTLS от proxy-SA).
//
// Мультитенантность — через storage-path-prefix "<registryID>/<repo>": в zot репо
// именуется полным путём с namespace-префиксом. Проекции Repository/Tag — output-only
// зеркало zot (source of truth = zot); в БД kacho-registry НЕ хранятся. Все HTTP-сбои
// zot → ErrUnavailable (fail-closed: проекции не отдают stale-фикцию, Delete-
// precondition не «считает пустым»).
//
// Проекции Repository/Tag читаются через zot search-extension GraphQL
// (POST /v2/_zot/ext/search): GlobalSearch отдаёт per-repo агрегаты (размер, момент
// последнего push, download-count) одним запросом, ImageList — теги repo с размером,
// платформой, push/pull-таймстампами и типом артефакта. Distribution-API остаётся для
// удаления тегов, инфра-статистики (Stats), catalog-листинга и per-repo blob-scope.
package zot

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	registry "github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/api/registry"
	"github.com/PRO-Robotech/kacho-registry/internal/domain"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// acceptManifests — Accept-заголовок манифест-запросов (OCI + Docker media-types),
// чтобы zot вернул конкретный манифест, а не index по умолчанию.
const acceptManifests = "application/vnd.oci.image.manifest.v1+json," +
	"application/vnd.docker.distribution.manifest.v2+json," +
	"application/vnd.oci.image.index.v1+json," +
	"application/vnd.docker.distribution.manifest.list.v2+json"

// Client — adapter к zot registry-API поверх HTTP.
type Client struct {
	http    *http.Client
	baseURL string
}

// New строит Client для zot-endpoint (baseURL, напр. https://zot.internal:5000).
// Пустой baseURL → клиент не сконфигурирован (методы отвечают Unavailable).
func New(baseURL string) *Client {
	return &Client{
		http:    &http.Client{Timeout: 30 * time.Second},
		baseURL: strings.TrimRight(baseURL, "/"),
	}
}

// ready — endpoint zot обязан быть подан (иначе Unavailable, fail-closed).
func (c *Client) ready() error {
	if c.baseURL == "" || c.http == nil {
		return regerrors.ErrUnavailable
	}
	return nil
}

// catalogResponse — тело GET /v2/_catalog.
type catalogResponse struct {
	Repositories []string `json:"repositories"`
}

// tagsResponse — тело GET /v2/<repo>/tags/list.
type tagsResponse struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

// manifestBody — минимальный разбор OCI/Docker image-манифеста: top-level mediaType
// (index/manifest-list для multi-arch), config (mediaType — дискриминатор типа
// артефакта; size/digest — для расчёта размеров) и layers. manifest-index не несёт
// layers — вклад в размер/блобы 0 (best-effort), но top-level mediaType несёт.
type manifestBody struct {
	MediaType string       `json:"mediaType"`
	Config    descriptor   `json:"config"`
	Layers    []descriptor `json:"layers"`
	// Manifests — дочерние манифесты multi-arch index/list (config/layers у самого
	// index нет; размер образа = сумма их size).
	Manifests []descriptor `json:"manifests"`
}

type descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

// namespaceRepos читает GET /v2/_catalog и возвращает full-repo-имена (с namespace-
// префиксом) реестра registryID. Любой HTTP-сбой → ErrUnavailable (fail-closed).
func (c *Client) namespaceRepos(ctx context.Context, registryID string) ([]string, error) {
	var cat catalogResponse
	if err := c.getJSON(ctx, "/v2/_catalog", &cat); err != nil {
		return nil, err
	}
	prefix := registryID + "/"
	var out []string
	for _, name := range cat.Repositories {
		if strings.HasPrefix(name, prefix) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

// zotFanout — верхняя граница параллельных запросов к zot при построении проекций
// (per-repo tags/list + classify, per-tag manifest+config). Ограничивает нагрузку
// на internal-endpoint, сохраняя скорость против N последовательных round-trip'ов.
const zotFanout = 8

// ListRepositories возвращает repos namespace через search-ext GraphQL. GlobalSearch
// даёт per-repo агрегаты (Size / LastUpdated / DownloadCount) одним запросом и служит
// источником имён репо; per-repo ImageList (распараллелен, zotFanout) — теги для
// tag_count / artifact-типов / last-pull. Имя repo — БЕЗ namespace-префикса. Repo с
// НУЛЁМ тегов (все теги удалены, GC ещё не снял запись) — скрывается: пустой repo для
// tenant'а эквивалентен удалённому. Результат отсортирован по имени. Полная проекция
// (authz-фильтр и пагинацию применяет handler ПОСЛЕ фильтра).
func (c *Client) ListRepositories(ctx context.Context, q registry.RepoListQuery) ([]*domain.Repository, string, error) {
	if err := c.ready(); err != nil {
		return nil, "", err
	}
	prefix := q.RegistryID + "/"
	var gs gqlGlobalSearchData
	if err := c.gqlQuery(ctx, globalSearchQuery(prefix), &gs); err != nil {
		return nil, "", err
	}
	summaries := gs.GlobalSearch.Repos
	repos := make([]*domain.Repository, len(summaries)) // индексируем — компактим ниже
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(zotFanout)
	for i, rs := range summaries {
		i, rs := i, rs
		// GlobalSearch — substring-поиск: отбрасываем чужой namespace (defence-in-depth).
		if !strings.HasPrefix(rs.Name, prefix) {
			continue
		}
		g.Go(func() error {
			var data gqlImageListData
			if err := c.gqlQuery(gctx, imageListQuery(rs.Name), &data); err != nil {
				return err // zot недоступен → fail-closed для всего списка
			}
			results := data.ImageList.Results
			if len(results) == 0 {
				return nil // ghost: пустой repo — скрываем (nil остаётся, компактится ниже)
			}
			repos[i] = repositoryFromSummaries(q.RegistryID, strings.TrimPrefix(rs.Name, prefix), rs, results)
			return nil
		})
	}
	if werr := g.Wait(); werr != nil {
		return nil, "", werr
	}
	out := make([]*domain.Repository, 0, len(repos))
	for _, r := range repos {
		if r != nil {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, "", nil
}

// repositoryFromSummaries собирает проекцию repo из GlobalSearch-агрегата (rs) и тегов
// (results из ImageList). tag_count — число тегов; artifact_types — упорядоченно-
// уникальный набор ClassifyArtifact по тегам (mixed-repo несёт оба значения), без
// UNSPECIFIED; artifact_type (primary) — первый из набора. last_pulled_at — max
// LastPullTimestamp по тегам. Size / updated_at / download_count берутся из GlobalSearch;
// fallback (агрегат пуст) — сумма/максимум по тегам.
func repositoryFromSummaries(registryID, name string, rs gqlRepoSummary, results []gqlImageSummary) *domain.Repository {
	repo := &domain.Repository{
		RegistryID:    registryID,
		Name:          name,
		TagCount:      int32(len(results)),
		SizeBytes:     parseInt64(rs.Size),
		UpdatedAt:     parseZotTS(rs.LastUpdated),
		DownloadCount: rs.DownloadCount,
	}
	var types []domain.ArtifactType
	seen := map[domain.ArtifactType]bool{}
	var maxPull, maxPush time.Time
	var sumSize, sumDownloads int64
	for _, r := range results {
		if at := classifyTag(r); at != domain.ArtifactTypeUnspecified && !seen[at] {
			seen[at] = true
			types = append(types, at)
		}
		if pull := parseZotTS(r.LastPullTimestamp); pull.After(maxPull) {
			maxPull = pull
		}
		if push := parseZotTS(r.PushTimestamp); push.After(maxPush) {
			maxPush = push
		}
		sumSize += parseInt64(r.Size)
		sumDownloads += r.DownloadCount
	}
	repo.ArtifactTypes = types
	if len(types) > 0 {
		repo.ArtifactType = types[0]
	}
	repo.LastPulledAt = maxPull
	if repo.UpdatedAt.IsZero() { // GlobalSearch LastUpdated отсутствует → max push по тегам
		repo.UpdatedAt = maxPush
	}
	if repo.SizeBytes == 0 { // GlobalSearch Size отсутствует → Σ размеров тегов
		repo.SizeBytes = sumSize
	}
	if repo.DownloadCount == 0 { // GlobalSearch DownloadCount отсутствует → Σ по тегам
		repo.DownloadCount = sumDownloads
	}
	return repo
}

// classifyTag определяет тип артефакта тега по config-mediaType (Manifests[0].ArtifactType)
// и top-level media-type. Multi-arch index (config пуст) классифицируется по top-level
// mediaType как контейнерный образ.
func classifyTag(m gqlImageSummary) domain.ArtifactType {
	config := ""
	if len(m.Manifests) > 0 {
		config = m.Manifests[0].ArtifactType
	}
	return domain.ClassifyArtifact(config, m.MediaType)
}

// repoTags читает GET /v2/<full-repo>/tags/list. 404 (repo нет / GC-нут) → пустой
// список (грациозный dangling-ref, не ошибка); прочий HTTP-сбой → ErrUnavailable.
func (c *Client) repoTags(ctx context.Context, fullRepo string) ([]string, error) {
	var tr tagsResponse
	err := c.getJSON(ctx, "/v2/"+repoPath(fullRepo)+"/tags/list", &tr)
	if err != nil {
		if err == errNotFound {
			return nil, nil
		}
		return nil, err
	}
	sort.Strings(tr.Tags)
	return tr.Tags, nil
}

// ListTags возвращает теги repo через search-ext GraphQL (ImageList). На каждый тег
// проецируются digest, размер образа (Size int64), media-type, момент push (created_at),
// момент последнего pull, subject-push (pushed_by), download-count и платформа
// ("<os>/<arch>", "multi-arch" для index). Порядок Results сохраняется. Несуществующий
// repo → пустой ImageList.Results → пустой список (грациозный dangling-ref, не ошибка).
// Полная проекция (пагинацию применяет handler).
func (c *Client) ListTags(ctx context.Context, q registry.TagListQuery) ([]*domain.Tag, string, error) {
	if err := c.ready(); err != nil {
		return nil, "", err
	}
	fullRepo := q.RegistryID + "/" + q.Repository
	var data gqlImageListData
	if err := c.gqlQuery(ctx, imageListQuery(fullRepo), &data); err != nil {
		return nil, "", err
	}
	results := data.ImageList.Results
	out := make([]*domain.Tag, 0, len(results))
	for _, r := range results {
		out = append(out, tagFromSummary(q.RegistryID, q.Repository, r))
	}
	return out, "", nil
}

// tagFromSummary строит проекцию одного тега из ImageList-элемента. Размер — Size
// (string int64) из zot; платформа — "multi-arch" для index (>1 манифест), иначе
// "<os>/<arch>" единственного манифеста.
func tagFromSummary(registryID, repository string, s gqlImageSummary) *domain.Tag {
	t := &domain.Tag{
		RegistryID:    registryID,
		Repository:    repository,
		Tag:           s.Tag,
		Digest:        s.Digest,
		SizeBytes:     parseInt64(s.Size),
		MediaType:     s.MediaType,
		CreatedAt:     parseZotTS(s.PushTimestamp),
		LastPulledAt:  parseZotTS(s.LastPullTimestamp),
		PushedBy:      s.PushedBy,
		DownloadCount: s.DownloadCount,
	}
	switch {
	case len(s.Manifests) > 1:
		t.Architecture = "multi-arch"
	case len(s.Manifests) == 1:
		t.Architecture = platformString(s.Manifests[0].Platform.Os, s.Manifests[0].Platform.Arch)
	}
	return t
}

// DeleteTag удаляет тег/манифест: сначала резолвит digest тега (HEAD), затем
// DELETE /manifests/<digest>. Отсутствующий тег/манифест → идемпотентный success
// (async-retry worker'а не залипает). zot недоступен → ErrUnavailable.
func (c *Client) DeleteTag(ctx context.Context, registryID, repository, tag string) error {
	if err := c.ready(); err != nil {
		return err
	}
	fullRepo := registryID + "/" + repository
	digest, _, _, err := c.headManifest(ctx, fullRepo, tag)
	if err != nil {
		if err == errNotFound {
			return nil // тег уже отсутствует — идемпотентно
		}
		return err
	}
	delErr := c.do(ctx, http.MethodDelete, "/v2/"+repoPath(fullRepo)+"/manifests/"+digest, nil, nil)
	if delErr == errNotFound {
		return nil // манифест уже снят — идемпотентно
	}
	return delErr
}

// NamespaceEmpty сообщает, пуст ли namespace реестра (нет ни одного repo с префиксом
// <registryID>/). zot недоступен → ErrUnavailable (fail-closed: Delete-precondition
// НЕ трактует ошибку как «пусто»).
func (c *Client) NamespaceEmpty(ctx context.Context, registryID string) (bool, error) {
	if err := c.ready(); err != nil {
		return false, err
	}
	repos, err := c.namespaceRepos(ctx, registryID)
	if err != nil {
		return false, err
	}
	return len(repos) == 0, nil
}

// RemoveNamespace снимает storage-namespace реестра в zot. namespace-объекта в zot
// нет (репо адресуются полным путём), а Delete допускается только для ПУСТОГО
// namespace (precondition REG-08) — снимать нечего. Проверяет пустоту и завершается;
// zot недоступен → ErrUnavailable.
func (c *Client) RemoveNamespace(ctx context.Context, registryID string) error {
	if err := c.ready(); err != nil {
		return err
	}
	// Delete прошёл precondition пустого namespace; физически удалять нечего.
	empty, err := c.NamespaceEmpty(ctx, registryID)
	if err != nil {
		return err
	}
	if !empty {
		return regerrors.ErrFailedPrecondition
	}
	return nil
}

// TriggerGC форсирует garbage collection namespace. Реальная рекламация unreferenced-
// блобов исполняется native-scheduler'ом zot по расписанию; ad-hoc HTTP-триггера у zot
// нет, поэтому trigger проверяет достижимость zot (/v2/ handshake) и подтверждает
// (идемпотентно). zot недоступен → ErrUnavailable (fail-closed).
func (c *Client) TriggerGC(ctx context.Context, registryID string) error {
	if err := c.ready(); err != nil {
		return err
	}
	return c.do(ctx, http.MethodGet, "/v2/", nil, nil)
}

// Stats возвращает инфра-статистику namespace (repo/tag count, суммарный размер,
// число уникальных блобов) — только для Internal-API (:9091). Размер/блобы считаются
// из манифестов (config.size + layers[].size, уникальные digest'ы). Манифест, который
// не удалось прочитать, пропускается (best-effort). zot недоступен → ErrUnavailable.
func (c *Client) Stats(ctx context.Context, registryID string) (*domain.RegistryStats, error) {
	if err := c.ready(); err != nil {
		return nil, err
	}
	fullNames, err := c.namespaceRepos(ctx, registryID)
	if err != nil {
		return nil, err
	}
	stats := &domain.RegistryStats{RegistryID: registryID, RepositoryCount: int32(len(fullNames))}
	blobs := map[string]int64{}
	for _, full := range fullNames {
		tags, terr := c.repoTags(ctx, full)
		if terr != nil {
			return nil, terr
		}
		stats.TagCount += int32(len(tags))
		for _, tag := range tags {
			mb, merr := c.getManifest(ctx, full, tag)
			if merr != nil {
				continue // best-effort: не валим Stats из-за одного манифеста
			}
			if mb.Config.Digest != "" {
				blobs[mb.Config.Digest] = mb.Config.Size
			}
			for _, l := range mb.Layers {
				if l.Digest != "" {
					blobs[l.Digest] = l.Size
				}
			}
		}
	}
	for _, sz := range blobs {
		stats.TotalSizeBytes += sz
	}
	stats.BlobCount = int64(len(blobs))
	return stats, nil
}

// ---- data-plane Backend (authz-интроспекция; не reverse-proxy) ------------

// RepoExists сообщает, зарегистрирован ли repo (несёт ≥1 тег) — data-plane
// verb-map push-new (v_create@namespace) vs push-existing (v_update@repo). zot
// недоступен → ErrUnavailable (fail-closed: не решаем new/existing вслепую).
func (c *Client) RepoExists(ctx context.Context, registryID, repo string) (bool, error) {
	if err := c.ready(); err != nil {
		return false, err
	}
	tags, err := c.repoTags(ctx, registryID+"/"+repo)
	if err != nil {
		return false, err
	}
	return len(tags) > 0, nil
}

// CatalogRepoNames возвращает полный zot-каталог (full-repo-имена всех namespace'ов)
// для per-repo listauthz-фильтрации _catalog в data-plane. zot недоступен →
// ErrUnavailable (fail-closed — не отдаём частичный каталог).
func (c *Client) CatalogRepoNames(ctx context.Context) ([]string, error) {
	if err := c.ready(); err != nil {
		return nil, err
	}
	var cat catalogResponse
	if err := c.getJSON(ctx, "/v2/_catalog", &cat); err != nil {
		return nil, err
	}
	out := append([]string(nil), cat.Repositories...)
	sort.Strings(out)
	return out, nil
}

// BlobInRepo проверяет per-repo blob-scope (REG-37): <digest> достижим только если
// входит в config/layers манифеста(ов) авторизованного repo. Cross-reference:
// перебирает теги repo, читает манифесты, собирает уникальные блоб-digest'ы. Чужой
// content-addressable блоб (принадлежит манифесту другого repo) → false. zot
// недоступен → ErrUnavailable (fail-closed).
func (c *Client) BlobInRepo(ctx context.Context, registryID, repo, digest string) (bool, error) {
	if err := c.ready(); err != nil {
		return false, err
	}
	fullRepo := registryID + "/" + repo
	tags, err := c.repoTags(ctx, fullRepo)
	if err != nil {
		return false, err
	}
	for _, tag := range tags {
		mb, merr := c.getManifest(ctx, fullRepo, tag)
		if merr != nil {
			if merr == errNotFound {
				continue // тег исчез между list и read — пропускаем
			}
			return false, merr
		}
		if mb.Config.Digest == digest {
			return true, nil
		}
		for _, l := range mb.Layers {
			if l.Digest == digest {
				return true, nil
			}
		}
	}
	return false, nil
}

// ---- HTTP helpers ---------------------------------------------------------

// errNotFound — внутренний sentinel: zot ответил 404 (тег/манифест/repo отсутствует).
// Маппится caller-методом в идемпотентный success либо пустую проекцию.
var errNotFound = fmt.Errorf("zot: not found")

// repoPath url-кодирует сегменты полного repo-пути (multi-segment), сохраняя '/'.
func repoPath(fullRepo string) string {
	segs := strings.Split(fullRepo, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}

// getJSON выполняет GET и декодирует JSON-тело. 404 → errNotFound; прочий не-2xx или
// транспортный сбой → ErrUnavailable (fail-closed, сырой zot-текст наружу не течёт).
func (c *Client) getJSON(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, out)
}

// headManifest резолвит digest/size/media-type манифеста по ref (тег или digest)
// через HEAD /manifests/<ref>. 404 → errNotFound.
func (c *Client) headManifest(ctx context.Context, fullRepo, ref string) (digest string, size int64, mediaType string, err error) {
	req, rerr := http.NewRequestWithContext(ctx, http.MethodHead,
		c.baseURL+"/v2/"+repoPath(fullRepo)+"/manifests/"+url.PathEscape(ref), nil)
	if rerr != nil {
		return "", 0, "", regerrors.ErrUnavailable
	}
	req.Header.Set("Accept", acceptManifests)
	resp, derr := c.http.Do(req)
	if derr != nil {
		return "", 0, "", regerrors.ErrUnavailable
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return "", 0, "", errNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", 0, "", regerrors.ErrUnavailable
	}
	return resp.Header.Get("Docker-Content-Digest"), resp.ContentLength, resp.Header.Get("Content-Type"), nil
}

// getManifest читает и разбирает тело манифеста (config + layers). 404 → errNotFound.
func (c *Client) getManifest(ctx context.Context, fullRepo, ref string) (manifestBody, error) {
	req, rerr := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+"/v2/"+repoPath(fullRepo)+"/manifests/"+url.PathEscape(ref), nil)
	if rerr != nil {
		return manifestBody{}, regerrors.ErrUnavailable
	}
	req.Header.Set("Accept", acceptManifests)
	resp, derr := c.http.Do(req)
	if derr != nil {
		return manifestBody{}, regerrors.ErrUnavailable
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return manifestBody{}, errNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return manifestBody{}, regerrors.ErrUnavailable
	}
	var mb manifestBody
	if err := json.NewDecoder(resp.Body).Decode(&mb); err != nil {
		return manifestBody{}, regerrors.ErrUnavailable
	}
	return mb, nil
}

// platformString собирает "<os>/<arch>" (оба поля), либо только непустое, либо "".
func platformString(os, arch string) string {
	switch {
	case os != "" && arch != "":
		return os + "/" + arch
	case arch != "":
		return arch
	case os != "":
		return os
	default:
		return ""
	}
}

// do выполняет запрос method+path; при out != nil декодирует JSON-тело. 404 →
// errNotFound; прочий не-2xx или транспортный сбой → ErrUnavailable. Сырой zot-текст
// наружу не течёт (fail-closed фиксированный sentinel).
func (c *Client) do(ctx context.Context, method, path string, body io.Reader, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return regerrors.ErrUnavailable
	}
	if out != nil {
		req.Header.Set("Accept", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return regerrors.ErrUnavailable
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return regerrors.ErrUnavailable
	}
	if out != nil {
		if derr := json.NewDecoder(resp.Body).Decode(out); derr != nil {
			return regerrors.ErrUnavailable
		}
	} else {
		_, _ = io.Copy(io.Discard, resp.Body)
	}
	return nil
}

// ---- search-ext GraphQL --------------------------------------------------

// gqlPlatform — платформа манифеста (Os/Arch) в ImageList.
type gqlPlatform struct {
	Os   string `json:"Os"`
	Arch string `json:"Arch"`
}

// gqlManifestSummary — один манифест образа. ArtifactType несёт config-mediaType
// (дискриминатор helm/container); Platform — ОС/архитектура.
type gqlManifestSummary struct {
	ArtifactType string      `json:"ArtifactType"`
	Platform     gqlPlatform `json:"Platform"`
}

// gqlImageSummary — элемент ImageList.Results: проекция одного тега. Size — string
// int64; таймстампы — RFC3339 ("1970-01-01T00:00:00Z" = never). Manifests — платформы
// (>1 → multi-arch index).
type gqlImageSummary struct {
	Tag               string               `json:"Tag"`
	Digest            string               `json:"Digest"`
	MediaType         string               `json:"MediaType"`
	Size              string               `json:"Size"`
	DownloadCount     int64                `json:"DownloadCount"`
	PushTimestamp     string               `json:"PushTimestamp"`
	LastPullTimestamp string               `json:"LastPullTimestamp"`
	PushedBy          string               `json:"PushedBy"`
	Manifests         []gqlManifestSummary `json:"Manifests"`
}

// gqlImageListData — data-обёртка ответа ImageList.
type gqlImageListData struct {
	ImageList struct {
		Results []gqlImageSummary `json:"Results"`
	} `json:"ImageList"`
}

// gqlRepoSummary — элемент GlobalSearch.Repos: per-repo агрегаты. Size — string int64;
// LastUpdated — RFC3339 момента последнего push.
type gqlRepoSummary struct {
	Name          string `json:"Name"`
	Size          string `json:"Size"`
	LastUpdated   string `json:"LastUpdated"`
	DownloadCount int64  `json:"DownloadCount"`
}

// gqlGlobalSearchData — data-обёртка ответа GlobalSearch.
type gqlGlobalSearchData struct {
	GlobalSearch struct {
		Repos []gqlRepoSummary `json:"Repos"`
	} `json:"GlobalSearch"`
}

// imageListQuery строит ImageList-запрос по full-repo (<registryID>/<repo>).
func imageListQuery(fullRepo string) string {
	return `{ImageList(repo:` + strconv.Quote(fullRepo) +
		`){Results{Tag Digest MediaType Size DownloadCount PushTimestamp LastPullTimestamp PushedBy ` +
		`Manifests{ArtifactType Platform{Os Arch}}}}}`
}

// globalSearchQuery строит GlobalSearch-запрос по namespace-префиксу (<registryID>/).
func globalSearchQuery(query string) string {
	return `{GlobalSearch(query:` + strconv.Quote(query) +
		`){Repos{Name Size LastUpdated DownloadCount}}}`
}

// gqlQuery выполняет POST /v2/_zot/ext/search с телом {"query": query} и декодирует
// поле data в out. Непустой errors, не-2xx, транспортный сбой или decode-ошибка →
// ErrUnavailable (fail-closed: сырой zot-текст наружу не течёт).
func (c *Client) gqlQuery(ctx context.Context, query string, out any) error {
	reqBody, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		return regerrors.ErrUnavailable
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/v2/_zot/ext/search", bytes.NewReader(reqBody))
	if err != nil {
		return regerrors.ErrUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return regerrors.ErrUnavailable
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return regerrors.ErrUnavailable
	}
	var wrapper struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if derr := json.NewDecoder(resp.Body).Decode(&wrapper); derr != nil {
		return regerrors.ErrUnavailable
	}
	if len(wrapper.Errors) > 0 {
		return regerrors.ErrUnavailable
	}
	if uerr := json.Unmarshal(wrapper.Data, out); uerr != nil {
		return regerrors.ErrUnavailable
	}
	return nil
}

// parseZotTS разбирает RFC3339-таймстамп zot. Пусто, ошибка разбора или year<=1970
// (zot-эпоха "никогда") → нулевой time.Time.
func parseZotTS(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil || t.Year() <= 1970 {
		return time.Time{}
	}
	return t
}

// parseInt64 разбирает строковый int64 (zot отдаёт Size строкой). Мусор → 0.
func parseInt64(s string) int64 {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

var _ registry.ZotClient = (*Client)(nil)
