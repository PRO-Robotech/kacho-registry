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
package zot

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

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

// ListRepositories возвращает repos namespace (GET /v2/_catalog, namespace-prefix
// фильтр). Имя repo — БЕЗ namespace-префикса; tag_count — из tags/list. Возвращает
// полную проекцию (per-repo authz-фильтр и пагинацию применяет handler ПОСЛЕ фильтра).
func (c *Client) ListRepositories(ctx context.Context, q registry.RepoListQuery) ([]*domain.Repository, string, error) {
	if err := c.ready(); err != nil {
		return nil, "", err
	}
	fullNames, err := c.namespaceRepos(ctx, q.RegistryID)
	if err != nil {
		return nil, "", err
	}
	prefix := q.RegistryID + "/"
	out := make([]*domain.Repository, 0, len(fullNames))
	for _, full := range fullNames {
		tags, terr := c.repoTags(ctx, full)
		if terr != nil {
			return nil, "", terr
		}
		out = append(out, &domain.Repository{
			RegistryID:   q.RegistryID,
			Name:         strings.TrimPrefix(full, prefix),
			TagCount:     int32(len(tags)),
			ArtifactType: c.classifyRepo(ctx, full, tags),
		})
	}
	return out, "", nil
}

// classifyRepo определяет тип артефакта репо по манифесту репрезентативного тега
// (best-effort): "latest" если присутствует, иначе последний в отсортированном
// списке. Любая ошибка чтения манифеста (404/5xx/decode) → UNSPECIFIED — список
// НЕ падает (полный отказ zot ловится раньше, на _catalog/tags/list). Нет тегов →
// UNSPECIFIED. Дискриминатор — config.mediaType (+ top-level mediaType для index).
func (c *Client) classifyRepo(ctx context.Context, fullRepo string, tags []string) domain.ArtifactType {
	if len(tags) == 0 {
		return domain.ArtifactTypeUnspecified
	}
	ref := representativeTag(tags)
	mb, err := c.getManifest(ctx, fullRepo, ref)
	if err != nil {
		return domain.ArtifactTypeUnspecified // best-effort: тип неизвестен, список жив
	}
	return domain.ClassifyArtifact(mb.Config.MediaType, mb.MediaType)
}

// representativeTag выбирает тег для классификации: "latest" (если есть), иначе
// последний в отсортированном списке. Репо практически тип-стабилен, поэтому
// одного репрезентанта достаточно (mixed-repo — by-design best-effort).
func representativeTag(tags []string) string {
	for _, t := range tags {
		if t == "latest" {
			return t
		}
	}
	return tags[len(tags)-1]
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

// ListTags возвращает теги repo (GET /v2/<registryID>/<repo>/tags/list) с digest и
// размером манифеста (HEAD /manifests/<tag>). Полная проекция (пагинацию применяет
// handler). Несуществующий repo → пустой список.
func (c *Client) ListTags(ctx context.Context, q registry.TagListQuery) ([]*domain.Tag, string, error) {
	if err := c.ready(); err != nil {
		return nil, "", err
	}
	fullRepo := q.RegistryID + "/" + q.Repository
	tags, err := c.repoTags(ctx, fullRepo)
	if err != nil {
		return nil, "", err
	}
	out := make([]*domain.Tag, 0, len(tags))
	for _, tag := range tags {
		digest, size, mediaType, herr := c.headManifest(ctx, fullRepo, tag)
		if herr != nil && herr != errNotFound {
			return nil, "", herr
		}
		out = append(out, &domain.Tag{
			RegistryID: q.RegistryID,
			Repository: q.Repository,
			Tag:        tag,
			Digest:     digest,
			SizeBytes:  size,
			MediaType:  mediaType,
		})
	}
	return out, "", nil
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

var _ registry.ZotClient = (*Client)(nil)
