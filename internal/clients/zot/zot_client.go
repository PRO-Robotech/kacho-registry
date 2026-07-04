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

// imageConfig — разбор image-config blob (config.mediaType image): платформа и
// момент создания образа. Для helm-config / артефактов эти поля отсутствуют.
type imageConfig struct {
	Created      string `json:"created"`
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
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

// ListRepositories возвращает repos namespace (GET /v2/_catalog, namespace-prefix
// фильтр). Имя repo — БЕЗ namespace-префикса; tag_count — из tags/list; classify —
// по репрезентативному манифесту. Per-repo обход распараллелен (zotFanout). Repo с
// НУЛЁМ тегов (все теги удалены, GC ещё не снял запись из _catalog) — скрывается:
// пустой repo для tenant'а эквивалентен удалённому. Полная проекция (authz-фильтр и
// пагинацию применяет handler ПОСЛЕ фильтра).
func (c *Client) ListRepositories(ctx context.Context, q registry.RepoListQuery) ([]*domain.Repository, string, error) {
	if err := c.ready(); err != nil {
		return nil, "", err
	}
	fullNames, err := c.namespaceRepos(ctx, q.RegistryID)
	if err != nil {
		return nil, "", err
	}
	prefix := q.RegistryID + "/"
	repos := make([]*domain.Repository, len(fullNames)) // индексируем — порядок _catalog сохраняется
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(zotFanout)
	for i, full := range fullNames {
		i, full := i, full
		g.Go(func() error {
			tags, terr := c.repoTags(gctx, full)
			if terr != nil {
				return terr // zot недоступен → fail-closed для всего списка
			}
			if len(tags) == 0 {
				return nil // ghost: пустой repo — скрываем (nil остаётся, компактится ниже)
			}
			repos[i] = &domain.Repository{
				RegistryID:   q.RegistryID,
				Name:         strings.TrimPrefix(full, prefix),
				TagCount:     int32(len(tags)),
				ArtifactType: c.classifyRepo(gctx, full, tags),
			}
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

// ListTags возвращает теги repo (GET /v2/<registryID>/<repo>/tags/list) с digest,
// реальным размером образа (config + Σlayers; для index — Σ дочерних) и, для
// контейнерных образов, платформой/created из image-config. Per-tag обход
// распараллелен (zotFanout). Несуществующий repo → пустой список; тег, исчезнувший
// между list и read, выпадает из проекции. Полная проекция (пагинацию применяет handler).
func (c *Client) ListTags(ctx context.Context, q registry.TagListQuery) ([]*domain.Tag, string, error) {
	if err := c.ready(); err != nil {
		return nil, "", err
	}
	fullRepo := q.RegistryID + "/" + q.Repository
	tags, err := c.repoTags(ctx, fullRepo)
	if err != nil {
		return nil, "", err
	}
	projected := make([]*domain.Tag, len(tags)) // индексируем — порядок tags/list сохраняется
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(zotFanout)
	for i, tag := range tags {
		i, tag := i, tag
		g.Go(func() error {
			t, terr := c.projectTag(gctx, q.RegistryID, q.Repository, fullRepo, tag)
			if terr != nil {
				if terr == errNotFound {
					return nil // тег исчез между list и read — выпадает из проекции
				}
				return terr // zot недоступен → fail-closed для всего списка
			}
			projected[i] = t
			return nil
		})
	}
	if werr := g.Wait(); werr != nil {
		return nil, "", werr
	}
	out := make([]*domain.Tag, 0, len(projected))
	for _, t := range projected {
		if t != nil {
			out = append(out, t)
		}
	}
	return out, "", nil
}

// projectTag строит проекцию одного тега: digest + media-type + реальный размер
// (config + Σlayers; для multi-arch index — Σ дочерних манифестов) + платформа/created
// из image-config (best-effort: недоступный config-blob не валит тег). errNotFound —
// тег исчез между list и read.
func (c *Client) projectTag(ctx context.Context, registryID, repository, fullRepo, tag string) (*domain.Tag, error) {
	digest, mb, err := c.getManifestFull(ctx, fullRepo, tag)
	if err != nil {
		return nil, err
	}
	t := &domain.Tag{
		RegistryID: registryID,
		Repository: repository,
		Tag:        tag,
		Digest:     digest,
		MediaType:  mb.MediaType,
	}
	if len(mb.Manifests) > 0 {
		// multi-arch index: config/layers у index нет, размер — сумма дочерних манифестов.
		for _, m := range mb.Manifests {
			t.SizeBytes += m.Size
		}
		t.Architecture = "multi-arch"
		return t, nil
	}
	t.SizeBytes = mb.Config.Size
	for _, l := range mb.Layers {
		t.SizeBytes += l.Size
	}
	// Платформа/created — из image-config blob (только контейнерный образ; helm-config
	// их не несёт). Миссинг/ошибка чтения config-blob — best-effort, тег остаётся.
	if isImageConfig(mb.Config.MediaType) && mb.Config.Digest != "" {
		if cfg, cerr := c.getConfigBlob(ctx, fullRepo, mb.Config.Digest); cerr == nil {
			t.Architecture = platformString(cfg.OS, cfg.Architecture)
			if cfg.Created != "" {
				if ct, perr := time.Parse(time.RFC3339, cfg.Created); perr == nil {
					t.CreatedAt = ct
				}
			}
		}
	}
	return t, nil
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

// getManifestFull GET-ит манифест по ref и возвращает digest (Docker-Content-Digest
// заголовок) вместе с разобранным телом (config/layers/manifests). 404 → errNotFound;
// прочий не-2xx / транспорт / decode → ErrUnavailable.
func (c *Client) getManifestFull(ctx context.Context, fullRepo, ref string) (string, manifestBody, error) {
	req, rerr := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+"/v2/"+repoPath(fullRepo)+"/manifests/"+url.PathEscape(ref), nil)
	if rerr != nil {
		return "", manifestBody{}, regerrors.ErrUnavailable
	}
	req.Header.Set("Accept", acceptManifests)
	resp, derr := c.http.Do(req)
	if derr != nil {
		return "", manifestBody{}, regerrors.ErrUnavailable
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return "", manifestBody{}, errNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", manifestBody{}, regerrors.ErrUnavailable
	}
	var mb manifestBody
	if err := json.NewDecoder(resp.Body).Decode(&mb); err != nil {
		return "", manifestBody{}, regerrors.ErrUnavailable
	}
	return resp.Header.Get("Docker-Content-Digest"), mb, nil
}

// getConfigBlob читает image-config blob (GET /blobs/<digest>) и разбирает
// платформу/created. 404/сбой → ошибка (caller трактует best-effort).
func (c *Client) getConfigBlob(ctx context.Context, fullRepo, digest string) (imageConfig, error) {
	var cfg imageConfig
	if err := c.getJSON(ctx, "/v2/"+repoPath(fullRepo)+"/blobs/"+digest, &cfg); err != nil {
		return imageConfig{}, err
	}
	return cfg, nil
}

// isImageConfig — config.mediaType контейнерного образа (docker/oci), чей blob несёт
// architecture/os/created. helm-config и прочие артефакты сюда не попадают.
func isImageConfig(mediaType string) bool {
	return mediaType == "application/vnd.oci.image.config.v1+json" ||
		mediaType == "application/vnd.docker.container.image.v1+json"
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

var _ registry.ZotClient = (*Client)(nil)
