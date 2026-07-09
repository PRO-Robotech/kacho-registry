// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package zot

// graphql.go — zot search-extension GraphQL projection: output-only проекции
// Repository/Tag на request-path (ListRepositories / ListTags) и разбор
// GlobalSearch/ImageList. Source of truth — zot; в БД kacho-registry не хранится.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	registry "github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/api/registry"
	"github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/shared/namepage"
	"github.com/PRO-Robotech/kacho-registry/internal/domain"
)

// zotFanout — верхняя граница параллельных запросов к zot при построении проекций
// (per-repo tags/list + classify, per-tag manifest+config). Ограничивает нагрузку
// на internal-endpoint, сохраняя скорость против N последовательных round-trip'ов.
const zotFanout = 8

// maxGraphQLBytes — верхняя граница тела search-ext GraphQL-ответа (ImageList/
// GlobalSearch), читаемого под io.LimitReader перед декодом. zot ImageList не
// поддерживает server-side tag-пагинацию, поэтому tenant-controlled tag/repo-count
// иначе материализуется в память целиком на каждый ListTags/ListRepositories (CWE-770:
// pathological tag-push в собственный repo → O(N) память на каждый запрос → OOM shared
// control-plane). LimitReader — defense-in-depth (паритет с decodeManifest /
// maxManifestBytes): оверсайз-ответ деградирует в fail-closed ErrUnavailable, не в
// безразмерную аллокацию. Bound щедрый — реальные проекции namespace/тегов много ниже.
const maxGraphQLBytes = 16 << 20 // 16 MiB

// ListRepositories возвращает repos namespace через search-ext GraphQL. GlobalSearch
// даёт per-repo агрегаты (Size / LastUpdated / DownloadCount) + имена одним дешёвым
// запросом. Имена сортируются и режутся ОКНОМ (page_size/page_token) ДО per-repo
// ImageList-fan-out — иначе один вызов развернулся бы в N round-trip'ов к zot по всей
// проекции namespace (CWE-770 memory/backend-амплификация; N не контролируется
// вызывающим). ImageList (теги для tag_count/artifact-типов/last-pull) запрашивается
// ТОЛЬКО для окна, распараллелен zotFanout. Имя repo — БЕЗ namespace-префикса. Repo с
// НУЛЁМ тегов (все теги удалены, GC ещё не снял запись) — скрывается. Возвращает
// окно (отсортировано ASC) + next-token — ОПАКОВЫЙ offset, НЕ имя граничного репо:
// handler фильтрует per-repo v_list ПОСЛЕ окна, поэтому name-курсор echo'ил бы имя
// скрытого репо (existence-oracle). Offset скрытие/фильтр страницу не «удлиняют» — все
// разрешённые repos достижимы пагинацией даже через полностью-скрытые окна.
func (c *Client) ListRepositories(ctx context.Context, q registry.RepoListQuery) ([]*domain.Repository, string, error) {
	if err := c.ready(); err != nil {
		return nil, "", err
	}
	prefix := q.RegistryID + "/"
	var gs gqlGlobalSearchData
	if err := c.gqlQuery(ctx, globalSearchQuery(prefix), &gs); err != nil {
		return nil, "", err
	}

	// GlobalSearch — substring-поиск: оставляем только свой namespace (defence-in-depth),
	// сортируем по имени ASC (стабильный ключ курсора).
	kept := make([]gqlRepoSummary, 0, len(gs.GlobalSearch.Repos))
	for _, rs := range gs.GlobalSearch.Repos {
		if strings.HasPrefix(rs.Name, prefix) {
			kept = append(kept, rs)
		}
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].Name < kept[j].Name })

	// Окно по (page_size, page_token) ДО ImageList-fan-out — bound per-request нагрузки
	// к zot. Курсор — ОПАКОВЫЙ offset (позиция в отсортированном срезе), НЕ имя репо:
	// per-repo authz-фильтр handler'а применяется ПОСЛЕ окна, поэтому name-курсор
	// раскрыл бы имя скрытого репо (existence-oracle).
	window, next, err := namepage.WindowByOffset(kept, q.PageSize, q.PageToken)
	if err != nil {
		return nil, "", err
	}

	repos := make([]*domain.Repository, len(window)) // индексируем — компактим ниже
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(zotFanout)
	for i, rs := range window {
		i, rs := i, rs
		g.Go(func() error {
			var data gqlImageListData
			if err := c.gqlQuery(gctx, imageListQuery(rs.Name), &data); err != nil {
				return err // zot недоступен → fail-closed для всего окна
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
	return out, next, nil
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
		TagCount:      int32(len(results)), // #nosec G115 -- tag count of one registry, bounded well below int32 max
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

// ListTags возвращает теги repo через search-ext GraphQL (ImageList). На каждый тег
// проецируются digest, размер образа (Size int64), media-type, момент push (created_at),
// момент последнего pull, subject-push (pushed_by), download-count и платформа
// ("<os>/<arch>", "multi-arch" для index). Несуществующий repo → пустой ImageList.Results
// → пустой список (грациозный dangling-ref, не ошибка).
//
// Окно (page_size/page_token) режется по имени тега (ASC) В АДАПТЕРЕ ДО проекции в
// domain.Tag: материализация/аллокация ограничена запрошенной страницей, а не полным
// набором тегов repo (CWE-770 — дешёвый ListTags(page_size=1) иначе аллоцировал бы
// domain.Tag на КАЖДЫЙ тег; паритет с ListRepositories window-before-fan-out). zot
// ImageList не поддерживает server-side keyset — сортируем+режем окно здесь; курсор
// (namepage) байт-совместим с прежней handler-пагинацией. next-token пуст на последней
// странице.
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
	sort.Slice(results, func(i, j int) bool { return results[i].Tag < results[j].Tag })
	window, next, err := namepage.Window(results, func(r gqlImageSummary) string { return r.Tag },
		q.PageSize, q.PageToken)
	if err != nil {
		return nil, "", err
	}
	out := make([]*domain.Tag, 0, len(window))
	for _, r := range window {
		out = append(out, tagFromSummary(q.RegistryID, q.Repository, r))
	}
	return out, next, nil
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

// ---- search-ext GraphQL типы/запросы --------------------------------------

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
		return failClosed("graphql marshal", "err", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/v2/_zot/ext/search", bytes.NewReader(reqBody))
	if err != nil {
		return failClosed("graphql request build", "err", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return failClosed("graphql transport", "err", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return failClosed("graphql non-2xx", "status", resp.StatusCode)
	}
	return decodeGraphQL(resp.Body, maxGraphQLBytes, out)
}

// decodeGraphQL декодирует search-ext GraphQL envelope из body под io.LimitReader(limit)
// и раскладывает поле data в out. Тело сверх лимита → усечение → decode error; непустой
// errors-массив; невалидный data — всё → failClosed ErrUnavailable (сырой zot-текст
// наружу не течёт, оверсайз-ответ деградирует в fail-closed, не в безразмерную аллокацию).
func decodeGraphQL(body io.Reader, limit int64, out any) error {
	var wrapper struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if derr := json.NewDecoder(io.LimitReader(body, limit)).Decode(&wrapper); derr != nil {
		return failClosed("graphql decode", "err", derr)
	}
	if len(wrapper.Errors) > 0 {
		return failClosed("graphql errors", "graphql_error", wrapper.Errors[0].Message,
			"error_count", len(wrapper.Errors))
	}
	if uerr := json.Unmarshal(wrapper.Data, out); uerr != nil {
		return failClosed("graphql data unmarshal", "err", uerr)
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
