// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package zot_test — тесты adapter-клиента к zot против mock-HTTP-сервера.
// Проекции Repository/Tag читаются через search-ext GraphQL (POST /v2/_zot/ext/search:
// GlobalSearch per-repo агрегаты + ImageList теги), а удаление тегов, инфра-статистика
// (Stats) и namespace-проверки — через OCI Distribution / Docker Registry v2 API
// (_catalog, tags/list, manifests HEAD/GET/DELETE). Проверяется namespace-scope проекций,
// агрегация размеров/download-count/artifact-типов, резолв digest перед удалением и
// fail-closed на недоступность zot. Имена тестов трассируются к acceptance-сценариям (REG-NN).
package zot_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	registry "github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/api/registry"
	zotclient "github.com/PRO-Robotech/kacho-registry/internal/clients/zot"
	"github.com/PRO-Robotech/kacho-registry/internal/domain"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// config.mediaType дискриминаторы artifact-типа (для GraphQL Manifests[].ArtifactType).
const (
	configOCIImage   = "application/vnd.oci.image.config.v1+json"
	configHelm       = "application/vnd.cncf.helm.config.v1+json"
	mediaOCIManifest = "application/vnd.oci.image.manifest.v1+json"
	mediaOCIIndex    = "application/vnd.oci.image.index.v1+json"
)

// zotNever — zot-эпоха "никогда" для pull/push-таймстампа.
const zotNever = "1970-01-01T00:00:00Z"

// manifestFixture — образ манифеста repo/tag в mock-zot (Distribution-API path): digest +
// config/layers для расчёта размеров и уникальных блобов Stats.
type manifestFixture struct {
	digest    string
	mediaType string
	configSz  int64
	layerSz   []int64
	body      []byte
}

// gqlTag — фикстура тега для search-ext GraphQL (ImageList). size — байты образа;
// pushTS/pullTS — RFC3339 (zotNever = никогда); configMedia — config.mediaType
// (дискриминатор helm/container); multiArch — образ несёт >1 манифеста (index).
type gqlTag struct {
	tag           string
	digest        string
	mediaType     string
	size          int64
	pushTS        string
	pullTS        string
	configMedia   string
	os            string
	arch          string
	downloadCount int64
	pushedBy      string
	multiArch     bool
}

// gqlRepoFixture — per-repo GraphQL-фикстура: GlobalSearch-агрегаты + теги ImageList.
type gqlRepoFixture struct {
	size          int64
	lastUpdated   string
	downloadCount int64
	tags          []gqlTag
}

// fakeZot — mock zot. repos: full-repo-name → tag → манифест (Distribution-API);
// gqlRepos: full-repo-name → GraphQL-фикстура (search-ext).
type fakeZot struct {
	repos        map[string]map[string]manifestFixture
	blobs        map[string][]byte          // content-addressable blob-store
	deleted      []string                   // записанные DELETE digest'ы
	failCatalog  bool                       // 500 на _catalog (эмуляция недоступности)
	failManifest map[string]bool            // full-repo → 500 на GET манифеста
	gqlRepos     map[string]*gqlRepoFixture // search-ext GraphQL-фикстуры
	gqlFail      bool                       // 500 на GraphQL (транспортная недоступность)
	gqlErrors    bool                       // непустой errors-массив в GraphQL-ответе

	imageListCalls atomic.Int64 // счётчик ImageList-round-trip (bound fan-out)
}

func newFakeZot() *fakeZot {
	return &fakeZot{
		repos:        map[string]map[string]manifestFixture{},
		blobs:        map[string][]byte{},
		failManifest: map[string]bool{},
		gqlRepos:     map[string]*gqlRepoFixture{},
	}
}

// put регистрирует tag в repo с манифестом (config + layers) для Distribution-API path.
func (f *fakeZot) put(repo, tag, digest string, configSz int64, layers ...int64) {
	body, _ := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     mediaOCIManifest,
		"config":        map[string]any{"mediaType": configOCIImage, "size": configSz, "digest": "sha256:cfg" + digest},
		"layers": func() []any {
			out := make([]any, 0, len(layers))
			for i, sz := range layers {
				out = append(out, map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "size": sz, "digest": "sha256:l" + digest + string(rune('a'+i))})
			}
			return out
		}(),
	})
	if f.repos[repo] == nil {
		f.repos[repo] = map[string]manifestFixture{}
	}
	f.repos[repo][tag] = manifestFixture{
		digest:    digest,
		mediaType: mediaOCIManifest,
		configSz:  configSz,
		layerSz:   layers,
		body:      body,
	}
}

// gqlRepo лениво создаёт/возвращает GraphQL-фикстуру repo.
func (f *fakeZot) gqlRepo(name string) *gqlRepoFixture {
	fx := f.gqlRepos[name]
	if fx == nil {
		fx = &gqlRepoFixture{}
		f.gqlRepos[name] = fx
	}
	return fx
}

// addGqlTag добавляет тег в GraphQL-фикстуру repo (порядок сохраняется в Results).
func (f *fakeZot) addGqlTag(repo string, t gqlTag) {
	fx := f.gqlRepo(repo)
	fx.tags = append(fx.tags, t)
}

// setGqlAgg выставляет per-repo GlobalSearch-агрегаты (размер/last-update/download-count).
func (f *fakeZot) setGqlAgg(repo string, size int64, lastUpdated string, downloadCount int64) {
	fx := f.gqlRepo(repo)
	fx.size = size
	fx.lastUpdated = lastUpdated
	fx.downloadCount = downloadCount
}

func (f *fakeZot) manifestByRef(repo, ref string) (manifestFixture, bool) {
	tags := f.repos[repo]
	if tags == nil {
		return manifestFixture{}, false
	}
	if m, ok := tags[ref]; ok {
		return m, true
	}
	for _, m := range tags {
		if m.digest == ref {
			return m, true
		}
	}
	return manifestFixture{}, false
}

func (f *fakeZot) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case path == "/v2/_zot/ext/search":
			f.handleGraphQL(w, r)
		case path == "/v2/" || path == "/v2":
			w.WriteHeader(http.StatusOK)
		case path == "/v2/_catalog":
			if f.failCatalog {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			names := make([]string, 0, len(f.repos))
			for name := range f.repos {
				names = append(names, name)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"repositories": names})
		case strings.HasSuffix(path, "/tags/list"):
			repo := strings.TrimSuffix(strings.TrimPrefix(path, "/v2/"), "/tags/list")
			tags := f.repos[repo]
			if tags == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			names := make([]string, 0, len(tags))
			for tag := range tags {
				names = append(names, tag)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"name": repo, "tags": names})
		case strings.Contains(path, "/manifests/"):
			f.handleManifest(w, r)
		case strings.Contains(path, "/blobs/"):
			digest := path[strings.Index(path, "/blobs/")+len("/blobs/"):]
			b, ok := f.blobs[digest]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write(b)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (f *fakeZot) handleManifest(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v2/")
	i := strings.Index(rest, "/manifests/")
	repo := rest[:i]
	ref := rest[i+len("/manifests/"):]
	m, ok := f.manifestByRef(repo, ref)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	switch r.Method {
	case http.MethodDelete:
		f.deleted = append(f.deleted, ref)
		w.WriteHeader(http.StatusAccepted)
	case http.MethodHead:
		w.Header().Set("Docker-Content-Digest", m.digest)
		w.Header().Set("Content-Type", m.mediaType)
		w.Header().Set("Content-Length", strconv.Itoa(len(m.body)))
		w.WriteHeader(http.StatusOK)
	default: // GET
		if f.failManifest[repo] {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Docker-Content-Digest", m.digest)
		w.Header().Set("Content-Type", m.mediaType)
		_, _ = w.Write(m.body)
	}
}

// gqlArgRe извлекает строковый аргумент GraphQL (repo:"..." / query:"...").
var gqlArgRe = regexp.MustCompile(`(repo|query):"([^"]*)"`)

func extractGqlArg(query, name string) string {
	for _, m := range gqlArgRe.FindAllStringSubmatch(query, -1) {
		if m[1] == name {
			return m[2]
		}
	}
	return ""
}

// handleGraphQL эмулирует search-ext: GlobalSearch (per-repo агрегаты) и ImageList
// (теги repo). gqlFail → 500 (транспорт); gqlErrors → непустой errors-массив.
func (f *fakeZot) handleGraphQL(w http.ResponseWriter, r *http.Request) {
	if f.gqlFail {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	var req struct {
		Query string `json:"query"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if f.gqlErrors {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data":   nil,
			"errors": []map[string]any{{"message": "boom"}},
		})
		return
	}
	switch {
	case strings.Contains(req.Query, "GlobalSearch"):
		f.writeGlobalSearch(w, req.Query)
	case strings.Contains(req.Query, "ImageList"):
		f.writeImageList(w, req.Query)
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

func (f *fakeZot) writeGlobalSearch(w http.ResponseWriter, query string) {
	prefix := extractGqlArg(query, "query")
	names := make([]string, 0, len(f.gqlRepos))
	for name := range f.gqlRepos {
		names = append(names, name)
	}
	sort.Strings(names)
	repos := make([]map[string]any, 0, len(names))
	for _, name := range names {
		if !strings.HasPrefix(name, prefix) {
			continue // GlobalSearch — namespace-scoped (substring по префиксу)
		}
		fx := f.gqlRepos[name]
		repos = append(repos, map[string]any{
			"Name":          name,
			"Size":          strconv.FormatInt(fx.size, 10),
			"LastUpdated":   fx.lastUpdated,
			"DownloadCount": fx.downloadCount,
		})
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"data": map[string]any{"GlobalSearch": map[string]any{"Repos": repos}},
	})
}

func (f *fakeZot) writeImageList(w http.ResponseWriter, query string) {
	f.imageListCalls.Add(1)
	repo := extractGqlArg(query, "repo")
	fx := f.gqlRepos[repo]
	results := make([]map[string]any, 0)
	if fx != nil {
		for _, t := range fx.tags {
			manifests := []map[string]any{
				{"ArtifactType": t.configMedia, "Platform": map[string]any{"Os": t.os, "Arch": t.arch}},
			}
			if t.multiArch { // >1 манифест → клиент помечает "multi-arch"
				manifests = append(manifests, map[string]any{
					"ArtifactType": t.configMedia, "Platform": map[string]any{"Os": "linux", "Arch": "arm64"},
				})
			}
			results = append(results, map[string]any{
				"Tag":               t.tag,
				"Digest":            t.digest,
				"MediaType":         t.mediaType,
				"Size":              strconv.FormatInt(t.size, 10),
				"DownloadCount":     t.downloadCount,
				"PushTimestamp":     t.pushTS,
				"LastPullTimestamp": t.pullTS,
				"PushedBy":          t.pushedBy,
				"Manifests":         manifests,
			})
		}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"data": map[string]any{"ImageList": map[string]any{"Results": results}},
	})
}

// containerTag / helmTag — фикстура-конструкторы для читаемости тестов.
func containerTag(tag, digest string, size int64, os, arch string) gqlTag {
	return gqlTag{
		tag: tag, digest: digest, mediaType: mediaOCIManifest, size: size,
		configMedia: configOCIImage, os: os, arch: arch,
		pushTS: "2026-01-01T00:00:00Z", pullTS: zotNever,
	}
}

func helmTag(tag, digest string, size int64) gqlTag {
	return gqlTag{
		tag: tag, digest: digest, mediaType: mediaOCIManifest, size: size,
		configMedia: configHelm, pushTS: "2026-01-01T00:00:00Z", pullTS: zotNever,
	}
}

// REG-22 — ListRepositories возвращает repos ТОЛЬКО своего namespace (prefix
// <registryID>/), без namespace-prefix в имени, с tag_count из ImageList; чужой
// namespace не течёт (GlobalSearch namespace-scoped).
func TestZot_REG22_ListRepositories_NamespaceScoped(t *testing.T) {
	fz := newFakeZot()
	fz.addGqlTag("reg-A/app", containerTag("v1", "sha256:app1", 310, "linux", "amd64"))
	fz.addGqlTag("reg-A/app", containerTag("v2", "sha256:app2", 110, "linux", "amd64"))
	fz.addGqlTag("reg-A/web", containerTag("v1", "sha256:web1", 60, "linux", "amd64"))
	fz.addGqlTag("reg-B/secret", containerTag("v1", "sha256:sec1", 500, "linux", "amd64"))
	srv := fz.server(t)

	cli := zotclient.New(srv.URL)
	repos, _, err := cli.ListRepositories(t.Context(), registry.RepoListQuery{RegistryID: "reg-A"})
	require.NoError(t, err)

	byName := map[string]int32{}
	for _, r := range repos {
		require.Equal(t, "reg-A", r.RegistryID)
		require.NotContains(t, r.Name, "reg-A/", "namespace-prefix stripped from repo name")
		byName[r.Name] = r.TagCount
	}
	require.Len(t, repos, 2, "only reg-A/* repos; reg-B not leaked")
	require.Equal(t, int32(2), byName["app"], "app has 2 tags")
	require.Equal(t, int32(1), byName["web"])
	require.NotContains(t, byName, "secret", "cross-namespace not leaked")
	// Результат отсортирован по имени.
	require.Equal(t, "app", repos[0].Name)
	require.Equal(t, "web", repos[1].Name)
}

// REG-DOS — ListRepositories режет ОКНО (page_size) ДО per-repo ImageList-fan-out:
// при большом namespace дешёвый запрос НЕ разворачивается в N round-trip к zot. Регресс-
// гейт против CWE-770 memory/backend-амплификации на уровне адаптера.
func TestZot_ListRepositories_PaginatedBoundsImageListFanout(t *testing.T) {
	fz := newFakeZot()
	const total = 60
	for i := 0; i < total; i++ {
		name := "reg-A/repo-" + strconv.Itoa(1000+i) // 1000.. → лексикографически стабильно
		fz.addGqlTag(name, containerTag("v1", "sha256:d"+strconv.Itoa(i), 100, "linux", "amd64"))
	}
	srv := fz.server(t)
	cli := zotclient.New(srv.URL)

	repos, next, err := cli.ListRepositories(t.Context(),
		registry.RepoListQuery{RegistryID: "reg-A", PageSize: 5})
	require.NoError(t, err)
	require.Len(t, repos, 5, "страница ограничена page_size")
	require.NotEmpty(t, next, "есть ещё репо → next-token")
	require.Equal(t, int64(5), fz.imageListCalls.Load(),
		"ImageList fan-out ограничен окном (5), а не всей проекцией (%d)", total)

	// Курсор доводит до всех репо: следующая страница продолжает без пропусков.
	fz.imageListCalls.Store(0)
	repos2, _, err := cli.ListRepositories(t.Context(),
		registry.RepoListQuery{RegistryID: "reg-A", PageSize: 5, PageToken: next})
	require.NoError(t, err)
	require.Len(t, repos2, 5)
	require.Equal(t, int64(5), fz.imageListCalls.Load(), "вторая страница — тоже только окно")
	require.Equal(t, "repo-1005", repos2[0].Name, "продолжение строго после курсора первой страницы")
}

// REG-22 — ListRepositories агрегирует размер/last-update/download-count из GlobalSearch,
// tag_count из ImageList, а artifact_types — из типов тегов. Mixed-repo (docker + helm)
// несёт ОБА типа; ghost (0 тегов) скрывается.
func TestZot_REG22_ListRepositories_AggregatesAndMixedArtifactTypes(t *testing.T) {
	fz := newFakeZot()
	// mixed: контейнерный образ + helm-чарт → ArtifactTypes = [CONTAINER_IMAGE, HELM_CHART].
	fz.addGqlTag("reg-A/mixed", containerTag("app-v1", "sha256:c1", 300, "linux", "amd64"))
	fz.addGqlTag("reg-A/mixed", helmTag("chart-1", "sha256:h1", 40))
	fz.setGqlAgg("reg-A/mixed", 1000, "2026-03-01T12:00:00Z", 42)
	// ghost: агрегат есть, тегов нет → скрывается.
	fz.setGqlAgg("reg-A/ghost", 0, "2026-01-01T00:00:00Z", 0)
	srv := fz.server(t)

	cli := zotclient.New(srv.URL)
	repos, _, err := cli.ListRepositories(t.Context(), registry.RepoListQuery{RegistryID: "reg-A"})
	require.NoError(t, err)
	require.Len(t, repos, 1, "ghost repo (0 тегов) скрыт")

	r := repos[0]
	require.Equal(t, "mixed", r.Name)
	require.Equal(t, int32(2), r.TagCount)
	require.Equal(t, int64(1000), r.SizeBytes, "size из GlobalSearch, не Σ тегов")
	require.Equal(t, int64(42), r.DownloadCount, "download-count из GlobalSearch")
	require.Equal(t, 2026, r.UpdatedAt.Year())
	require.Equal(t, time.March, r.UpdatedAt.Month())
	require.Equal(t, []domain.ArtifactType{domain.ArtifactTypeContainerImage, domain.ArtifactTypeHelmChart}, r.ArtifactTypes,
		"mixed repo несёт оба типа, порядок по первому появлению")
	require.Equal(t, domain.ArtifactTypeContainerImage, r.ArtifactType, "primary = первый из набора")
}

// REG-22 — GlobalSearch-агрегаты пусты → fallback на суммы/максимум по тегам ImageList.
func TestZot_REG22_ListRepositories_AggregateFallback(t *testing.T) {
	fz := newFakeZot()
	t1 := containerTag("v1", "sha256:a", 100, "linux", "amd64")
	t1.pushTS = "2026-02-01T00:00:00Z"
	t1.downloadCount = 3
	t2 := containerTag("v2", "sha256:b", 250, "linux", "amd64")
	t2.pushTS = "2026-05-05T00:00:00Z"
	t2.downloadCount = 4
	fz.addGqlTag("reg-A/svc", t1)
	fz.addGqlTag("reg-A/svc", t2)
	// НЕ вызываем setGqlAgg → GlobalSearch отдаёт size=0/last-update=""/dl=0.
	srv := fz.server(t)

	cli := zotclient.New(srv.URL)
	repos, _, err := cli.ListRepositories(t.Context(), registry.RepoListQuery{RegistryID: "reg-A"})
	require.NoError(t, err)
	require.Len(t, repos, 1)
	r := repos[0]
	require.Equal(t, int64(350), r.SizeBytes, "fallback: Σ размеров тегов")
	require.Equal(t, int64(7), r.DownloadCount, "fallback: Σ download-count тегов")
	require.Equal(t, time.May, r.UpdatedAt.Month(), "fallback: max PushTimestamp")
}

// ListRepositories — repo с НУЛЁМ тегов (все удалены, запись осталась до GC) скрывается
// из проекции: пустой repo для tenant'а эквивалентен удалённому.
func TestZot_ListRepositories_HidesEmptyRepo(t *testing.T) {
	fz := newFakeZot()
	fz.addGqlTag("reg-A/live", containerTag("v1", "sha256:live1", 110, "linux", "amd64"))
	fz.setGqlAgg("reg-A/ghost", 5, "2026-01-01T00:00:00Z", 1) // GlobalSearch помнит, тегов нет
	srv := fz.server(t)

	cli := zotclient.New(srv.URL)
	repos, _, err := cli.ListRepositories(t.Context(), registry.RepoListQuery{RegistryID: "reg-A"})
	require.NoError(t, err)
	require.Len(t, repos, 1, "ghost repo (0 тегов) скрыт")
	require.Equal(t, "live", repos[0].Name)
}

// REG-24 — ListTags возвращает теги repo с digest + размером образа (Size из GraphQL) +
// платформой из манифеста; source of truth = zot.
func TestZot_REG24_ListTags_DigestAndSize(t *testing.T) {
	fz := newFakeZot()
	fz.addGqlTag("reg-A/app", containerTag("v1", "sha256:app1", 310, "linux", "amd64"))
	fz.addGqlTag("reg-A/app", containerTag("v2", "sha256:app2", 110, "linux", "amd64"))
	srv := fz.server(t)

	cli := zotclient.New(srv.URL)
	tags, _, err := cli.ListTags(t.Context(), registry.TagListQuery{RegistryID: "reg-A", Repository: "app"})
	require.NoError(t, err)
	require.Len(t, tags, 2)

	byTag := map[string]*domain.Tag{}
	for _, tg := range tags {
		require.Equal(t, "reg-A", tg.RegistryID)
		require.Equal(t, "app", tg.Repository)
		require.NotEmpty(t, tg.Digest, "digest из ImageList")
		byTag[tg.Tag] = tg
	}
	require.Equal(t, "sha256:app1", byTag["v1"].Digest)
	require.Equal(t, "sha256:app2", byTag["v2"].Digest)
	require.Equal(t, int64(310), byTag["v1"].SizeBytes)
	require.Equal(t, int64(110), byTag["v2"].SizeBytes)
	require.Equal(t, "linux/amd64", byTag["v1"].Architecture, "платформа из манифеста")
}

// ListTags — платформа, момент push (created_at), last-pull, pushed-by и download-count
// проецируются из ImageList (search-ext), не из манифеста.
func TestZot_ListTags_ProjectsGraphQLFields(t *testing.T) {
	fz := newFakeZot()
	tg := gqlTag{
		tag: "v1", digest: "sha256:img1", mediaType: mediaOCIManifest, size: 312,
		configMedia: configOCIImage, os: "linux", arch: "arm64",
		pushTS: "2026-02-03T10:20:30Z", pullTS: "2026-02-05T08:00:00Z",
		pushedBy: "user:alice", downloadCount: 7,
	}
	fz.addGqlTag("reg-A/img", tg)
	srv := fz.server(t)

	cli := zotclient.New(srv.URL)
	tags, _, err := cli.ListTags(t.Context(), registry.TagListQuery{RegistryID: "reg-A", Repository: "img"})
	require.NoError(t, err)
	require.Len(t, tags, 1)
	got := tags[0]
	require.Equal(t, int64(312), got.SizeBytes)
	require.Equal(t, "linux/arm64", got.Architecture)
	require.Equal(t, 2026, got.CreatedAt.Year(), "created_at = PushTimestamp")
	require.Equal(t, time.February, got.CreatedAt.Month())
	require.Equal(t, 3, got.CreatedAt.Day())
	require.Equal(t, 5, got.LastPulledAt.Day(), "last_pulled_at = LastPullTimestamp")
	require.Equal(t, "user:alice", got.PushedBy)
	require.Equal(t, int64(7), got.DownloadCount)
}

// ListTags — pull-таймстамп "1970-…" (никогда не скачивался) → нулевой LastPulledAt.
func TestZot_ListTags_NeverPulled_ZeroTime(t *testing.T) {
	fz := newFakeZot()
	fz.addGqlTag("reg-A/app", containerTag("v1", "sha256:app1", 100, "linux", "amd64")) // pullTS = zotNever
	srv := fz.server(t)

	cli := zotclient.New(srv.URL)
	tags, _, err := cli.ListTags(t.Context(), registry.TagListQuery{RegistryID: "reg-A", Repository: "app"})
	require.NoError(t, err)
	require.Len(t, tags, 1)
	require.True(t, tags[0].LastPulledAt.IsZero(), "1970-эпоха zot = никогда → zero time")
}

// ListTags — образ с >1 манифестом (multi-arch index) → Architecture == "multi-arch".
func TestZot_ListTags_MultiArch(t *testing.T) {
	fz := newFakeZot()
	fz.addGqlTag("reg-A/multi", gqlTag{
		tag: "v1", digest: "sha256:multi1", mediaType: mediaOCIIndex, size: 900,
		configMedia: configOCIImage, os: "linux", arch: "amd64",
		pushTS: "2026-01-01T00:00:00Z", pullTS: zotNever, multiArch: true,
	})
	srv := fz.server(t)

	cli := zotclient.New(srv.URL)
	tags, _, err := cli.ListTags(t.Context(), registry.TagListQuery{RegistryID: "reg-A", Repository: "multi"})
	require.NoError(t, err)
	require.Len(t, tags, 1)
	require.Equal(t, "multi-arch", tags[0].Architecture)
}

// SEC (CWE-770) — ListTags режет ОКНО (page_size) по имени тега (ASC) В АДАПТЕРЕ ДО
// проекции в domain.Tag — материализация/аллокация ограничена запрошенной страницей,
// а не полным набором тегов repo (паритет с ListRepositories window-before-fan-out).
// Курсор (opaque base64 имени) байт-совместим с прежней handler-пагинацией.
func TestZot_ListTags_PaginatedWindowByName(t *testing.T) {
	fz := newFakeZot()
	// Порядок в Results намеренно НЕ отсортирован — адаптер обязан сортировать по имени.
	fz.addGqlTag("reg-A/app", containerTag("v3", "sha256:t3", 30, "linux", "amd64"))
	fz.addGqlTag("reg-A/app", containerTag("v1", "sha256:t1", 10, "linux", "amd64"))
	fz.addGqlTag("reg-A/app", containerTag("v2", "sha256:t2", 20, "linux", "amd64"))
	srv := fz.server(t)
	cli := zotclient.New(srv.URL)

	// Первая страница (size=2) — первые два имени ASC (v1, v2) + next-token.
	page1, next, err := cli.ListTags(t.Context(),
		registry.TagListQuery{RegistryID: "reg-A", Repository: "app", PageSize: 2})
	require.NoError(t, err)
	require.Len(t, page1, 2, "окно size=2, а не весь набор тегов")
	require.Equal(t, "v1", page1[0].Tag)
	require.Equal(t, "v2", page1[1].Tag)
	require.NotEmpty(t, next, "есть ещё теги → non-empty next-token")

	// Вторая страница (по next-token) — остаток (v3), next пуст.
	page2, next2, err := cli.ListTags(t.Context(),
		registry.TagListQuery{RegistryID: "reg-A", Repository: "app", PageSize: 2, PageToken: next})
	require.NoError(t, err)
	require.Len(t, page2, 1)
	require.Equal(t, "v3", page2[0].Tag)
	require.Empty(t, next2, "последняя страница → пустой next-token")
}

// REG-24 — ListTags на несуществующий repo → пустой список (грациозный dangling-ref, не
// ошибка): ImageList отдаёт пустой Results, репо GC-нут — не 500.
func TestZot_REG24_ListTags_MissingRepo_Empty(t *testing.T) {
	fz := newFakeZot()
	srv := fz.server(t)
	cli := zotclient.New(srv.URL)
	tags, _, err := cli.ListTags(t.Context(), registry.TagListQuery{RegistryID: "reg-A", Repository: "ghost"})
	require.NoError(t, err)
	require.Empty(t, tags)
}

// ListTags / ListRepositories — непустой errors-массив GraphQL → fail-closed Unavailable
// (не отдаём частичную/stale-проекцию).
func TestZot_GraphQL_Errors_FailClosed(t *testing.T) {
	fz := newFakeZot()
	fz.gqlErrors = true
	srv := fz.server(t)
	cli := zotclient.New(srv.URL)

	_, _, err := cli.ListTags(t.Context(), registry.TagListQuery{RegistryID: "reg-A", Repository: "app"})
	require.ErrorIs(t, err, regerrors.ErrUnavailable)
	_, _, err = cli.ListRepositories(t.Context(), registry.RepoListQuery{RegistryID: "reg-A"})
	require.ErrorIs(t, err, regerrors.ErrUnavailable)
}

// ListTags / ListRepositories — GraphQL 5xx (транспорт) → fail-closed Unavailable.
func TestZot_GraphQL_Transport_FailClosed(t *testing.T) {
	fz := newFakeZot()
	fz.gqlFail = true
	srv := fz.server(t)
	cli := zotclient.New(srv.URL)

	_, _, err := cli.ListTags(t.Context(), registry.TagListQuery{RegistryID: "reg-A", Repository: "app"})
	require.ErrorIs(t, err, regerrors.ErrUnavailable)
	_, _, err = cli.ListRepositories(t.Context(), registry.RepoListQuery{RegistryID: "reg-A"})
	require.ErrorIs(t, err, regerrors.ErrUnavailable)
}

// REG-25 — DeleteTag резолвит digest тега (HEAD) и удаляет манифест по digest
// (DELETE /manifests/<digest>) — Distribution-API path.
func TestZot_REG25_DeleteTag_ResolvesDigest(t *testing.T) {
	fz := newFakeZot()
	fz.put("reg-A/app", "v1", "sha256:app1", 10, 100)
	srv := fz.server(t)

	cli := zotclient.New(srv.URL)
	require.NoError(t, cli.DeleteTag(t.Context(), "reg-A", "app", "v1"))
	require.Contains(t, fz.deleted, "sha256:app1", "delete by resolved digest, not by tag")
}

// REG-25 — DeleteTag на отсутствующий тег идемпотентен (already-gone → success).
func TestZot_REG25_DeleteTag_Idempotent(t *testing.T) {
	fz := newFakeZot()
	srv := fz.server(t)
	cli := zotclient.New(srv.URL)
	require.NoError(t, cli.DeleteTag(t.Context(), "reg-A", "app", "nope"))
}

// REG-08 — NamespaceEmpty: true когда ни один repo не начинается с <registryID>/;
// false когда есть хоть один (Distribution-API _catalog).
func TestZot_REG08_NamespaceEmpty(t *testing.T) {
	fz := newFakeZot()
	fz.put("reg-A/app", "v1", "sha256:app1", 10, 100)
	srv := fz.server(t)
	cli := zotclient.New(srv.URL)

	empty, err := cli.NamespaceEmpty(t.Context(), "reg-A")
	require.NoError(t, err)
	require.False(t, empty, "reg-A has repos")

	empty, err = cli.NamespaceEmpty(t.Context(), "reg-Z")
	require.NoError(t, err)
	require.True(t, empty, "reg-Z has no repos")
}

// REG-38 — Stats агрегирует namespace: repo/tag count, суммарный размер (config +
// layers) и число уникальных блобов (infra-проекция, только Internal-API; Distribution-API).
func TestZot_REG38_Stats_Aggregates(t *testing.T) {
	fz := newFakeZot()
	fz.put("reg-A/app", "v1", "sha256:app1", 10, 100, 200)
	fz.put("reg-A/web", "v1", "sha256:web1", 10, 50)
	srv := fz.server(t)

	cli := zotclient.New(srv.URL)
	stats, err := cli.Stats(t.Context(), "reg-A")
	require.NoError(t, err)
	require.Equal(t, "reg-A", stats.RegistryID)
	require.Equal(t, int32(2), stats.RepositoryCount)
	require.Equal(t, int32(2), stats.TagCount)
	require.Greater(t, stats.TotalSizeBytes, int64(0))
	require.Greater(t, stats.BlobCount, int64(0))
}

// REG-38 — TriggerGC проверяет достижимость zot и подтверждает (реальная рекламация —
// native-scheduler zot); недоступность → fail-closed.
func TestZot_REG38_TriggerGC(t *testing.T) {
	fz := newFakeZot()
	srv := fz.server(t)
	cli := zotclient.New(srv.URL)
	require.NoError(t, cli.TriggerGC(t.Context(), "reg-A"))
}

// REG-08/REG-22 edge — zot не сконфигурирован (пустой endpoint) → все проекции и
// проверки fail-closed Unavailable (не отдают stale-фикцию, не «считаем пустым»).
func TestZot_FailClosed_Unavailable(t *testing.T) {
	cli := zotclient.New("") // endpoint не подан → Unavailable
	_, _, err := cli.ListRepositories(t.Context(), registry.RepoListQuery{RegistryID: "reg-A"})
	require.ErrorIs(t, err, regerrors.ErrUnavailable)
	_, _, err = cli.ListTags(t.Context(), registry.TagListQuery{RegistryID: "reg-A", Repository: "app"})
	require.ErrorIs(t, err, regerrors.ErrUnavailable)
	_, err = cli.NamespaceEmpty(t.Context(), "reg-A")
	require.ErrorIs(t, err, regerrors.ErrUnavailable)
}

// REG-08 edge — zot возвращает 5xx на _catalog при NamespaceEmpty → Unavailable
// (fail-closed: НЕ «считаем пустым и удаляем»).
func TestZot_REG08_NamespaceEmpty_ZotError_FailClosed(t *testing.T) {
	fz := newFakeZot()
	fz.failCatalog = true
	srv := fz.server(t)
	cli := zotclient.New(srv.URL)
	_, err := cli.NamespaceEmpty(t.Context(), "reg-A")
	require.ErrorIs(t, err, regerrors.ErrUnavailable)
}
