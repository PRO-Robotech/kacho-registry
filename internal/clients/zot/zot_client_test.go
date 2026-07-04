// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package zot_test — тесты adapter-клиента к zot против mock-HTTP-сервера,
// эмулирующего OCI Distribution / Docker Registry v2 API (_catalog, tags/list,
// manifests HEAD/GET/DELETE). Проверяет namespace-prefix-фильтр проекций, резолв
// digest перед удалением, инфра-статистику и fail-closed на недоступность zot.
// Имена тестов трассируются к acceptance-сценариям (REG-NN).
package zot_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	registry "github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/api/registry"
	zotclient "github.com/PRO-Robotech/kacho-registry/internal/clients/zot"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// manifestFixture — образ манифеста repo/tag в mock-zot: digest + config/layers для
// расчёта размеров и уникальных блобов Stats.
type manifestFixture struct {
	digest    string
	mediaType string
	configSz  int64
	layerSz   []int64
	body      []byte
}

// fakeZot — mock OCI-реестра. repos: full-repo-name (с namespace-prefix) → tag → манифест.
type fakeZot struct {
	repos        map[string]map[string]manifestFixture
	blobs        map[string][]byte // content-addressable blob-store: config-digest → тело
	deleted      []string          // записанные DELETE digest'ы
	failCatalog  bool              // 500 на _catalog (эмуляция недоступности)
	failManifest map[string]bool   // full-repo → 500 на GET манифеста (best-effort classify)
}

func newFakeZot() *fakeZot {
	return &fakeZot{
		repos:        map[string]map[string]manifestFixture{},
		blobs:        map[string][]byte{},
		failManifest: map[string]bool{},
	}
}

// put регистрирует tag в repo с манифестом (config + layers), проставляя digest
// и сериализованное тело OCI-манифеста.
func (f *fakeZot) put(repo, tag, digest string, configSz int64, layers ...int64) {
	body, _ := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.manifest.v1+json",
		"config":        map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "size": configSz, "digest": "sha256:cfg" + digest},
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
		mediaType: "application/vnd.oci.image.manifest.v1+json",
		configSz:  configSz,
		layerSz:   layers,
		body:      body,
	}
	// image-config blob (по умолчанию — платформа linux/amd64, без created) под
	// config-digest; тест может переопределить f.blobs[...] для created/иной платформы.
	if f.blobs["sha256:cfg"+digest] == nil {
		f.blobs["sha256:cfg"+digest] = []byte(`{"architecture":"amd64","os":"linux"}`)
	}
}

func (f *fakeZot) manifestByRef(repo, ref string) (manifestFixture, bool) {
	tags := f.repos[repo]
	if tags == nil {
		return manifestFixture{}, false
	}
	if m, ok := tags[ref]; ok {
		return m, true
	}
	// ref может быть digest'ом.
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
		// best-effort classify: манифест-репрезентант может флейкнуть 5xx, при
		// живых _catalog/tags/list — тогда тип остаётся UNSPECIFIED, список жив.
		if f.failManifest[repo] {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Docker-Content-Digest", m.digest)
		w.Header().Set("Content-Type", m.mediaType)
		_, _ = w.Write(m.body)
	}
}

// REG-22 — ListRepositories возвращает repos ТОЛЬКО своего namespace (prefix
// <registryID>/), без namespace-prefix в имени, с tag_count из tags/list; чужой
// namespace не течёт.
func TestZot_REG22_ListRepositories_NamespaceScoped(t *testing.T) {
	fz := newFakeZot()
	fz.put("reg-A/app", "v1", "sha256:app1", 10, 100, 200)
	fz.put("reg-A/app", "v2", "sha256:app2", 10, 100)
	fz.put("reg-A/web", "v1", "sha256:web1", 10, 50)
	fz.put("reg-B/secret", "v1", "sha256:sec1", 10, 500)
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
}

// REG-24 — ListTags возвращает теги repo с digest + РЕАЛЬНЫМ размером образа
// (config + Σlayers, НЕ размер манифеста) + платформой из image-config; source of
// truth = zot.
func TestZot_REG24_ListTags_DigestAndSize(t *testing.T) {
	fz := newFakeZot()
	fz.put("reg-A/app", "v1", "sha256:app1", 10, 100, 200)
	fz.put("reg-A/app", "v2", "sha256:app2", 10, 100)
	srv := fz.server(t)

	cli := zotclient.New(srv.URL)
	tags, _, err := cli.ListTags(t.Context(), registry.TagListQuery{RegistryID: "reg-A", Repository: "app"})
	require.NoError(t, err)
	require.Len(t, tags, 2)

	byTag := map[string]*struct {
		digest string
		size   int64
		arch   string
	}{}
	for _, tg := range tags {
		require.Equal(t, "reg-A", tg.RegistryID)
		require.Equal(t, "app", tg.Repository)
		require.NotEmpty(t, tg.Digest, "digest resolved via manifest GET")
		byTag[tg.Tag] = &struct {
			digest string
			size   int64
			arch   string
		}{tg.Digest, tg.SizeBytes, tg.Architecture}
	}
	require.Equal(t, "sha256:app1", byTag["v1"].digest)
	require.Equal(t, "sha256:app2", byTag["v2"].digest)
	require.Equal(t, int64(310), byTag["v1"].size, "config(10)+layers(100+200)")
	require.Equal(t, int64(110), byTag["v2"].size, "config(10)+layer(100)")
	require.Equal(t, "linux/amd64", byTag["v1"].arch, "платформа из image-config")
}

// ListTags — платформа и created берутся из image-config blob (не из манифеста).
func TestZot_ListTags_ArchitectureAndCreated(t *testing.T) {
	fz := newFakeZot()
	fz.put("reg-A/img", "v1", "sha256:img1", 12, 300)
	// Переопределяем config-blob: иная платформа + created (RFC3339).
	fz.blobs["sha256:cfgsha256:img1"] = []byte(`{"architecture":"arm64","os":"linux","created":"2026-02-03T10:20:30Z"}`)
	srv := fz.server(t)

	cli := zotclient.New(srv.URL)
	tags, _, err := cli.ListTags(t.Context(), registry.TagListQuery{RegistryID: "reg-A", Repository: "img"})
	require.NoError(t, err)
	require.Len(t, tags, 1)
	require.Equal(t, int64(312), tags[0].SizeBytes, "config(12)+layer(300)")
	require.Equal(t, "linux/arm64", tags[0].Architecture)
	require.Equal(t, 2026, tags[0].CreatedAt.Year())
	require.Equal(t, time.February, tags[0].CreatedAt.Month())
	require.Equal(t, 3, tags[0].CreatedAt.Day())
}

// ListRepositories — repo с НУЛЁМ тегов (все удалены, запись в _catalog осталась до
// GC) скрывается из проекции: пустой repo для tenant'а эквивалентен удалённому.
func TestZot_ListRepositories_HidesEmptyRepo(t *testing.T) {
	fz := newFakeZot()
	fz.put("reg-A/live", "v1", "sha256:live1", 10, 100)
	fz.repos["reg-A/ghost"] = map[string]manifestFixture{} // _catalog помнит, тегов нет
	srv := fz.server(t)

	cli := zotclient.New(srv.URL)
	repos, _, err := cli.ListRepositories(t.Context(), registry.RepoListQuery{RegistryID: "reg-A"})
	require.NoError(t, err)
	require.Len(t, repos, 1, "ghost repo (0 тегов) скрыт")
	require.Equal(t, "live", repos[0].Name)
}

// REG-24 — ListTags на несуществующий repo → пустой список (грациозный dangling-ref,
// не ошибка): проекция read-only, репо GC-нут — не 500.
func TestZot_REG24_ListTags_MissingRepo_Empty(t *testing.T) {
	fz := newFakeZot()
	srv := fz.server(t)
	cli := zotclient.New(srv.URL)
	tags, _, err := cli.ListTags(t.Context(), registry.TagListQuery{RegistryID: "reg-A", Repository: "ghost"})
	require.NoError(t, err)
	require.Empty(t, tags)
}

// REG-25 — DeleteTag резолвит digest тега (HEAD) и удаляет манифест по digest
// (DELETE /manifests/<digest>).
func TestZot_REG25_DeleteTag_ResolvesDigest(t *testing.T) {
	fz := newFakeZot()
	fz.put("reg-A/app", "v1", "sha256:app1", 10, 100)
	srv := fz.server(t)

	cli := zotclient.New(srv.URL)
	require.NoError(t, cli.DeleteTag(t.Context(), "reg-A", "app", "v1"))
	require.Contains(t, fz.deleted, "sha256:app1", "delete by resolved digest, not by tag")
}

// REG-25 — DeleteTag на отсутствующий тег идемпотентен (already-gone → success),
// чтобы async-retry worker'а не залипал.
func TestZot_REG25_DeleteTag_Idempotent(t *testing.T) {
	fz := newFakeZot()
	srv := fz.server(t)
	cli := zotclient.New(srv.URL)
	require.NoError(t, cli.DeleteTag(t.Context(), "reg-A", "app", "nope"))
}

// REG-08 — NamespaceEmpty: true когда ни один repo не начинается с <registryID>/;
// false когда есть хоть один.
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
// layers) и число уникальных блобов (infra-проекция, только Internal-API).
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

// REG-38 — TriggerGC проверяет достижимость zot и подтверждает (реальная рекламация
// — native-scheduler zot); недоступность → fail-closed.
func TestZot_REG38_TriggerGC(t *testing.T) {
	fz := newFakeZot()
	srv := fz.server(t)
	cli := zotclient.New(srv.URL)
	require.NoError(t, cli.TriggerGC(t.Context(), "reg-A"))
}

// REG-08/REG-22 edge — zot недоступен (не сконфигурирован endpoint) → все проекции и
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
