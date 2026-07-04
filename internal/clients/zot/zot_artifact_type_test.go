// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package zot_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	registry "github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/api/registry"
	zotclient "github.com/PRO-Robotech/kacho-registry/internal/clients/zot"
	"github.com/PRO-Robotech/kacho-registry/internal/domain"
)

const (
	mediaManifestOCI  = "application/vnd.oci.image.manifest.v1+json"
	mediaConfigDocker = "application/vnd.docker.container.image.v1+json"
	mediaConfigHelm   = "application/vnd.cncf.helm.config.v1+json"
	mediaIndexOCI     = "application/vnd.oci.image.index.v1+json"
)

// putArtifact регистрирует tag с манифестом заданного top-level media-type и
// config.mediaType (дискриминатор docker/helm) — для тестов классификации.
func putArtifact(fz *fakeZot, repo, tag, digest, manifestMedia, configMedia string) {
	body, _ := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     manifestMedia,
		"config":        map[string]any{"mediaType": configMedia, "size": 7, "digest": "sha256:cfg" + digest},
		"layers":        []any{},
	})
	if fz.repos[repo] == nil {
		fz.repos[repo] = map[string]manifestFixture{}
	}
	fz.repos[repo][tag] = manifestFixture{digest: digest, mediaType: manifestMedia, body: body}
}

// putIndex регистрирует tag как OCI-index / docker-manifest-list (multi-arch, без
// config) — top-level media-type index, manifests-массив вместо config/layers.
func putIndex(fz *fakeZot, repo, tag, digest, indexMedia string) {
	body, _ := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     indexMedia,
		"manifests":     []any{map[string]any{"mediaType": mediaManifestOCI, "digest": "sha256:child" + digest}},
	})
	if fz.repos[repo] == nil {
		fz.repos[repo] = map[string]manifestFixture{}
	}
	fz.repos[repo][tag] = manifestFixture{digest: digest, mediaType: indexMedia, body: body}
}

func artifactTypeOf(t *testing.T, repos []*domain.Repository, name string) domain.ArtifactType {
	t.Helper()
	for _, r := range repos {
		if r.Name == name {
			return r.ArtifactType
		}
	}
	t.Fatalf("repo %q not found in %v", name, repos)
	return domain.ArtifactTypeUnspecified
}

// GWT-1 — docker-config образ → CONTAINER_IMAGE (end-to-end извлечение config.mediaType).
func TestZot_ArtifactType_DockerImage(t *testing.T) {
	fz := newFakeZot()
	putArtifact(fz, "reg-A/app", "v1", "sha256:app1", mediaManifestOCI, mediaConfigDocker)
	srv := fz.server(t)

	repos, _, err := zotclient.New(srv.URL).ListRepositories(t.Context(), registry.RepoListQuery{RegistryID: "reg-A"})
	require.NoError(t, err)
	require.Equal(t, domain.ArtifactTypeContainerImage, artifactTypeOf(t, repos, "app"))
}

// GWT-2 — helm-config образ → HELM_CHART (главный дискриминатор).
func TestZot_ArtifactType_HelmChart(t *testing.T) {
	fz := newFakeZot()
	putArtifact(fz, "reg-A/chart", "1.0.0", "sha256:chart1", mediaManifestOCI, mediaConfigHelm)
	srv := fz.server(t)

	repos, _, err := zotclient.New(srv.URL).ListRepositories(t.Context(), registry.RepoListQuery{RegistryID: "reg-A"})
	require.NoError(t, err)
	require.Equal(t, domain.ArtifactTypeHelmChart, artifactTypeOf(t, repos, "chart"))
}

// GWT-4 — multi-arch index (config пуст, top-level index) → CONTAINER_IMAGE.
func TestZot_ArtifactType_MultiArchIndex(t *testing.T) {
	fz := newFakeZot()
	putIndex(fz, "reg-A/multi", "v1", "sha256:idx1", mediaIndexOCI)
	srv := fz.server(t)

	repos, _, err := zotclient.New(srv.URL).ListRepositories(t.Context(), registry.RepoListQuery{RegistryID: "reg-A"})
	require.NoError(t, err)
	require.Equal(t, domain.ArtifactTypeContainerImage, artifactTypeOf(t, repos, "multi"))
}

// GWT-6 — манифест-репрезентант флейкует 5xx (при живых catalog/tags) → UNSPECIFIED,
// список НЕ падает (best-effort по прецеденту Stats).
func TestZot_ArtifactType_ManifestUnreadable_Unspecified(t *testing.T) {
	fz := newFakeZot()
	putArtifact(fz, "reg-A/app", "v1", "sha256:app1", mediaManifestOCI, mediaConfigDocker)
	fz.failManifest["reg-A/app"] = true // GET манифеста → 500
	srv := fz.server(t)

	repos, _, err := zotclient.New(srv.URL).ListRepositories(t.Context(), registry.RepoListQuery{RegistryID: "reg-A"})
	require.NoError(t, err, "манифест-флейк не роняет ListRepositories")
	require.Len(t, repos, 1, "репо всё равно в проекции")
	require.Equal(t, domain.ArtifactTypeUnspecified, artifactTypeOf(t, repos, "app"))
}

// GWT-2 (representative) — репрезентант = "latest" если присутствует: latest=helm,
// v1=docker → HELM_CHART (классифицируем по latest, не по случайному тегу).
func TestZot_ArtifactType_RepresentativeIsLatest(t *testing.T) {
	fz := newFakeZot()
	putArtifact(fz, "reg-A/mixed", "v1", "sha256:mix1", mediaManifestOCI, mediaConfigDocker)
	putArtifact(fz, "reg-A/mixed", "latest", "sha256:mixL", mediaManifestOCI, mediaConfigHelm)
	srv := fz.server(t)

	repos, _, err := zotclient.New(srv.URL).ListRepositories(t.Context(), registry.RepoListQuery{RegistryID: "reg-A"})
	require.NoError(t, err)
	require.Equal(t, domain.ArtifactTypeHelmChart, artifactTypeOf(t, repos, "mixed"))
}
