// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package zot_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	registry "github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/api/registry"
	zotclient "github.com/PRO-Robotech/kacho-registry/internal/clients/zot"
	"github.com/PRO-Robotech/kacho-registry/internal/domain"
)

// repoByName ищет проекцию repo по имени (без namespace-префикса).
func repoByName(t *testing.T, repos []*domain.Repository, name string) *domain.Repository {
	t.Helper()
	for _, r := range repos {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("repo %q not found in %v", name, repos)
	return nil
}

// GWT-1 — docker/oci-config образ → CONTAINER_IMAGE (классификация по
// Manifests[].ArtifactType из ImageList).
func TestZot_ArtifactType_DockerImage(t *testing.T) {
	fz := newFakeZot()
	fz.addGqlTag("reg-A/app", containerTag("v1", "sha256:app1", 100, "linux", "amd64"))
	srv := fz.server(t)

	repos, _, err := zotclient.New(srv.URL).ListRepositories(t.Context(), registry.RepoListQuery{RegistryID: "reg-A"})
	require.NoError(t, err)
	r := repoByName(t, repos, "app")
	require.Equal(t, domain.ArtifactTypeContainerImage, r.ArtifactType)
	require.Equal(t, []domain.ArtifactType{domain.ArtifactTypeContainerImage}, r.ArtifactTypes)
}

// GWT-2 — helm-config образ → HELM_CHART (главный дискриминатор config.mediaType).
func TestZot_ArtifactType_HelmChart(t *testing.T) {
	fz := newFakeZot()
	fz.addGqlTag("reg-A/chart", helmTag("1.0.0", "sha256:chart1", 40))
	srv := fz.server(t)

	repos, _, err := zotclient.New(srv.URL).ListRepositories(t.Context(), registry.RepoListQuery{RegistryID: "reg-A"})
	require.NoError(t, err)
	r := repoByName(t, repos, "chart")
	require.Equal(t, domain.ArtifactTypeHelmChart, r.ArtifactType)
	require.Equal(t, []domain.ArtifactType{domain.ArtifactTypeHelmChart}, r.ArtifactTypes)
}

// GWT-4 — multi-arch index (config пуст, top-level index media-type) → CONTAINER_IMAGE.
func TestZot_ArtifactType_MultiArchIndex(t *testing.T) {
	fz := newFakeZot()
	fz.addGqlTag("reg-A/multi", gqlTag{
		tag: "v1", digest: "sha256:idx1", mediaType: mediaOCIIndex, size: 500,
		configMedia: "", // config у index отсутствует → тип по top-level media-type
		pushTS:      "2026-01-01T00:00:00Z", pullTS: zotNever, multiArch: true,
	})
	srv := fz.server(t)

	repos, _, err := zotclient.New(srv.URL).ListRepositories(t.Context(), registry.RepoListQuery{RegistryID: "reg-A"})
	require.NoError(t, err)
	r := repoByName(t, repos, "multi")
	require.Equal(t, domain.ArtifactTypeContainerImage, r.ArtifactType)
}

// GWT-6 — тег неклассифицируемого типа (config пуст, plain manifest) → UNSPECIFIED
// выпадает из набора; repo всё равно в проекции (best-effort, не роняем список).
func TestZot_ArtifactType_Unclassifiable_Unspecified(t *testing.T) {
	fz := newFakeZot()
	fz.addGqlTag("reg-A/app", gqlTag{
		tag: "v1", digest: "sha256:app1", mediaType: mediaOCIManifest, size: 100,
		configMedia: "", // ни config, ни index → UNSPECIFIED
		pushTS:      "2026-01-01T00:00:00Z", pullTS: zotNever,
	})
	srv := fz.server(t)

	repos, _, err := zotclient.New(srv.URL).ListRepositories(t.Context(), registry.RepoListQuery{RegistryID: "reg-A"})
	require.NoError(t, err, "неклассифицируемый тег не роняет ListRepositories")
	require.Len(t, repos, 1, "репо всё равно в проекции")
	r := repoByName(t, repos, "app")
	require.Equal(t, domain.ArtifactTypeUnspecified, r.ArtifactType)
	require.Empty(t, r.ArtifactTypes, "UNSPECIFIED выпадает из набора")
}

// artifact_types — упорядоченно-уникальный набор: два контейнерных тега → один элемент
// (dedup, без повтора CONTAINER_IMAGE).
func TestZot_ArtifactType_SetDedup(t *testing.T) {
	fz := newFakeZot()
	fz.addGqlTag("reg-A/app", containerTag("v1", "sha256:app1", 100, "linux", "amd64"))
	fz.addGqlTag("reg-A/app", containerTag("v2", "sha256:app2", 120, "linux", "arm64"))
	srv := fz.server(t)

	repos, _, err := zotclient.New(srv.URL).ListRepositories(t.Context(), registry.RepoListQuery{RegistryID: "reg-A"})
	require.NoError(t, err)
	r := repoByName(t, repos, "app")
	require.Equal(t, []domain.ArtifactType{domain.ArtifactTypeContainerImage}, r.ArtifactTypes, "dedup: один элемент")
}
