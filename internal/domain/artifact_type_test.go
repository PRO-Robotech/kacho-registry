// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain_test

import (
	"testing"

	"github.com/PRO-Robotech/kacho-registry/internal/domain"
)

// TestClassifyArtifact проверяет упорядоченный классификатор типа артефакта по
// config.mediaType (+ top-level manifest mediaType для multi-arch index). Порядок
// веток нормативен: config-приоритет над top-level, first-match-wins.
func TestClassifyArtifact(t *testing.T) {
	const (
		helmConfig   = "application/vnd.cncf.helm.config.v1+json"
		dockerConfig = "application/vnd.docker.container.image.v1+json"
		ociConfig    = "application/vnd.oci.image.config.v1+json"
		ociIndex     = "application/vnd.oci.image.index.v1+json"
		dockerList   = "application/vnd.docker.distribution.manifest.list.v2+json"
		ociManifest  = "application/vnd.oci.image.manifest.v1+json"
		sbomConfig   = "application/vnd.example.sbom.v1+json"
	)

	cases := []struct {
		name          string
		configMedia   string
		manifestMedia string
		want          domain.ArtifactType
	}{
		// GWT-2 — helm config → HELM_CHART (даже поверх image-манифеста).
		{"helm config", helmConfig, ociManifest, domain.ArtifactTypeHelmChart},
		// GWT-2 (config-приоритет) — helm config даже если top-level index.
		{"helm config beats index top-level", helmConfig, ociIndex, domain.ArtifactTypeHelmChart},
		// GWT-1 — docker container config → CONTAINER_IMAGE.
		{"docker container config", dockerConfig, ociManifest, domain.ArtifactTypeContainerImage},
		// GWT-3 — oci image config → CONTAINER_IMAGE.
		{"oci image config", ociConfig, ociManifest, domain.ArtifactTypeContainerImage},
		// GWT-5 — иной непустой config → OTHER.
		{"sbom config → other", sbomConfig, ociManifest, domain.ArtifactTypeOther},
		// GWT-4 — config пуст + top-level oci index → CONTAINER_IMAGE (multi-arch).
		{"empty config + oci index", "", ociIndex, domain.ArtifactTypeContainerImage},
		// GWT-4 — config пуст + top-level docker manifest-list → CONTAINER_IMAGE.
		{"empty config + docker manifest-list", "", dockerList, domain.ArtifactTypeContainerImage},
		// GWT-6 — config пуст + обычный image-манифест (не index) → UNSPECIFIED.
		{"empty config + plain manifest → unspecified", "", ociManifest, domain.ArtifactTypeUnspecified},
		// GWT-6 — оба пусты → UNSPECIFIED.
		{"both empty → unspecified", "", "", domain.ArtifactTypeUnspecified},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := domain.ClassifyArtifact(tc.configMedia, tc.manifestMedia)
			if got != tc.want {
				t.Fatalf("ClassifyArtifact(%q, %q) = %v, want %v", tc.configMedia, tc.manifestMedia, got, tc.want)
			}
		})
	}
}

// TestArtifactType_Validate — enum-parity guard (как RegistryStatus.Validate).
func TestArtifactType_Validate(t *testing.T) {
	valid := []domain.ArtifactType{
		domain.ArtifactTypeUnspecified,
		domain.ArtifactTypeContainerImage,
		domain.ArtifactTypeHelmChart,
		domain.ArtifactTypeOther,
	}
	for _, a := range valid {
		if err := a.Validate(); err != nil {
			t.Errorf("Validate(%v) unexpected error: %v", a, err)
		}
	}
	if err := domain.ArtifactType(99).Validate(); err == nil {
		t.Error("Validate(99) expected out-of-range error, got nil")
	}
}
