// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

import "fmt"

// ArtifactType — тип OCI-артефакта образа. Ширина int32 совпадает с
// registryv1.ArtifactType, поэтому конверсии domain↔proto точны (UNSPECIFIED=0,
// CONTAINER_IMAGE=1, HELM_CHART=2, OTHER=3).
type ArtifactType int32

// Значения ArtifactType (parity с proto-enum registry.v1.ArtifactType).
const (
	ArtifactTypeUnspecified ArtifactType = iota
	ArtifactTypeContainerImage
	ArtifactTypeHelmChart
	ArtifactTypeOther
)

// Validate проверяет, что тип артефакта — известное значение (parity-guard).
func (a ArtifactType) Validate() error {
	switch a {
	case ArtifactTypeUnspecified, ArtifactTypeContainerImage, ArtifactTypeHelmChart, ArtifactTypeOther:
		return nil
	default:
		return fmt.Errorf("artifact type %d is out of range", int32(a))
	}
}

// config.mediaType артефактов, различающих контейнерный образ и helm-чарт. Оба
// типа несут одинаковый top-level manifest media-type — дискриминатор только здесь.
const (
	mediaConfigHelm        = "application/vnd.cncf.helm.config.v1+json"
	mediaConfigDockerImage = "application/vnd.docker.container.image.v1+json"
	mediaConfigOCIImage    = "application/vnd.oci.image.config.v1+json"
)

// top-level media-type multi-arch манифеста (index / manifest-list): config
// отсутствует, поэтому тип выводится по нему как контейнерный образ.
const (
	mediaOCIIndex   = "application/vnd.oci.image.index.v1+json"
	mediaDockerList = "application/vnd.docker.distribution.manifest.list.v2+json"
)

// ClassifyArtifact классифицирует тип артефакта по config.mediaType манифеста
// репрезентативного тега (+ top-level manifest mediaType для multi-arch index).
// Порядок веток нормативен (config-приоритет над top-level, first-match-wins):
//
//  1. config == helm                          → HELM_CHART
//  2. config ∈ {docker image, oci image}      → CONTAINER_IMAGE
//  3. config непустой, но неизвестный          → OTHER
//  4. config пуст И top-level — index/list     → CONTAINER_IMAGE (multi-arch)
//  5. иначе                                     → UNSPECIFIED
//
// Пустые оба аргумента (манифест непрочитан / нет тегов) → UNSPECIFIED.
func ClassifyArtifact(configMediaType, manifestMediaType string) ArtifactType {
	switch configMediaType {
	case mediaConfigHelm:
		return ArtifactTypeHelmChart
	case mediaConfigDockerImage, mediaConfigOCIImage:
		return ArtifactTypeContainerImage
	case "":
		// config отсутствует — multi-arch index/list несёт образ на верхнем уровне.
		if manifestMediaType == mediaOCIIndex || manifestMediaType == mediaDockerList {
			return ArtifactTypeContainerImage
		}
		return ArtifactTypeUnspecified
	default:
		return ArtifactTypeOther
	}
}
