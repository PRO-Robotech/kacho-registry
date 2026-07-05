// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package handler

import (
	"testing"

	registryv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/registry/v1"

	"github.com/PRO-Robotech/kacho-registry/internal/domain"
)

// TestArtifactType_ProtoParity фиксирует численную parity domain↔proto: маппинг в
// toProtoRepository — прямой int32-каст, поэтому reorder/renumber одного из enum'ов
// молча испортил бы тип. Тест ловит такой дрейф (red).
func TestArtifactType_ProtoParity(t *testing.T) {
	pairs := []struct {
		d domain.ArtifactType
		p registryv1.ArtifactType
	}{
		{domain.ArtifactTypeUnspecified, registryv1.ArtifactType_ARTIFACT_TYPE_UNSPECIFIED},
		{domain.ArtifactTypeContainerImage, registryv1.ArtifactType_ARTIFACT_TYPE_CONTAINER_IMAGE},
		{domain.ArtifactTypeHelmChart, registryv1.ArtifactType_ARTIFACT_TYPE_HELM_CHART},
		{domain.ArtifactTypeOther, registryv1.ArtifactType_ARTIFACT_TYPE_OTHER},
	}
	for _, pr := range pairs {
		if int32(pr.d) != int32(pr.p) {
			t.Errorf("parity drift: domain %d != proto %d (%s)", int32(pr.d), int32(pr.p), pr.p)
		}
	}
}

// TestArtifactType_RegistryStatusParity — та же parity-гарантия для RegistryStatus
// (тоже int32-каст domain↔proto в use-case ProtoRegistry).
func TestArtifactType_RegistryStatusParity(t *testing.T) {
	pairs := []struct {
		d domain.RegistryStatus
		p registryv1.RegistryStatus
	}{
		{domain.RegistryStatusUnspecified, registryv1.RegistryStatus_REGISTRY_STATUS_UNSPECIFIED},
		{domain.RegistryStatusActive, registryv1.RegistryStatus_REGISTRY_STATUS_ACTIVE},
		{domain.RegistryStatusDeleting, registryv1.RegistryStatus_REGISTRY_STATUS_DELETING},
	}
	for _, pr := range pairs {
		if int32(pr.d) != int32(pr.p) {
			t.Errorf("parity drift: domain %d != proto %d (%s)", int32(pr.d), int32(pr.p), pr.p)
		}
	}
}

// TestToProtoRepository_MapsArtifactType проверяет, что transport-конвертер
// переносит ArtifactType в proto-проекцию (иначе UI-фильтр остался бы слепым).
func TestToProtoRepository_MapsArtifactType(t *testing.T) {
	cases := []struct {
		in   domain.ArtifactType
		want registryv1.ArtifactType
	}{
		{domain.ArtifactTypeContainerImage, registryv1.ArtifactType_ARTIFACT_TYPE_CONTAINER_IMAGE},
		{domain.ArtifactTypeHelmChart, registryv1.ArtifactType_ARTIFACT_TYPE_HELM_CHART},
		{domain.ArtifactTypeOther, registryv1.ArtifactType_ARTIFACT_TYPE_OTHER},
		{domain.ArtifactTypeUnspecified, registryv1.ArtifactType_ARTIFACT_TYPE_UNSPECIFIED},
	}
	for _, tc := range cases {
		got := toProtoRepository(&domain.Repository{RegistryID: "reg-x", Name: "app", ArtifactType: tc.in})
		if got.GetArtifactType() != tc.want {
			t.Errorf("toProtoRepository ArtifactType = %s, want %s", got.GetArtifactType(), tc.want)
		}
	}
}
