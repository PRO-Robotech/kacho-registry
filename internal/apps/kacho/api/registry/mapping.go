// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	registryv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/registry/v1"

	"github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/shared/prototime"
	"github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/shared/serviceerr"
	"github.com/PRO-Robotech/kacho-registry/internal/domain"
)

// ProtoRegistry конвертирует domain.Registry → registryv1.Registry. Единый
// источник tenant-facing проекции: используется worker'ом (Operation.response) и
// тонким handler'ом (Get/List). created_at усекается до секунд; endpoint —
// output-only ("<base>/<id>"); repository_count — проекция из zot (0 до data-plane).
func (u *UseCase) ProtoRegistry(r *domain.Registry) *registryv1.Registry {
	if r == nil {
		return nil
	}
	return &registryv1.Registry{
		Id:                r.ID,
		ProjectId:         r.ProjectID,
		CreatedAt:         prototime.Truncate(r.CreatedAt),
		Name:              r.Name,
		Description:       r.Description,
		Labels:            r.Labels,
		Endpoint:          u.EndpointFor(r.ID),
		Status:            registryv1.RegistryStatus(r.Status),
		DefaultVisibility: registryv1.Visibility(r.DefaultVisibility),
	}
}

// mapRepoErr переводит sentinel-ошибку repo/clients в gRPC-статус (единый маппинг
// serviceerr — тот же, что тонкий handler и worker сохраняют в Operation.error).
func mapRepoErr(err error) error {
	return serviceerr.ToStatus(err)
}
