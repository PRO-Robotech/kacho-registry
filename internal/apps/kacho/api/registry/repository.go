// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	"context"
	"errors"
	"fmt"

	corevalidate "github.com/PRO-Robotech/kacho-corelib/validate"
	registryv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/registry/v1"

	"github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/shared/prototime"
	"github.com/PRO-Robotech/kacho-registry/internal/domain"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// repository.go — config-overlay Repository (RG-1): sync-чтение GetRepository
// (overlay ⟂ projection LEFT JOIN, D-1) + общие хелперы среза (ProtoRepository,
// merge overlay+projection, visibility-resolve, description-валидация). Async-мутации
// (Create/Update/Delete/Rename) — в отдельных файлах среза.

// GetRepository возвращает публичный Repository по натуральному ключу (registry_id,
// name): LEFT JOIN overlay (intent) + projection (result). Существование:
// tenant-виден ⟺ есть overlay-строка ИЛИ проекция несёт ≥1 тег (D-1). Ни того, ни
// другого → ErrNotFound "repository not found" (uniform existence-hiding; per-repo
// v_get Check + deny→NOT_FOUND — в handler ДО вызова). malformed registry_id / имя —
// провалидированы ПЕРВЫМ стейтментом (A05/A06). zot недоступен → Unavailable.
func (u *UseCase) GetRepository(ctx context.Context, registryID, repository string) (*domain.Repository, error) {
	if err := u.assertRepoWired(); err != nil {
		return nil, err
	}
	if err := ValidateRegistryID(registryID); err != nil {
		return nil, err
	}
	if err := domain.ValidateRepositoryName("repository", repository); err != nil {
		return nil, failInvalidArg("%s", err.Error())
	}

	overlay, oerr := u.cfg.GetConfig(ctx, registryID, repository)
	if oerr != nil && !errors.Is(oerr, regerrors.ErrNotFound) {
		return nil, mapRepoErr(oerr)
	}
	proj, perr := u.zot.RepositoryProjection(ctx, registryID, repository)
	if perr != nil {
		return nil, mapRepoErr(perr)
	}

	repo := mergeRepository(registryID, repository, overlay, proj)
	if repo == nil {
		// Ни overlay-строки, ни проекции с тегами → tenant-невидим (existence-hiding).
		return nil, failNotFound("repository not found")
	}
	return repo, nil
}

// mergeRepository строит публичный Repository из overlay-строки (intent) и
// projection (result) — LEFT JOIN over (registry_id, name), D-1. Видимость:
//   - overlay есть → durable (survives-empty): projection-поля из proj (либо нули,
//     если проекции нет — пустой durable-repo), overlay-поля из overlay;
//   - overlay нет, проекция несёт теги → ephemeral: projection-поля из proj, overlay
//     пусты (visibility=PRIVATE by default);
//   - ни того, ни другого → nil (tenant-невидим).
func mergeRepository(registryID, name string, overlay *domain.RepositoryConfig, proj *domain.Repository) *domain.Repository {
	switch {
	case overlay != nil:
		repo := &domain.Repository{
			RegistryID:  registryID,
			Name:        name,
			Description: overlay.Description,
			Labels:      overlay.Labels,
			Visibility:  overlay.Visibility,
			CreatedAt:   overlay.CreatedAt,
		}
		if proj != nil {
			repo.TagCount = proj.TagCount
			repo.SizeBytes = proj.SizeBytes
			repo.UpdatedAt = proj.UpdatedAt
			repo.ArtifactType = proj.ArtifactType
			repo.ArtifactTypes = proj.ArtifactTypes
			repo.LastPulledAt = proj.LastPulledAt
			repo.DownloadCount = proj.DownloadCount
		}
		return repo
	case proj != nil && proj.TagCount > 0:
		// Ephemeral: проекция без overlay — visibility=PRIVATE by default, overlay-поля
		// пусты, created_at нулевой (своей строки нет).
		proj.RegistryID = registryID
		proj.Name = name
		proj.Visibility = domain.VisibilityPrivate
		return proj
	default:
		return nil
	}
}

// ProtoRepository конвертирует публичный domain.Repository → registryv1.Repository.
// created_at/updated_at/last_pulled_at усекаются до секунд (api-conventions.md); у
// ephemeral-repo created_at нулевой → prototime.Truncate отдаёт nil (пусто на wire).
// Инфра-полей НЕ несёт (X01 — только tenant-intent + result-counts).
func (u *UseCase) ProtoRepository(r *domain.Repository) *registryv1.Repository {
	if r == nil {
		return nil
	}
	var types []registryv1.ArtifactType
	if len(r.ArtifactTypes) > 0 {
		types = make([]registryv1.ArtifactType, len(r.ArtifactTypes))
		for i, at := range r.ArtifactTypes {
			types[i] = registryv1.ArtifactType(at)
		}
	}
	return &registryv1.Repository{
		RegistryId:    r.RegistryID,
		Name:          r.Name,
		Description:   r.Description,
		Labels:        r.Labels,
		Visibility:    registryv1.Visibility(r.Visibility),
		CreatedAt:     prototime.Truncate(r.CreatedAt),
		TagCount:      r.TagCount,
		SizeBytes:     r.SizeBytes,
		UpdatedAt:     prototime.Truncate(r.UpdatedAt),
		ArtifactType:  registryv1.ArtifactType(r.ArtifactType),
		ArtifactTypes: types,
		LastPulledAt:  prototime.Truncate(r.LastPulledAt),
		DownloadCount: r.DownloadCount,
	}
}

// resolveVisibility разрешает запрошенную visibility при create: явно заданная
// PRIVATE/PUBLIC — как есть; UNSPECIFIED → наследует registry.default_visibility
// (fail-safe: неизвестное значение default'а → PRIVATE через Visibility.Validate).
// admin-gate на EXPLICIT PUBLIC — в handler'е (B08); inherited PUBLIC (B12) —
// gate-at-default, admin уже авторизовал дефолт.
func resolveVisibility(requested, registryDefault domain.Visibility) domain.Visibility {
	if requested == domain.VisibilityPrivate || requested == domain.VisibilityPublic {
		return requested
	}
	if registryDefault == domain.VisibilityPublic {
		return domain.VisibilityPublic
	}
	return domain.VisibilityPrivate
}

// validateRepoDescription — description-границы overlay Repository (A22): длина
// ≤256 rune (corelib parity с Registry) + запрет control-char'ов (\x00…\x1f):
// валидный multibyte-unicode проходит и round-trip'ит байт-в-байт.
func validateRepoDescription(description string) error {
	if err := corevalidate.Description("description", description); err != nil {
		return err
	}
	for _, r := range description {
		if r < 0x20 { // control-char (включая \x00) — не печатаемый tenant-intent
			return failInvalidArg("description contains control characters")
		}
	}
	return nil
}

// failNotFound — sentinel ErrNotFound + текст → gRPC NOT_FOUND (existence-hiding).
func failNotFound(format string, a ...any) error {
	return mapRepoErr(fmt.Errorf("%w: %s", regerrors.ErrNotFound, fmt.Sprintf(format, a...)))
}
