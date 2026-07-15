// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho-corelib/ids"
	"github.com/PRO-Robotech/kacho-corelib/operations"
	corevalidate "github.com/PRO-Robotech/kacho-corelib/validate"
	registryv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/registry/v1"

	"github.com/PRO-Robotech/kacho-registry/internal/domain"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// UpdateRepositorySpec — вход UpdateRepository (тело + update_mask, распарсенное handler'ом).
type UpdateRepositorySpec struct {
	RegistryID  string
	Repository  string
	Description string
	Labels      map[string]string
	Visibility  domain.Visibility
	Mask        []string
}

// UpdateRepository — async FieldMask-PATCH config-overlay (description/labels/visibility;
// name immutable → RenameRepository). Sync-часть: format-валидация (malformed-first),
// update_mask discipline (immutable → A11, unknown → A10, оба ДО Operation), payload-
// границы применяемых полей (A22). Async worker: UpdateConfig (tx: ACTIVE-guard A24 +
// UPDATE + public-grant governance по итоговому visibility, B01/B06 — в той же tx);
// ephemeral (нет overlay) → auto-promote INSERT (A12). admin-gate на visibility→PUBLIC
// (B02) — в handler'е ДО вызова.
func (u *UseCase) UpdateRepository(ctx context.Context, spec UpdateRepositorySpec) (*operations.Operation, error) {
	if err := u.assertRepoWired(); err != nil {
		return nil, err
	}
	if err := ValidateRegistryID(spec.RegistryID); err != nil {
		return nil, err
	}
	if err := domain.ValidateRepositoryName("repository", spec.Repository); err != nil {
		return nil, failInvalidArg("%s", err.Error())
	}

	cfgSpec := RepositoryConfigUpdate{
		RegistryID:  spec.RegistryID,
		Name:        spec.Repository,
		Description: spec.Description,
		Labels:      spec.Labels,
		Visibility:  spec.Visibility,
	}
	cfgSpec, err := resolveRepoUpdateMask(cfgSpec, spec.Mask)
	if err != nil {
		return nil, err
	}
	if cfgSpec.ApplyDescription {
		if verr := validateRepoDescription(cfgSpec.Description); verr != nil {
			return nil, verr
		}
	}
	if cfgSpec.ApplyLabels {
		if verr := corevalidate.Labels("labels", cfgSpec.Labels); verr != nil {
			return nil, verr
		}
	}
	if cfgSpec.ApplyVisibility {
		if verr := cfgSpec.Visibility.Validate(); verr != nil {
			return nil, failInvalidArg("Illegal argument: %s", verr.Error())
		}
	}

	principal := operations.PrincipalFromContext(ctx)
	op, err := operations.NewFromContext(ctx,
		ids.PrefixOperationReg,
		fmt.Sprintf("Update Repository %s/%s", spec.RegistryID, spec.Repository),
		&registryv1.UpdateRepositoryMetadata{RegistryId: spec.RegistryID, Repository: spec.Repository},
	)
	if err != nil {
		return nil, mapRepoErr(err)
	}
	if err := u.ops.CreateWithPrincipal(ctx, op, principal); err != nil {
		return nil, mapRepoErr(err)
	}

	operations.Run(ctx, u.ops, op.ID, func(workerCtx context.Context) (*anypb.Any, error) {
		wctx := operations.WithPrincipal(workerCtx, principal)
		updated, uerr := u.applyRepoUpdate(wctx, cfgSpec, principal)
		if uerr != nil {
			return nil, uerr
		}
		proj, perr := u.zot.RepositoryProjection(wctx, spec.RegistryID, spec.Repository)
		if perr != nil {
			return nil, mapRepoErr(perr)
		}
		return u.repositoryAny(mergeRepository(spec.RegistryID, spec.Repository, updated, proj))
	})

	return &op, nil
}

// applyRepoUpdate применяет UpdateConfig к durable overlay; если строки нет (ephemeral)
// — auto-promote: INSERT overlay под применёнными полями + registry.default_visibility
// (A12, «overlay upsert»). Гонка promote (две конкурентные Update ephemeral) — арбитр
// DB PRIMARY KEY: проигравший INSERT видит 23505 → повторный UpdateConfig (строка уже
// есть). public-grant governance эмитится по ИТОГОВОМУ visibility в той же tx.
func (u *UseCase) applyRepoUpdate(ctx context.Context, spec RepositoryConfigUpdate, principal operations.Principal) (*domain.RepositoryConfig, error) {
	updated, err := u.cfg.UpdateConfig(ctx, spec, updateGovernanceIntents(spec)...)
	if err == nil {
		return updated, nil
	}
	if !errors.Is(err, regerrors.ErrNotFound) {
		return nil, mapRepoErr(err)
	}

	// Ephemeral → promote: строим overlay из применённых полей + default_visibility.
	reg, gerr := u.reader.Get(ctx, spec.RegistryID)
	if gerr != nil {
		return nil, mapRepoErr(gerr)
	}
	visibility := reg.DefaultVisibility
	if spec.ApplyVisibility {
		visibility = spec.Visibility
	}
	visibility = resolveVisibility(visibility, reg.DefaultVisibility)
	promoted := &domain.RepositoryConfig{
		RegistryID:  spec.RegistryID,
		Name:        spec.Name,
		Description: spec.Description,
		Labels:      spec.Labels,
		Visibility:  visibility,
	}
	promoteIntents := []OutboxIntent{}
	if visibility == domain.VisibilityPublic {
		promoteIntents = append(promoteIntents,
			OutboxIntent{Event: domain.FGAEventRegister, Intent: domain.RegisterIntentForRepoPublicGrant(spec.RegistryID, spec.Name)})
	}
	inserted, ierr := u.cfg.InsertConfig(ctx, promoted, promoteIntents...)
	if ierr == nil {
		return inserted, nil
	}
	if errors.Is(ierr, regerrors.ErrAlreadyExists) {
		// Проигранная promote-гонка: строка уже вставлена конкурентом → повторный UPDATE.
		retried, rerr := u.cfg.UpdateConfig(ctx, spec, updateGovernanceIntents(spec)...)
		if rerr != nil {
			return nil, mapRepoErr(rerr)
		}
		return retried, nil
	}
	return nil, mapRepoErr(ierr)
}

// updateGovernanceIntents — public-grant governance для UpdateRepository: эмитится
// ТОЛЬКО при явном visibility в mask (иначе visibility не тронут — governance неизменна).
// PUBLIC → register "user:* v_get" (B01); PRIVATE → unregister (B06 revoke). Presence
// tuple конвергирует к финальному visibility по commit-порядку (B09, X03).
func updateGovernanceIntents(spec RepositoryConfigUpdate) []OutboxIntent {
	if !spec.ApplyVisibility {
		return nil
	}
	if spec.Visibility == domain.VisibilityPublic {
		return []OutboxIntent{{Event: domain.FGAEventRegister, Intent: domain.RegisterIntentForRepoPublicGrant(spec.RegistryID, spec.Name)}}
	}
	return []OutboxIntent{{Event: domain.FGAEventUnregister, Intent: domain.UnregisterIntentForRepoPublicGrant(spec.RegistryID, spec.Name)}}
}
