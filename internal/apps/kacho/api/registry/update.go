// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho-corelib/ids"
	"github.com/PRO-Robotech/kacho-corelib/operations"
	corevalidate "github.com/PRO-Robotech/kacho-corelib/validate"
	registryv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/registry/v1"

	"github.com/PRO-Robotech/kacho-registry/internal/domain"
)

// Update — async смена mutable-полей (labels/description). name/project immutable.
// Sync-часть: id-формат, update_mask discipline (unknown/immutable → InvalidArgument,
// без Operation), валидация применяемых полей. Async worker (с проброшенным
// principal): атомарный UPDATE ... RETURNING + mirror register-intent с ОБНОВЛЁННЫМИ
// labels в той же tx — снятая метка реально отзывает label-scoped доступ (iam-mirror).
func (u *UseCase) Update(ctx context.Context, spec UpdateSpec) (*operations.Operation, error) {
	if err := u.assertWired(); err != nil {
		return nil, err
	}
	if spec.RegistryID == "" {
		return nil, status.Error(codes.InvalidArgument, "registryId is required")
	}
	if err := validateRegistryID(spec.RegistryID); err != nil {
		return nil, err
	}

	spec, err := resolveUpdateMask(spec)
	if err != nil {
		return nil, err
	}
	if spec.ApplyName {
		// Имя mutable, но валидируется теми же правилами, что и Create (DNS-safe,
		// длина). Конфликт по partial-UNIQUE(project,name) ловит DB → AlreadyExists.
		if verr := domain.ValidateName("name", spec.Name); verr != nil {
			return nil, status.Errorf(codes.InvalidArgument, "Illegal argument: %s", verr.Error())
		}
	}
	if spec.ApplyDescription {
		if verr := corevalidate.Description("description", spec.Description); verr != nil {
			return nil, verr
		}
	}
	if spec.ApplyLabels {
		if verr := corevalidate.Labels("labels", spec.Labels); verr != nil {
			return nil, verr
		}
	}

	op, err := operations.NewFromContext(ctx,
		ids.PrefixOperationReg,
		fmt.Sprintf("Update Registry %s", spec.RegistryID),
		&registryv1.UpdateRegistryMetadata{RegistryId: spec.RegistryID},
	)
	if err != nil {
		return nil, mapRepoErr(err)
	}
	principal := operations.PrincipalFromContext(ctx)
	if err := u.ops.CreateWithPrincipal(ctx, op, principal); err != nil {
		return nil, mapRepoErr(err)
	}

	operations.Run(ctx, u.ops, op.ID, func(workerCtx context.Context) (*anypb.Any, error) {
		// Worker-ctx детачнут от request'а — принудительно несём principal (иначе
		// mirror register-intent / любой downstream уходит анонимно, authz_no_principal).
		workerCtx = operations.WithPrincipal(workerCtx, principal)
		updated, uerr := u.writer.Update(workerCtx, spec, mirrorIntent)
		if uerr != nil {
			return nil, mapRepoErr(uerr)
		}
		return u.registryAny(updated)
	})

	return &op, nil
}

// mirrorIntent строит mirror register-intent из обновлённой строки: project-tuple
// с новыми labels (без creator-tuple). Callback вызывается репозиторием под
// RETURNING обновлённой строки — labels/project берутся из реального персиста.
func mirrorIntent(r *domain.Registry) domain.RegisterIntent {
	return domain.RegisterIntentForUpdate(r)
}
