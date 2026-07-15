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
	registryv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/registry/v1"

	"github.com/PRO-Robotech/kacho-registry/internal/domain"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// DeleteRepository — async reject-if-tags удаление config-overlay (D-4). Sync-часть:
// format-валидация. per-repo v_delete Check (deny|absent → sync NOT_FOUND, Operation
// НЕ создаётся, A15) — в handler'е ДО вызова. Async worker: emptiness-проверка в движке
// (source of truth, во избежание TOCTOU push-между-проверкой-и-delete) → не-пустой →
// Operation error FAILED_PRECONDITION "repository is not empty" (A14); движок недоступен
// → UNAVAILABLE (fail-closed: overlay не сносим, пока не подтвердили пустоту); пустой
// durable → DeleteConfig (tx: ACTIVE-guard + DELETE overlay + unregister repo-tuples +
// public-grant, same-registry only ban #4) → Get NOT_FOUND (A13). Cascade-with-tags —
// отдельный :deleteWithTags verb (вне scope RG-1).
func (u *UseCase) DeleteRepository(ctx context.Context, registryID, repository string) (*operations.Operation, error) {
	if err := u.assertRepoWired(); err != nil {
		return nil, err
	}
	if err := ValidateRegistryID(registryID); err != nil {
		return nil, err
	}
	if err := domain.ValidateRepositoryName("repository", repository); err != nil {
		return nil, failInvalidArg("%s", err.Error())
	}

	principal := operations.PrincipalFromContext(ctx)
	op, err := operations.NewFromContext(ctx,
		ids.PrefixOperationReg,
		fmt.Sprintf("Delete Repository %s/%s", registryID, repository),
		&registryv1.DeleteRepositoryMetadata{RegistryId: registryID, Repository: repository},
	)
	if err != nil {
		return nil, mapRepoErr(err)
	}
	if err := u.ops.CreateWithPrincipal(ctx, op, principal); err != nil {
		return nil, mapRepoErr(err)
	}

	operations.Run(ctx, u.ops, op.ID, func(workerCtx context.Context) (*anypb.Any, error) {
		wctx := operations.WithPrincipal(workerCtx, principal)
		// emptiness — source of truth = engine (worker-side, D-4 anti-TOCTOU). Движок
		// недоступен → Unavailable (fail-closed, overlay не сносим).
		empty, eerr := u.zot.RepositoryEmpty(wctx, registryID, repository)
		if eerr != nil {
			return nil, mapRepoErr(eerr)
		}
		if !empty {
			return nil, failFailedPrecondition("repository is not empty")
		}
		intents := []OutboxIntent{
			{Event: domain.FGAEventUnregister, Intent: domain.UnregisterIntentForRepo(registryID, repository)},
			{Event: domain.FGAEventUnregister, Intent: domain.UnregisterIntentForRepoPublicGrant(registryID, repository)},
		}
		if derr := u.cfg.DeleteConfig(wctx, registryID, repository, intents...); derr != nil {
			if errors.Is(derr, regerrors.ErrNotFound) {
				// Идемпотентно: overlay уже снят (повторный/конкурентный Delete) — done.
				return emptyAny()
			}
			return nil, mapRepoErr(derr)
		}
		return emptyAny()
	})

	return &op, nil
}
