// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho-corelib/ids"
	"github.com/PRO-Robotech/kacho-corelib/operations"
	registryv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/registry/v1"

	"github.com/PRO-Robotech/kacho-registry/internal/domain"
)

// DeleteTag — async удаление тега/манифеста в zot (проекция read-only, source of
// truth = zot). Sync-часть: id-формат + непустые repo/tag. Async worker (с
// проброшенным principal) исполняет zot.DeleteTag; полл до done.
//
// Per-repo authz (v_delete, existence-hiding deny→NOT_FOUND) — В ХЕНДЛЕРЕ ДО вызова
// use-case: handler синхронно Check'ает и НЕ создаёт Operation на deny (иначе async-
// Operation с error раскрыл бы факт существования repo/тега).
func (u *UseCase) DeleteTag(ctx context.Context, registryID, repository, tag string) (*operations.Operation, error) {
	if err := u.assertWired(); err != nil {
		return nil, err
	}
	if err := validateRegistryID(registryID); err != nil {
		return nil, err
	}
	if repository == "" {
		return nil, failInvalidArg("repository is required")
	}
	if tag == "" {
		return nil, failInvalidArg("tag is required")
	}

	op, err := operations.NewFromContext(ctx,
		ids.PrefixOperationReg,
		fmt.Sprintf("Delete tag %s of %s/%s", tag, registryID, repository),
		&registryv1.DeleteTagMetadata{RegistryId: registryID, Repository: repository, Tag: tag},
	)
	if err != nil {
		return nil, mapRepoErr(err)
	}
	principal := operations.PrincipalFromContext(ctx)
	if err := u.ops.CreateWithPrincipal(ctx, op, principal); err != nil {
		return nil, mapRepoErr(err)
	}

	operations.Run(ctx, u.ops, op.ID, func(workerCtx context.Context) (*anypb.Any, error) {
		// Worker-ctx детачнут — восстанавливаем principal (иначе downstream/peer-
		// вызовы уходят анонимно, authz_no_principal).
		wctx := operations.WithPrincipal(workerCtx, principal)
		if derr := u.zot.DeleteTag(wctx, registryID, repository, tag); derr != nil {
			return nil, mapRepoErr(derr)
		}
		if uerr := u.unregisterRepoIfEmpty(wctx, registryID, repository); uerr != nil {
			return nil, uerr
		}
		return emptyAny()
	})

	return &op, nil
}

// unregisterRepoIfEmpty — при удалении последнего тега repo эмитит unregister-intent
// registry_repository:<reg>/<repo> (не оставляем висячий authz-объект). Читает
// остаток тегов из zot; ошибка чтения → проброс (worker ретраит идемпотентно:
// zot.DeleteTag no-op на уже-удалённый тег, повторный unregister-intent идемпотентен
// в iam). repoReg==nil (breakglass) → no-op.
func (u *UseCase) unregisterRepoIfEmpty(ctx context.Context, registryID, repository string) error {
	if u.repoReg == nil {
		return nil
	}
	tags, _, err := u.zot.ListTags(ctx, TagListQuery{RegistryID: registryID, Repository: repository})
	if err != nil {
		return mapRepoErr(err)
	}
	if len(tags) > 0 {
		return nil // repo ещё непуст — authz-объект жив
	}
	intent := domain.UnregisterIntentForRepo(registryID, repository)
	if uerr := u.repoReg.UnregisterRepository(ctx, intent); uerr != nil {
		return mapRepoErr(uerr)
	}
	return nil
}

// TriggerGC — async garbage collection namespace в zot (Internal admin, :9091).
// Sync-часть: id-формат. Async worker (с principal) форсирует GC; реальная
// рекламация — native-scheduler zot, повторный вызов идемпотентен. Authz (admin-tier)
// энфорсит per-RPC interceptor на internal-листенере (internal НЕ освобождён).
func (u *UseCase) TriggerGC(ctx context.Context, registryID string) (*operations.Operation, error) {
	if err := u.assertWired(); err != nil {
		return nil, err
	}
	if err := validateRegistryID(registryID); err != nil {
		return nil, err
	}

	op, err := operations.NewFromContext(ctx,
		ids.PrefixOperationReg,
		fmt.Sprintf("Garbage-collect Registry %s", registryID),
		&registryv1.TriggerGarbageCollectionMetadata{RegistryId: registryID},
	)
	if err != nil {
		return nil, mapRepoErr(err)
	}
	principal := operations.PrincipalFromContext(ctx)
	if err := u.ops.CreateWithPrincipal(ctx, op, principal); err != nil {
		return nil, mapRepoErr(err)
	}

	operations.Run(ctx, u.ops, op.ID, func(workerCtx context.Context) (*anypb.Any, error) {
		wctx := operations.WithPrincipal(workerCtx, principal)
		if gerr := u.zot.TriggerGC(wctx, registryID); gerr != nil {
			return nil, mapRepoErr(gerr)
		}
		return emptyAny()
	})

	return &op, nil
}
