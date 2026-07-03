// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/PRO-Robotech/kacho-corelib/ids"
	"github.com/PRO-Robotech/kacho-corelib/operations"
	registryv1 "github.com/PRO-Robotech/kacho-registry/proto/gen/go/kacho/cloud/registry/v1"

	"github.com/PRO-Robotech/kacho-registry/internal/domain"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// Delete — async удаление реестра (forward-only). Sync-часть: id-формат + Operation.
// Async worker (с проброшенным principal): атомарный CAS ACTIVE→DELETING (idempotent
// на уже-DELETING — forward-only retry), best-effort снятие zot-namespace, DELETE
// строки + unregister-intent в ОДНОЙ writer-tx. `DELETING` — терминальный: revert в
// ACTIVE невозможен; повторный/конкурентный Delete завершается идемпотентно (ровно
// одна транзакция физически удаляет строку и эмитит ровно один unregister-intent).
func (u *UseCase) Delete(ctx context.Context, registryID string) (*operations.Operation, error) {
	if err := u.assertWired(); err != nil {
		return nil, err
	}
	if registryID == "" {
		return nil, status.Error(codes.InvalidArgument, "registryId is required")
	}
	if err := validateRegistryID(registryID); err != nil {
		return nil, err
	}

	op, err := operations.NewFromContext(ctx,
		ids.PrefixOperationReg,
		fmt.Sprintf("Delete Registry %s", registryID),
		&registryv1.DeleteRegistryMetadata{RegistryId: registryID},
	)
	if err != nil {
		return nil, mapRepoErr(err)
	}
	principal := operations.PrincipalFromContext(ctx)
	if err := u.ops.CreateWithPrincipal(ctx, op, principal); err != nil {
		return nil, mapRepoErr(err)
	}

	operations.Run(ctx, u.ops, op.ID, func(workerCtx context.Context) (*anypb.Any, error) {
		return u.doDelete(operations.WithPrincipal(workerCtx, principal), registryID)
	})

	return &op, nil
}

// doDelete — worker удаления: CAS→DELETING → zot-namespace снятие (best-effort,
// lazy) → DELETE + unregister-intent. Идемпотентно: строка уже удалена → done без
// повторного destructive-эффекта; ровно один unregister-intent (эмитится только
// той tx, что физически удалила строку).
func (u *UseCase) doDelete(ctx context.Context, registryID string) (*anypb.Any, error) {
	marked, err := u.writer.MarkDeleting(ctx, registryID)
	if err != nil {
		if errors.Is(err, regerrors.ErrNotFound) {
			// Строка уже удалена (конкурентный/повторный Delete) — идемпотентный done.
			return emptyAny()
		}
		return nil, mapRepoErr(err)
	}

	// zot-namespace lazy: провизионится на push, снимать нечего пока data-plane нет.
	// Best-effort — недоступность zot не блокирует forward-only удаление namespace-
	// метаданных (при реальном zot RemoveNamespace станет авторитетным).
	if rerr := u.zot.RemoveNamespace(ctx, registryID); rerr != nil {
		slog.Default().Warn("registry delete: zot namespace removal best-effort failed",
			"registry_id", registryID, "err", rerr)
	}

	intent := domain.UnregisterIntentForDelete(registryID, marked.ProjectID)
	if derr := u.writer.Delete(ctx, registryID, intent); derr != nil {
		if errors.Is(derr, regerrors.ErrNotFound) {
			// Конкурентная транзакция физически удалила строку первой — идемпотентно.
			return emptyAny()
		}
		return nil, mapRepoErr(derr)
	}
	return emptyAny()
}

// emptyAny — Operation.response для Delete (google.protobuf.Empty).
func emptyAny() (*anypb.Any, error) {
	out, err := anypb.New(&emptypb.Empty{})
	if err != nil {
		return nil, mapRepoErr(err)
	}
	return out, nil
}
