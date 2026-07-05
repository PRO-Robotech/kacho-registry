// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	"context"

	"github.com/PRO-Robotech/kacho-corelib/operations"
)

// ListOperationsQuery — вход ListOperations реестра: per-resource история
// async-операций, отфильтрованная по resource_id=registry_id. Cursor-пагинация
// как у прочих List (page_size/page_token опаковый).
type ListOperationsQuery struct {
	RegistryID string
	PageSize   int64
	PageToken  string
}

// ListOperations возвращает историю async-операций реестра (Create/Update/Delete/
// DeleteTag/GC) — sync-чтение поверх общего LRO-репозитория с фильтром по
// resource_id. registry_id обязателен: пустой дал бы operations.List без фильтра
// (история ВСЕХ реестров — leak), поэтому пустой → InvalidArgument; malformed id
// отсекается первым стейтментом (parity с Get/Stats). Сырой repo-текст наружу не
// течёт (mapRepoErr → фикс. INTERNAL).
func (u *UseCase) ListOperations(ctx context.Context, q ListOperationsQuery) ([]operations.Operation, string, error) {
	if err := u.assertWired(); err != nil {
		return nil, "", err
	}
	if q.RegistryID == "" {
		return nil, "", failInvalidArg("registry_id is required")
	}
	if err := ValidateRegistryID(q.RegistryID); err != nil {
		return nil, "", err
	}
	ops, next, err := u.ops.List(ctx, operations.ListFilter{
		ResourceID: q.RegistryID,
		PageSize:   q.PageSize,
		PageToken:  q.PageToken,
	})
	if err != nil {
		return nil, "", mapRepoErr(err)
	}
	return ops, next, nil
}
