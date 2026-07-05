// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package registry_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-corelib/ids"
	"github.com/PRO-Robotech/kacho-corelib/operations"

	registry "github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/api/registry"
)

// TestListOperations_RequiresRegistryID — пустой registry_id недопустим: без
// фильтра resource_id operations.List вернул бы историю ВСЕХ реестров (leak),
// поэтому пустой id → InvalidArgument ещё до обращения к репозиторию.
func TestListOperations_RequiresRegistryID(t *testing.T) {
	t.Parallel()
	uc := newUC(&mockRepo{}, &mockZot{}, &mockIAM{}, newMemOps())
	_, _, err := uc.ListOperations(context.Background(), registry.ListOperationsQuery{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestListOperations_MalformedRegistryID — malformed id → sync InvalidArgument
// первым стейтментом (parity с Get/Stats), до обращения к ops-репозиторию.
func TestListOperations_MalformedRegistryID(t *testing.T) {
	t.Parallel()
	uc := newUC(&mockRepo{}, &mockZot{}, &mockIAM{}, newMemOps())
	_, _, err := uc.ListOperations(context.Background(),
		registry.ListOperationsQuery{RegistryID: "not-a-registry-id"})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestListOperations_HappyPath — валидный registry_id → per-resource история
// операций реестра (фильтр по resource_id проброшен в operations.ListFilter).
func TestListOperations_HappyPath(t *testing.T) {
	t.Parallel()
	ops := newMemOps()
	regID := ids.NewID(ids.PrefixRegistry)
	ops.put(operations.Operation{ID: ids.NewID(ids.PrefixOperationReg), Description: "Create registry"})
	ops.put(operations.Operation{ID: ids.NewID(ids.PrefixOperationReg), Description: "Update registry"})

	uc := newUC(&mockRepo{}, &mockZot{}, &mockIAM{}, ops)
	list, _, err := uc.ListOperations(context.Background(),
		registry.ListOperationsQuery{RegistryID: regID})
	require.NoError(t, err)
	require.NotEmpty(t, list)
}

// TestListOperations_RepoError_NoLeak — сырой pgx/SQL-текст ops-репозитория
// наружу не течёт: репо-ошибка → фикс. codes.Internal без деталей (security.md).
func TestListOperations_RepoError_NoLeak(t *testing.T) {
	t.Parallel()
	const secret = `pq: relation "kacho_registry.operations" does not exist (host=db-internal-7)`
	ops := newMemOps()
	ops.listErr = errors.New(secret)

	uc := newUC(&mockRepo{}, &mockZot{}, &mockIAM{}, ops)
	_, _, err := uc.ListOperations(context.Background(),
		registry.ListOperationsQuery{RegistryID: ids.NewID(ids.PrefixRegistry)})
	require.Error(t, err)
	require.Equal(t, codes.Internal, status.Code(err))
	require.NotContains(t, err.Error(), "relation", "raw pgx/SQL text must not leak")
	require.NotContains(t, err.Error(), "db-internal-7", "infra detail must not leak")
}
