// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package handler

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-corelib/operations"
	operationpb "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/operation"
)

// OperationHandler реализует operationpb.OperationServiceServer каталога
// kacho-registry: клиент поллит Get(operation_id) до done=true после async-мутации
// (Create/Update/Delete/DeleteTag/TriggerGC). Регистрируется на обоих листенерах.
//
// OperationService помечен Public:true в permission_map (per-RPC IAM Check
// пропускается — op-id opaque, поллинг), поэтому авторизация выполняется на
// data-уровне: ownership-scoped GetOwned/CancelOwned матчат операцию по
// principal'у создателя (записанному через CreateWithPrincipal). Чужой principal
// → NotFound (no-leak). Это закрывает BOLA: без scoping'а любой аутентифицированный
// вызывающий мог прочитать/отменить чужую операцию по её id.
type OperationHandler struct {
	operationpb.UnimplementedOperationServiceServer
	owned operations.OwnedOperationRepo
}

// NewOperationHandler создаёт OperationHandler поверх ownership-scoped
// LRO-репозитория. repo обязан поддерживать OwnedOperationRepo (pgRepo из
// operations.NewRepo — поддерживает); иначе fail-fast при wiring'е.
func NewOperationHandler(repo operations.Repo) *OperationHandler {
	owned, ok := operations.AsOwned(repo)
	if !ok {
		panic("operations.Repo does not support ownership-scoped access (OwnedOperationRepo)")
	}
	return &OperationHandler{owned: owned}
}

// Get возвращает текущее состояние операции (done/error/response) — только если
// вызывающий principal владеет операцией; иначе NotFound.
func (h *OperationHandler) Get(ctx context.Context, req *operationpb.GetOperationRequest) (*operationpb.Operation, error) {
	if req.GetOperationId() == "" {
		return nil, status.Error(codes.InvalidArgument, "operation_id required")
	}
	owner := operations.OwnerFromPrincipal(operations.PrincipalFromContext(ctx))
	op, err := h.owned.GetOwned(ctx, req.GetOperationId(), owner)
	if err != nil {
		if errors.Is(err, operations.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "operation %s not found", req.GetOperationId())
		}
		// Без leak'а pgx-detail наружу.
		return nil, status.Error(codes.Internal, "operation get failed")
	}
	return operationToProto(op), nil
}

// Cancel отменяет ещё не завершённую операцию (done=true, code=CANCELLED) —
// только если вызывающий principal владеет операцией; иначе NotFound.
func (h *OperationHandler) Cancel(ctx context.Context, req *operationpb.CancelOperationRequest) (*operationpb.Operation, error) {
	if req.GetOperationId() == "" {
		return nil, status.Error(codes.InvalidArgument, "operation_id required")
	}
	owner := operations.OwnerFromPrincipal(operations.PrincipalFromContext(ctx))
	op, err := h.owned.CancelOwned(ctx, req.GetOperationId(), owner)
	if err != nil {
		if errors.Is(err, operations.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "operation %s not found", req.GetOperationId())
		}
		if errors.Is(err, operations.ErrAlreadyDone) {
			return nil, status.Errorf(codes.FailedPrecondition, "operation %s already completed", req.GetOperationId())
		}
		return nil, status.Error(codes.Internal, "operation cancel failed")
	}
	return operationToProto(op), nil
}
