// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package handler

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-corelib/operations"
	operationpb "github.com/PRO-Robotech/kacho-corelib/proto/gen/go/kacho/cloud/operation"
)

// OperationHandler реализует operationpb.OperationServiceServer каталога
// kacho-registry: клиент поллит Get(operation_id) до done=true после async-мутации
// (Create/Update/Delete/DeleteTag/TriggerGC). Регистрируется на обоих листенерах.
type OperationHandler struct {
	operationpb.UnimplementedOperationServiceServer
	repo operations.Repo
}

// NewOperationHandler создаёт OperationHandler поверх LRO-репозитория.
func NewOperationHandler(repo operations.Repo) *OperationHandler {
	return &OperationHandler{repo: repo}
}

// Get возвращает текущее состояние операции (done/error/response).
func (h *OperationHandler) Get(ctx context.Context, req *operationpb.GetOperationRequest) (*operationpb.Operation, error) {
	if req.GetOperationId() == "" {
		return nil, status.Error(codes.InvalidArgument, "operation_id required")
	}
	op, err := h.repo.Get(ctx, req.GetOperationId())
	if err != nil {
		if errors.Is(err, operations.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "operation %s not found", req.GetOperationId())
		}
		// Без leak'а pgx-detail наружу.
		return nil, status.Error(codes.Internal, "operation get failed")
	}
	return operationToProto(op), nil
}

// Cancel отменяет ещё не завершённую операцию (done=true, code=CANCELLED).
func (h *OperationHandler) Cancel(ctx context.Context, req *operationpb.CancelOperationRequest) (*operationpb.Operation, error) {
	if req.GetOperationId() == "" {
		return nil, status.Error(codes.InvalidArgument, "operation_id required")
	}
	if err := h.repo.Cancel(ctx, req.GetOperationId()); err != nil {
		if errors.Is(err, operations.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "operation %s not found", req.GetOperationId())
		}
		if errors.Is(err, operations.ErrAlreadyDone) {
			return nil, status.Errorf(codes.FailedPrecondition, "operation %s already completed", req.GetOperationId())
		}
		return nil, status.Error(codes.Internal, "operation cancel failed")
	}
	op, err := h.repo.Get(ctx, req.GetOperationId())
	if err != nil {
		if errors.Is(err, operations.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "operation %s not found", req.GetOperationId())
		}
		return nil, status.Error(codes.Internal, "operation reload after cancel failed")
	}
	return operationToProto(op), nil
}
