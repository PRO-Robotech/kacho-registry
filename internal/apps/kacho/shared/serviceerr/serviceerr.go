// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package serviceerr — единый маппинг sentinel-ошибок kacho-registry в
// gRPC-статус. Используется и тонким handler'ом (sync-возврат), и async-worker'ом
// LRO (worker сохраняет google.rpc.Status в Operation.error), поэтому доменная
// ошибка обязана конвертироваться в gRPC-код именно здесь — единообразно для
// sync- и async-веток.
//
// Тексты сообщений — часть контракта Kachō ("<Resource> %s not found" и т. п.);
// сырой pgx/SQL наружу не утекает (некатегоризированное → фиксированный INTERNAL).
package serviceerr

import (
	"errors"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// ToStatus переводит ошибку use-case/repo/clients в gRPC-статус, срезая
// sentinel-префикс. Неклассифицированное → фиксированный INTERNAL (без leak'а).
// Уже-gRPC-статус (например, validate.PageSize) пробрасывается как есть.
func ToStatus(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, regerrors.ErrNotFound):
		return status.Error(codes.NotFound, strip(err, regerrors.ErrNotFound))
	case errors.Is(err, regerrors.ErrAlreadyExists):
		return status.Error(codes.AlreadyExists, strip(err, regerrors.ErrAlreadyExists))
	case errors.Is(err, regerrors.ErrFailedPrecondition):
		return status.Error(codes.FailedPrecondition, strip(err, regerrors.ErrFailedPrecondition))
	case errors.Is(err, regerrors.ErrInvalidArg):
		return status.Error(codes.InvalidArgument, strip(err, regerrors.ErrInvalidArg))
	case errors.Is(err, regerrors.ErrUnavailable):
		return status.Error(codes.Unavailable, strip(err, regerrors.ErrUnavailable))
	case errors.Is(err, regerrors.ErrUnimplemented):
		return status.Error(codes.Unimplemented, "method not implemented")
	case errors.Is(err, regerrors.ErrInternal):
		return status.Error(codes.Internal, "internal database error")
	}
	if st, ok := status.FromError(err); ok && st.Code() != codes.Unknown {
		return err
	}
	return status.Error(codes.Internal, "internal database error")
}

// strip убирает префикс "<sentinel>: ", чтобы клиент видел стабильное сообщение.
func strip(err, sentinel error) string {
	msg := err.Error()
	prefix := sentinel.Error() + ": "
	if rest, ok := strings.CutPrefix(msg, prefix); ok {
		return rest
	}
	return msg
}
