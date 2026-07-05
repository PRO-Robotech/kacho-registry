// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	"fmt"

	"github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/shared/serviceerr"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// errmap.go — единый seam ошибок use-case'а. Слой use-case НЕ хардкодит gRPC-коды
// (`status.Error(codes.X, …)`) — он выражает ошибку domain-sentinel'ом
// (internal/errors) и маппит РОВНО через serviceerr.ToStatus (тот же seam, что и
// mapRepoErr для repo/clients-ошибок и что worker сохраняет в Operation.error).
//
// Почему возврат — уже gRPC-статус, а не «голый» sentinel наружу: (1) corelib
// operations.Run сериализует worker-ошибку в Operation.error через status.FromError —
// closure ОБЯЗАН вернуть gRPC-status (sentinel схлопнулся бы в INTERNAL); (2) thin
// handler всё равно прогоняет sync-возврат через тот же serviceerr (mapErr) —
// идемпотентно. Так сохраняется единый seam без разбросанных codes.* по use-case.
// Остаточная связь use-case↔proto (Operation.metadata/response = proto Any) —
// осознанная by-design LRO-граница, см. docs/architecture/known-divergences.md.

// failInvalidArg — sentinel ErrInvalidArg + сообщение → gRPC INVALID_ARGUMENT.
func failInvalidArg(format string, a ...any) error {
	return serviceerr.ToStatus(fmt.Errorf("%w: %s", regerrors.ErrInvalidArg, fmt.Sprintf(format, a...)))
}

// failFailedPrecondition — sentinel ErrFailedPrecondition → gRPC FAILED_PRECONDITION.
func failFailedPrecondition(format string, a ...any) error {
	return serviceerr.ToStatus(fmt.Errorf("%w: %s", regerrors.ErrFailedPrecondition, fmt.Sprintf(format, a...)))
}

// failAlreadyExists — sentinel ErrAlreadyExists → gRPC ALREADY_EXISTS.
func failAlreadyExists(format string, a ...any) error {
	return serviceerr.ToStatus(fmt.Errorf("%w: %s", regerrors.ErrAlreadyExists, fmt.Sprintf(format, a...)))
}

// failUnavailable — sentinel ErrUnavailable → gRPC UNAVAILABLE.
func failUnavailable(format string, a ...any) error {
	return serviceerr.ToStatus(fmt.Errorf("%w: %s", regerrors.ErrUnavailable, fmt.Sprintf(format, a...)))
}
