// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package registry_test — unit-тесты sync-проекции инфра-статистики namespace
// (GetRegistryStats, Internal-API :9091). Проверяется use-case-механика: проброс
// domain.RegistryStats из zot-бэкенда наружу без изменения и sync-reject malformed
// registry-id первым стейтментом (paritet с TriggerGC). REG-38.
package registry_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/shared/serviceerr"
	"github.com/PRO-Robotech/kacho-registry/internal/domain"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// REG-38 — Stats happy: use-case Stats(registryID) отдаёт domain.RegistryStats из
// zot-бэкенда без изменения (все поля проброшены), без error; бэкенд получил ровно
// наш registryID.
func TestRegistry_REG38_Stats_HappyPath(t *testing.T) {
	want := &domain.RegistryStats{
		RegistryID:      validRegID,
		RepositoryCount: 3,
		TagCount:        7,
		TotalSizeBytes:  4096,
		BlobCount:       11,
	}
	zot := &mockZot{statsResult: want}
	uc := newUC(&mockRepo{}, zot, &mockIAM{}, newMemOps())

	got, err := uc.Stats(aliceCtx(), validRegID)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, want.RegistryID, got.RegistryID)
	require.Equal(t, int32(3), got.RepositoryCount)
	require.Equal(t, int32(7), got.TagCount)
	require.Equal(t, int64(4096), got.TotalSizeBytes)
	require.Equal(t, int64(11), got.BlobCount)
	require.Equal(t, []string{validRegID}, zot.statsCalls, "zot-бэкенд получил ровно наш registryID")
}

// REG-38 — Stats malformed id → синхронный INVALID_ARGUMENT (zot не трогается);
// mirror TriggerGC malformed-id-теста (единая дисциплина: malformed id → sync reject
// первым стейтментом RPC, api-conventions.md).
func TestRegistry_REG38_Stats_MalformedID(t *testing.T) {
	zot := &mockZot{}
	uc := newUC(&mockRepo{}, zot, &mockIAM{}, newMemOps())

	_, err := uc.Stats(context.Background(), "not-an-id")
	require.Equal(t, codes.InvalidArgument, codeOf(t, err))
	require.Empty(t, zot.statsCalls, "zot not touched on sync-reject")
}

// REG-38 — Stats zot-backend error: zot вернул Unavailable → use-case пробрасывает
// domain-sentinel (не глотает), и единый handler-seam serviceerr.ToStatus (mapErr)
// маппит его в gRPC Unavailable БЕЗ утечки backend-детали. Раньше backend-error ветка
// Stats не покрывалась — mismap/leak на этом пути прошёл бы незамеченным (mirror
// REG-25 DeleteTag_WorkerZotError / REG-08 Delete_ZotUnavailable).
func TestRegistry_REG38_Stats_ZotError_Propagates(t *testing.T) {
	zot := &mockZot{statsErr: regerrors.ErrUnavailable}
	uc := newUC(&mockRepo{}, zot, &mockIAM{}, newMemOps())

	got, err := uc.Stats(aliceCtx(), validRegID)
	require.Nil(t, got)
	require.ErrorIs(t, err, regerrors.ErrUnavailable, "zot backend error propagated, not swallowed")
	require.Equal(t, []string{validRegID}, zot.statsCalls, "backend was reached with our id")

	// Тот же маппинг, что применяет thin handler (mapErr → serviceerr.ToStatus).
	st, ok := status.FromError(serviceerr.ToStatus(err))
	require.True(t, ok)
	require.Equal(t, codes.Unavailable, st.Code(), "mapped to Unavailable, not mismapped to Internal")
	require.NotContains(t, st.Message(), "pgx", "no raw backend detail leaked")
	require.NotContains(t, st.Message(), "http", "no raw backend detail leaked")
}
