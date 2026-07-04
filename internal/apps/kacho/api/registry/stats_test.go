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
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/PRO-Robotech/kacho-registry/internal/domain"
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
		LastGCAt:        time.Unix(1700000000, 0).UTC(),
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
	require.Equal(t, want.LastGCAt, got.LastGCAt)
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
