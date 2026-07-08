// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package handler

import (
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho-registry/internal/domain"
)

// TestToProtoStats_Nil — nil-guard: nil domain → nil proto (GetRegistryStats
// с пустым источником не паникует).
func TestToProtoStats_Nil(t *testing.T) {
	if got := toProtoStats(nil); got != nil {
		t.Fatalf("toProtoStats(nil) = %v, want nil", got)
	}
}

// TestToProtoStats_Maps фиксирует полный перенос domain.RegistryStats →
// registryv1.RegistryStats (Internal-only проекция; путь GetRegistryStats иначе
// не покрыт). LastGcAt truncate до секунд (api-conventions timestamp-дисциплина).
func TestToProtoStats_Maps(t *testing.T) {
	gc := time.Date(2026, 7, 6, 12, 34, 56, 789_000_000, time.UTC)
	s := &domain.RegistryStats{
		RegistryID:      "reg-abc",
		RepositoryCount: 7,
		TagCount:        42,
		TotalSizeBytes:  1 << 30,
		BlobCount:       128,
		LastGCAt:        gc,
	}

	got := toProtoStats(s)
	if got == nil {
		t.Fatal("toProtoStats returned nil for non-nil input")
	}
	if got.GetRegistryId() != s.RegistryID {
		t.Errorf("RegistryId = %q, want %q", got.GetRegistryId(), s.RegistryID)
	}
	if got.GetRepositoryCount() != s.RepositoryCount {
		t.Errorf("RepositoryCount = %d, want %d", got.GetRepositoryCount(), s.RepositoryCount)
	}
	if got.GetTagCount() != s.TagCount {
		t.Errorf("TagCount = %d, want %d", got.GetTagCount(), s.TagCount)
	}
	if got.GetTotalSizeBytes() != s.TotalSizeBytes {
		t.Errorf("TotalSizeBytes = %d, want %d", got.GetTotalSizeBytes(), s.TotalSizeBytes)
	}
	if got.GetBlobCount() != s.BlobCount {
		t.Errorf("BlobCount = %d, want %d", got.GetBlobCount(), s.BlobCount)
	}
	// truncate до секунд: под-секундная часть отбрасывается.
	wantGC := gc.Truncate(time.Second)
	if !got.GetLastGcAt().AsTime().Equal(wantGC) {
		t.Errorf("LastGcAt = %s, want %s (truncated to second)", got.GetLastGcAt().AsTime(), wantGC)
	}
}

// TestToProtoStats_ZeroGCTime — нулевой LastGCAt (GC ещё не запускался) →
// LastGcAt отсутствует (prototime.Truncate возвращает nil на zero-time).
func TestToProtoStats_ZeroGCTime(t *testing.T) {
	got := toProtoStats(&domain.RegistryStats{RegistryID: "reg-z"})
	if got == nil {
		t.Fatal("toProtoStats returned nil for non-nil input")
	}
	if got.GetLastGcAt() != nil {
		t.Errorf("LastGcAt = %v, want nil for zero GC time", got.GetLastGcAt())
	}
}
