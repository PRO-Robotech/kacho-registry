// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package handler

import (
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho-corelib/operations"
)

// TestOperationToProto_Nil — nil-guard: nil operation → nil proto (не паникует).
func TestOperationToProto_Nil(t *testing.T) {
	if got := operationToProto(nil); got != nil {
		t.Fatalf("operationToProto(nil) = %v, want nil", got)
	}
}

// TestOperationToProto_TruncatesTimestampsToSecond фиксирует, что Operation-конверт
// усекает CreatedAt/ModifiedAt до секунд — как toProtoRepository/toProtoTag/toProtoStats
// (api-conventions: «Микросекунды с БД не текут на wire», на КАЖДОМ ресурсе). Без
// truncate Operation-envelope течёт sub-секундную точность operations-таблицы, расходясь
// с остальными ресурсами того же сервиса (несогласованный wire-контракт).
func TestOperationToProto_TruncatesTimestampsToSecond(t *testing.T) {
	created := time.Date(2026, 7, 6, 12, 34, 56, 789_000_000, time.UTC)
	modified := time.Date(2026, 7, 6, 12, 35, 0, 123_000_000, time.UTC)
	op := &operations.Operation{
		ID:         "op0000000000000000aa",
		CreatedAt:  created,
		ModifiedAt: modified,
	}

	got := operationToProto(op)
	if got == nil {
		t.Fatal("operationToProto returned nil for non-nil input")
	}
	if wantC := created.Truncate(time.Second); !got.GetCreatedAt().AsTime().Equal(wantC) {
		t.Errorf("CreatedAt = %s, want %s (truncated to second)", got.GetCreatedAt().AsTime(), wantC)
	}
	if wantM := modified.Truncate(time.Second); !got.GetModifiedAt().AsTime().Equal(wantM) {
		t.Errorf("ModifiedAt = %s, want %s (truncated to second)", got.GetModifiedAt().AsTime(), wantM)
	}
}
