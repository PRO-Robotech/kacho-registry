// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package serviceerr_test — unit-тесты маппинга sentinel→gRPC + observability:
// неклассифицированная ошибка (напр. corelib operations `repo.Create: <raw pg>`,
// не прошедшая через registry-adapter Wrap) обязана залогировать сырой текст ПЕРЕД
// схлопом в фиксированный INTERNAL — иначе живой сбой Create невидим (grabli #7).
package serviceerr_test

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/shared/serviceerr"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

func codeOf(t *testing.T, err error) codes.Code {
	t.Helper()
	st, ok := status.FromError(err)
	require.True(t, ok)
	return st.Code()
}

// Неклассифицированная ошибка (не registry-sentinel, не gRPC-статус) → INTERNAL с
// фикс. текстом наружу, но сырой текст залогирован (клиент видит стабильное, лог —
// причину).
func TestToStatus_UnclassifiedError_LogsRaw(t *testing.T) {
	buf := captureSlog(t)
	raw := fmt.Errorf("repo.Create: %w", errors.New("null value in column \"account_id\""))

	st := serviceerr.ToStatus(raw)

	require.Equal(t, codes.Internal, codeOf(t, st))
	require.Equal(t, "internal database error", status.Convert(st).Message(), "raw pg НЕ течёт наружу")
	log := buf.String()
	require.Contains(t, log, "repo.Create", "внутренний лог несёт сырую причину")
	require.Contains(t, log, "account_id")
}

// ErrInternal sentinel (обёрнутый контекстом) — тоже логируется перед возвратом.
func TestToStatus_ErrInternalWrapped_Logs(t *testing.T) {
	buf := captureSlog(t)
	st := serviceerr.ToStatus(fmt.Errorf("outbox emit: %w", regerrors.ErrInternal))
	require.Equal(t, codes.Internal, codeOf(t, st))
	require.Contains(t, buf.String(), "outbox emit")
}

// Классифицированные sentinel'ы маппятся в свои коды и НЕ порождают error-лог.
func TestToStatus_Classified_NoErrorLog(t *testing.T) {
	buf := captureSlog(t)
	st := serviceerr.ToStatus(fmt.Errorf("%w: Registry reg123 not found", regerrors.ErrNotFound))
	require.Equal(t, codes.NotFound, codeOf(t, st))
	require.NotContains(t, buf.String(), "level=ERROR", "NotFound — не сбой наблюдаемости")
}
