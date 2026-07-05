// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// errmap_test.go — unit-тесты SQLSTATE→sentinel трансляции + observability:
// неклассифицированная DB-ошибка обязана залогировать сырой SQLSTATE/текст ПЕРЕД
// тем как схлопнуться в фиксированный INTERNAL (наружу сырой pgx не течёт, но
// внутренний лог несёт причину — иначе живой сбой невидим). Пакет pg (internal),
// а не pg_test — тестируем unexported wrapPgErr; Docker не требуется.
package pg

import (
	"bytes"
	"errors"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// captureSlog подменяет slog.Default() буфером на время теста.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

// Неклассифицированный SQLSTATE (напр. 42P01 undefined_table — goose-divergence) →
// ErrInternal наружу, но сырой код+текст залогированы (иначе живой сбой Create даёт
// «internal database error» без единой лог-строки).
func TestWrapPgErr_UnclassifiedPgError_LogsRawSQLSTATE(t *testing.T) {
	buf := captureSlog(t)
	pgErr := &pgconn.PgError{Code: "42P01", Message: `relation "registry_outbox" does not exist`}

	got := wrapPgErr(pgErr, "registry_outbox", "reg123")

	require.ErrorIs(t, got, regerrors.ErrInternal, "unclassified pg error → ErrInternal (no raw leak)")
	log := buf.String()
	require.Contains(t, log, "42P01", "SQLSTATE must be logged")
	require.Contains(t, log, "registry_outbox", "raw pg message must be logged")
}

// Non-pg unknown error тоже логируется перед схлопом в ErrInternal.
func TestWrapPgErr_UnknownError_Logs(t *testing.T) {
	buf := captureSlog(t)
	got := wrapPgErr(errors.New("connection reset by peer"), "Registry", "reg123")
	require.ErrorIs(t, got, regerrors.ErrInternal)
	require.Contains(t, buf.String(), "connection reset by peer")
}

// Классифицированные ошибки (ErrNoRows→NotFound, 23505→AlreadyExists) НЕ логируются
// как error (это ожидаемые доменные исходы, не сбой наблюдаемости).
func TestWrapPgErr_ClassifiedErrors_NotOverLogged(t *testing.T) {
	t.Run("no_rows", func(t *testing.T) {
		buf := captureSlog(t)
		got := wrapPgErr(pgx.ErrNoRows, "Registry", "reg123")
		require.ErrorIs(t, got, regerrors.ErrNotFound)
		require.NotContains(t, buf.String(), "level=ERROR", "NotFound не error-лог")
	})
	t.Run("unique", func(t *testing.T) {
		buf := captureSlog(t)
		got := wrapPgErr(&pgconn.PgError{Code: "23505"}, "Registry", "reg123")
		require.ErrorIs(t, got, regerrors.ErrAlreadyExists)
		require.NotContains(t, buf.String(), "level=ERROR")
	})
	t.Run("nil_passthrough", func(t *testing.T) {
		require.NoError(t, wrapPgErr(nil, "Registry", "reg123"))
	})
}
