// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// repository_config_maperr_test.go — unit-тесты mapConfigErr (config-overlay Repository,
// RG-1): SQLSTATE→sentinel + X02 INTERNAL-no-leak. Пакет pg (internal, unexported
// mapConfigErr); Docker НЕ требуется.
package pg

import (
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/shared/serviceerr"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// RG-1-X02 — non-sentineled DB-сбой (connection-drop, SQLSTATE 08006 с driver-текстом
// host=…) → mapConfigErr схлопывает в ErrInternal; serviceerr → INTERNAL "internal
// database error"; сырой pgx/driver-текст (host/user/db) НЕ течёт наружу (behaviour-level).
func TestMapConfigErr_X02_InternalNoLeak(t *testing.T) {
	raw := &pgconn.PgError{
		Code:    "08006", // connection_failure — НЕ в классифицированном switch
		Message: "server closed the connection unexpectedly",
		Detail:  "host=db-internal-7 user=registry dbname=kacho_registry",
	}
	mapped := mapConfigErr(raw)
	require.ErrorIs(t, mapped, regerrors.ErrInternal, "неклассифицированный SQLSTATE → ErrInternal")

	st := status.Convert(serviceerr.ToStatus(mapped))
	require.Equal(t, codes.Internal, st.Code())
	require.Equal(t, "internal database error", st.Message(), "фикс. INTERNAL-текст (X02)")
	require.NotContains(t, st.Message(), "host=", "driver-текст не течёт")
	require.NotContains(t, st.Message(), "db-internal-7")
	require.NotContains(t, st.Message(), "08006")
}

// RG-1 — классифицированные SQLSTATE → точные sentinel + контракт-тексты (A02/A24/FK).
func TestMapConfigErr_ClassifiedSQLSTATE(t *testing.T) {
	cases := []struct {
		name string
		err  error
		code codes.Code
		msg  string
	}{
		{"no_rows", pgx.ErrNoRows, codes.NotFound, "repository not found"},
		{"unique_23505", &pgconn.PgError{Code: "23505"}, codes.AlreadyExists, "repository already exists"},
		{"fk_23503", &pgconn.PgError{Code: "23503"}, codes.FailedPrecondition, "registry not found"},
		{"check_23514", &pgconn.PgError{Code: "23514"}, codes.InvalidArgument, "invalid repository config"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st := status.Convert(serviceerr.ToStatus(mapConfigErr(c.err)))
			require.Equal(t, c.code, st.Code())
			require.Equal(t, c.msg, st.Message())
		})
	}
}

// RG-1-A24 — sentinel-passthrough: guard-ошибка (ErrFailedPrecondition "registry is being
// deleted") НЕ переоборачивается mapConfigErr (сохраняет контракт-текст).
func TestMapConfigErr_SentinelPassthrough(t *testing.T) {
	guardErr := regerrors.ErrFailedPrecondition
	require.ErrorIs(t, mapConfigErr(guardErr), regerrors.ErrFailedPrecondition, "sentinel не переоборачивается")
}
