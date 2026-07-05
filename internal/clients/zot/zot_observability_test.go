// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// zot_observability_test.go — fail-closed ветки zot-адаптера обязаны залогировать
// discarded root-cause ПЕРЕД возвратом фиксированного ErrUnavailable (CWE-778): без
// этого оператор, отлаживающий пустые Repository/Tag-проекции, не отличит сетевой
// сбой от GraphQL/schema-разрыва. Наружу сырой zot-текст по-прежнему НЕ течёт —
// клиент видит только ErrUnavailable, лог — internal-only.
package zot_test

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	registry "github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/api/registry"
	zotclient "github.com/PRO-Robotech/kacho-registry/internal/clients/zot"
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

// GraphQL errors-массив (напр. сломанный ImageList после zot-upgrade) → ErrUnavailable
// наружу, но лог несёт signal (status/err) ПЕРЕД схлопом.
func TestZot_GraphQLErrors_LoggedBeforeFailClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errors":[{"message":"cannot query field ImageList"}]}`))
	}))
	defer srv.Close()

	buf := captureSlog(t)
	_, _, err := zotclient.New(srv.URL).ListRepositories(t.Context(),
		registry.RepoListQuery{RegistryID: "reg-A"})

	require.ErrorIs(t, err, regerrors.ErrUnavailable, "caller still sees only the sentinel")
	require.Contains(t, buf.String(), "level=ERROR", "fail-closed branch must emit an error log")
	require.Contains(t, buf.String(), "zot", "log must identify the zot adapter")
}

// Non-2xx статус distribution-API (напр. 503 на /v2/_catalog) → ErrUnavailable наружу,
// но лог несёт status-код ПЕРЕД схлопом.
func TestZot_Non2xxStatus_LoggedBeforeFailClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	buf := captureSlog(t)
	_, err := zotclient.New(srv.URL).NamespaceEmpty(t.Context(), "reg-A")

	require.ErrorIs(t, err, regerrors.ErrUnavailable)
	require.Contains(t, buf.String(), "level=ERROR", "fail-closed branch must emit an error log")
	require.Contains(t, buf.String(), "503", "log must carry the discarded HTTP status")
}
