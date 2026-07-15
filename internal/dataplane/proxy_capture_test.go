// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package dataplane

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// proxy_capture_test.go — TEST-ONLY (ban #13): ForwardCapture-путь реального
// ZotForwarder (blob-finalize, REG-33 Defect A). proxy_test.go покрывает стриминговый
// Forward; ForwardCapture (буферизующий bufferingRecorder) был непокрыт. Локает, что
// буферизованный ответ zot несёт статус/заголовки/тело 1:1 и что caller-credentials
// вычищаются и на capture-пути (тот же proxy, что и Forward).

// TestDataplane_ZotForwardCapture_BuffersStatusHeadersBody — ForwardCapture буферизует
// ответ zot (не стримит): CapturedResponse несёт zot-статус, заголовки (Location /
// Docker-Content-Digest, критичные для docker-финализации) и тело. Flush zot'а — no-op
// в bufferingRecorder (ничего не стримим). Caller Authorization не доходит до zot.
func TestDataplane_ZotForwardCapture_BuffersStatusHeadersBody(t *testing.T) {
	var gotPath, gotMethod, gotAuth string
	zot := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Location", "/v2/reg-A/app/blobs/sha256:cap")
		w.Header().Set("Docker-Content-Digest", "sha256:cap")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("finalize-ok"))
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush() // упирается в bufferingRecorder.Flush (no-op) — совместимость с ReverseProxy
		}
	}))
	defer zot.Close()

	fw, err := NewZotForwarder(zot.URL, nil)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPut, "/v2/reg-A/app/blobs/uploads/upl-1?digest=sha256:cap", nil)
	req.Header.Set("Authorization", "Bearer identity-jwt-secret")

	captured := fw.ForwardCapture(req)

	require.Equal(t, http.StatusCreated, captured.Status, "буферизованный zot-статус")
	require.Equal(t, "/v2/reg-A/app/blobs/sha256:cap", captured.Header.Get("Location"), "zot Location буферизован")
	require.Equal(t, "sha256:cap", captured.Header.Get("Docker-Content-Digest"), "zot digest-заголовок буферизован")
	require.Equal(t, "finalize-ok", string(captured.Body), "тело ответа zot буферизовано")
	require.Equal(t, "/v2/reg-A/app/blobs/uploads/upl-1", gotPath, "путь форвардится как есть")
	require.Equal(t, http.MethodPut, gotMethod)
	require.Empty(t, gotAuth, "caller Authorization не форвардится в zot и на capture-пути (CWE-522/200)")
}

// TestDataplane_ZotForwardCapture_ZotDown_502Buffered — zot недоступен на capture-пути →
// ErrorHandler буферизует 502 (fail-closed, не паника). forwardBlobFinalize тогда релеит
// не-2xx как есть (не пишет pending-строку — не заявляет владение).
func TestDataplane_ZotForwardCapture_ZotDown_502Buffered(t *testing.T) {
	zot := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := zot.URL
	zot.Close() // недоступен

	fw, err := NewZotForwarder(url, nil)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPut, "/v2/reg-A/app/blobs/uploads/upl-1?digest=sha256:x", nil)
	captured := fw.ForwardCapture(req)
	require.Equal(t, http.StatusBadGateway, captured.Status, "zot down → буферизованный 502 (fail-closed)")
}
