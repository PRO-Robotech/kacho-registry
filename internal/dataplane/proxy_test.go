// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package dataplane

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// zot-forward: ZotForwarder стримит запрос в zot как есть (путь/тело/статус) и
// возвращает записанный клиенту HTTP-статус.
func TestDataplane_ZotForward_StreamsAndCapturesStatus(t *testing.T) {
	var gotPath, gotMethod, gotBody string
	zot := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Docker-Content-Digest", "sha256:deadbeef")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("zot-ok"))
	}))
	defer zot.Close()

	fw, err := NewZotForwarder(zot.URL, nil)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPut, "/v2/reg-A/app/manifests/v1", stringReader("manifest-bytes"))
	rec := httptest.NewRecorder()
	status := fw.Forward(rec, req)

	require.Equal(t, http.StatusCreated, status, "captured zot status")
	require.Equal(t, http.StatusCreated, rec.Code)
	require.Equal(t, "zot-ok", rec.Body.String(), "zot body streamed to client")
	require.Equal(t, "/v2/reg-A/app/manifests/v1", gotPath, "path forwarded as-is")
	require.Equal(t, http.MethodPut, gotMethod)
	require.Equal(t, "manifest-bytes", gotBody, "request body streamed to zot")
	require.Equal(t, "sha256:deadbeef", rec.Header().Get("Docker-Content-Digest"), "zot headers passed back")
}

// SEC (CWE-522/200) — caller-identity credentials НЕ форвардятся в zot: authz уже
// энфорснут per-request Check выше, а bearer/cookie в access-логах zot расширяли бы
// harvest-поверхность (реплей в пределах TTL токена). Director вычищает Authorization
// и Cookie до проксирования.
func TestDataplane_ZotForward_StripsCallerCredentials(t *testing.T) {
	var gotAuth, gotCookie string
	zot := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotCookie = r.Header.Get("Cookie")
		w.WriteHeader(http.StatusOK)
	}))
	defer zot.Close()

	fw, err := NewZotForwarder(zot.URL, nil)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/v2/reg-A/app/manifests/v1", nil)
	req.Header.Set("Authorization", "Bearer identity-jwt-secret")
	req.Header.Set("Cookie", "session=abc")
	rec := httptest.NewRecorder()
	status := fw.Forward(rec, req)

	require.Equal(t, http.StatusOK, status)
	require.Empty(t, gotAuth, "caller Authorization must not be forwarded to zot")
	require.Empty(t, gotCookie, "caller Cookie must not be forwarded to zot")
}

// zot-forward fail-closed: zot недоступен → 502 (не паника, причина не течёт).
func TestDataplane_ZotForward_ZotDown_502(t *testing.T) {
	zot := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := zot.URL
	zot.Close() // сервер уже недоступен

	fw, err := NewZotForwarder(url, nil)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/v2/reg-A/app/manifests/v1", nil)
	rec := httptest.NewRecorder()
	status := fw.Forward(rec, req)
	require.Equal(t, http.StatusBadGateway, status)
	require.Equal(t, http.StatusBadGateway, rec.Code)
}

// end-to-end: valid token + Check allow + реальный ZotForwarder → pull стримится из
// zot-mock (полный путь parse→authz→forward).
func TestDataplane_EndToEnd_PullThroughRealForwarder(t *testing.T) {
	zot := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("manifest-json"))
	}))
	defer zot.Close()

	fw, err := NewZotForwarder(zot.URL, nil)
	require.NoError(t, err)

	az := &fakeAuthz{allow: map[string]bool{"v_get registry_repository:reg-A/app": true}}
	h := newTestHandler(&fakeVerifier{subject: "sva-ci"}, az, &fakeBackend{}, fw, &fakeRepoReg{})

	rec := doReq(h, http.MethodGet, "/v2/reg-A/app/manifests/v1", true)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "manifest-json", rec.Body.String())
}

// NewZotForwarder отвергает пустой/относительный endpoint (composition root fatal).
func TestDataplane_NewZotForwarder_BadEndpoint(t *testing.T) {
	_, err := NewZotForwarder("", nil)
	require.Error(t, err)
	_, err = NewZotForwarder("zot:5000", nil) // без scheme
	require.Error(t, err)
}

// stringReader — io.Reader из строки (без bytes-импорта в теле теста).
func stringReader(s string) *readerString { return &readerString{s: s} }

type readerString struct {
	s string
	i int
}

func (r *readerString) Read(p []byte) (int, error) {
	if r.i >= len(r.s) {
		return 0, io.EOF
	}
	n := copy(p, r.s[r.i:])
	r.i += n
	return n, nil
}
