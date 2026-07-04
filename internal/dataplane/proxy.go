// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package dataplane

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// ZotForwarder — reverse-proxy запросов в zot после passed-authz. Путь передаётся
// как есть (/v2/<reg>/<repo>/... — zot хранит namespace по path-prefix); тело/range/
// заголовки стримятся (chunked upload). Ошибка zot → 502 (fail-closed, не паника).
type ZotForwarder struct {
	proxy  *httputil.ReverseProxy
	logger *slog.Logger
}

// NewZotForwarder строит ZotForwarder на internal-endpoint zot (напр.
// http://zot:5000). zot никогда не публично достижим — трафик уходит на
// cluster-internal endpoint. Пустой/битый endpoint → ошибка (composition root fatal).
func NewZotForwarder(zotEndpoint string, logger *slog.Logger) (*ZotForwarder, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if zotEndpoint == "" {
		return nil, fmt.Errorf("dataplane: zot endpoint is required")
	}
	target, err := url.Parse(zotEndpoint)
	if err != nil {
		return nil, fmt.Errorf("dataplane: parse zot endpoint: %w", err)
	}
	if target.Scheme == "" || target.Host == "" {
		return nil, fmt.Errorf("dataplane: zot endpoint must be an absolute URL (got %q)", zotEndpoint)
	}
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, e error) {
		// zot недоступен/сбой на forward — fail-closed 502, причина только в лог.
		logger.Warn("zot forward failed", "path", r.URL.Path, "err", e)
		writeError(w, http.StatusBadGateway, "UNAVAILABLE", "backend unavailable")
	}
	return &ZotForwarder{proxy: rp, logger: logger}, nil
}

// Forward проксирует запрос в zot и возвращает записанный клиенту HTTP-статус
// (register-on-first-push эмитится только на успешном manifest-PUT).
func (f *ZotForwarder) Forward(w http.ResponseWriter, r *http.Request) int {
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	f.proxy.ServeHTTP(rec, r)
	return rec.status
}

// statusRecorder перехватывает HTTP-статус, не мешая стримингу тела (Write —
// pass-through). WriteHeader фиксирует первый записанный код.
type statusRecorder struct {
	http.ResponseWriter
	status  int
	written bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.written {
		s.status = code
		s.written = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	// Тело без явного WriteHeader → неявный 200 (как у http.ResponseWriter).
	if !s.written {
		s.status = http.StatusOK
		s.written = true
	}
	return s.ResponseWriter.Write(b)
}

// Flush пробрасывает flush в нижележащий writer (стриминг blob-upload/pull).
func (s *statusRecorder) Flush() {
	if fl, ok := s.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}

var _ Forwarder = (*ZotForwarder)(nil)
