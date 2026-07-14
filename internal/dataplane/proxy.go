// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package dataplane

import (
	"bytes"
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
	// Rewrite (не deprecated Director): путь форвардится как есть (SetURL джойнит base-path
	// target'а с inbound-путём — у zot base пуст), inbound Host сохраняется (паритет с
	// прежним NewSingleHostReverseProxy). Вычищаем caller-identity credentials до форварда:
	// authz уже энфорснут per-request Check выше, zot'у bearer/cookie caller'а не нужны, а
	// осевшие в его access-логах они расширяли бы harvest-поверхность (реплей в пределах TTL
	// токена, CWE-522/200).
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Del("Cookie")
		},
	}
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

// ForwardCapture проксирует запрос в zot, но БУФЕРИЗУЕТ ответ (status+headers+body) в
// память вместо стриминга клиенту (см. Forwarder.ForwardCapture). Тело ЗАПРОСА при этом
// по-прежнему стримится в zot (ReverseProxy читает r.Body потоково), поэтому даже
// монолитный blob-PUT с полным слоем в теле не буферизуется — буферизуется лишь
// (пустой для blob-finalize) ответ zot. Использует тот же proxy (Rewrite/auth-strip/
// error-handler), что и Forward.
func (f *ZotForwarder) ForwardCapture(r *http.Request) CapturedResponse {
	rec := &bufferingRecorder{status: http.StatusOK}
	f.proxy.ServeHTTP(rec, r)
	return CapturedResponse{
		Status: rec.status,
		Header: rec.Header(),
		Body:   rec.body.Bytes(),
	}
}

// bufferingRecorder — http.ResponseWriter, накапливающий ответ zot в память
// (ForwardCapture). Реализует http.Flusher no-op'ом: httputil.ReverseProxy может
// вызвать Flush, но нам ничего стримить не нужно (буфер отдаётся целиком).
type bufferingRecorder struct {
	header  http.Header
	status  int
	body    bytes.Buffer
	written bool
}

func (b *bufferingRecorder) Header() http.Header {
	if b.header == nil {
		b.header = make(http.Header)
	}
	return b.header
}

func (b *bufferingRecorder) WriteHeader(code int) {
	if !b.written {
		b.status = code
		b.written = true
	}
}

func (b *bufferingRecorder) Write(p []byte) (int, error) {
	if !b.written {
		b.status = http.StatusOK
		b.written = true
	}
	return b.body.Write(p)
}

// Flush — no-op: буферизующий recorder ничего не стримит (совместимость с
// ReverseProxy, который может привести writer к http.Flusher).
func (b *bufferingRecorder) Flush() {}

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
