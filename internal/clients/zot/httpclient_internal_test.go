// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package zot

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// TestDecodeManifest_LimitReader — тело манифеста декодируется под io.LimitReader
// (defense-in-depth, CWE-770): манифест в пределах лимита разбирается штатно, а
// одиночное JSON-значение сверх лимита усекается LimitReader'ом → decode рвётся →
// fail-closed ErrUnavailable (скомпрометированный/битый zot не OOM'ит декодер
// безразмерным телом; сырой zot-текст наружу не течёт).
func TestDecodeManifest_LimitReader(t *testing.T) {
	// В пределах лимита — разбирается штатно (config.size/digest проецируются).
	mb, err := decodeManifest(strings.NewReader(`{"config":{"digest":"sha256:x","size":7}}`), 1<<20)
	require.NoError(t, err)
	require.Equal(t, int64(7), mb.Config.Size)
	require.Equal(t, "sha256:x", mb.Config.Digest)

	// Одиночное JSON-значение (гигантский digest-string) сверх лимита → LimitReader
	// усекает → json.Decode падает (unexpected EOF) → failClosed ErrUnavailable.
	oversized := `{"config":{"digest":"` + strings.Repeat("a", 500) + `"}}`
	_, err = decodeManifest(strings.NewReader(oversized), 50)
	require.ErrorIs(t, err, regerrors.ErrUnavailable)
}

// TestDo_DrainsBodyForKeepalive — на success-decode-ветке do() обязан дренировать
// resp.Body до io.EOF перед Close, иначе net/http не вернёт persistent-соединение в
// пул (json.Decoder останавливается на первом значении, не доходя до EOF), и на каждый
// introspection-вызов открывается свежий TCP-handshake к zot на hot data-plane
// pull-authz пути. Наблюдаемое: несколько последовательных getJSON к одному хосту
// переиспользуют ОДНО соединение (StateNew==1), а не открывают N. Тело берётся
// заведомо больше внутреннего slurp-лимита net/http (~2 KiB), при котором Body.Close
// сам дотягивает хвост, — иначе разница между дренажом и его отсутствием не проявится.
func TestDo_DrainsBodyForKeepalive(t *testing.T) {
	var newConns int64
	// json.Decoder читает ровно одно значение и останавливается на закрывающей `}`,
	// НЕ доходя до io.EOF — хвостовой padding (сверх slurp-лимита net/http ~2 KiB)
	// остаётся непрочитанным. Без явного дренажа net/http бросает соединение.
	trailing := strings.Repeat("\n", 256<<10) // 256 KiB хвоста после JSON-значения
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"a":"b"}`))
		_, _ = io.WriteString(w, trailing)
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			atomic.AddInt64(&newConns, 1)
		}
	}
	srv.Start()
	defer srv.Close()

	c := &Client{
		http:    &http.Client{Transport: &http.Transport{}},
		baseURL: srv.URL,
	}

	for i := 0; i < 3; i++ {
		var out map[string]string
		require.NoError(t, c.getJSON(context.Background(), "/probe", &out))
		require.Equal(t, "b", out["a"])
	}

	require.Equal(t, int64(1), atomic.LoadInt64(&newConns),
		"do() must drain resp.Body to EOF so the persistent connection is reused (keepalive)")
}

// TestGetManifest_DrainsBodyForKeepalive — getManifest на success-ветке (после
// decodeManifest под LimitReader) обязан дренировать остаток тела, иначе
// manifest-fan-out (Stats/BlobInRepo сканируют тысячи манифестов) открывает свежий
// TCP-handshake к zot на каждый манифест. Наблюдаемое: N последовательных getManifest
// переиспользуют ОДНО соединение (StateNew==1).
func TestGetManifest_DrainsBodyForKeepalive(t *testing.T) {
	var newConns int64
	trailing := strings.Repeat("\n", 256<<10) // хвост сверх slurp-лимита net/http
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"config":{"digest":"sha256:c","size":3}}`))
		_, _ = io.WriteString(w, trailing)
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			atomic.AddInt64(&newConns, 1)
		}
	}
	srv.Start()
	defer srv.Close()

	c := &Client{
		http:    &http.Client{Transport: &http.Transport{}},
		baseURL: srv.URL,
	}

	for i := 0; i < 3; i++ {
		mb, err := c.getManifest(context.Background(), "acme/app", "latest")
		require.NoError(t, err)
		require.Equal(t, "sha256:c", mb.Config.Digest)
	}

	require.Equal(t, int64(1), atomic.LoadInt64(&newConns),
		"getManifest must drain resp.Body to EOF so the persistent connection is reused (keepalive)")
}
