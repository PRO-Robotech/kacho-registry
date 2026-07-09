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

// TestGqlQuery_DrainsBodyForKeepalive — на success-ветке (после decodeGraphQL под
// LimitReader) gqlQuery обязан дренировать остаток тела до io.EOF перед Close, иначе
// net/http не вернёт persistent-соединение в пул (json.Decoder останавливается на
// первом top-level object, не доходя до EOF), и на каждый ListRepositories/ListTags
// открывается свежий TCP+TLS handshake к zot на hot projection-пути (плюс per-repo
// fan-out). Наблюдаемое: N последовательных gqlQuery к одному хосту переиспользуют ОДНО
// соединение (StateNew==1). Паритет с do()/getManifest (httpclient.go). Хвост берётся
// заведомо больше внутреннего slurp-лимита net/http (~2 KiB), иначе Body.Close сам
// дотягивает хвост и разница между дренажом и его отсутствием не проявится.
func TestGqlQuery_DrainsBodyForKeepalive(t *testing.T) {
	var newConns int64
	trailing := strings.Repeat("\n", 256<<10) // 256 KiB хвоста после JSON-envelope
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"ImageList":{"Results":[{"Tag":"v1"}]}}}`))
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
		var out gqlImageListData
		require.NoError(t, c.gqlQuery(context.Background(), imageListQuery("acme/app"), &out))
		require.Len(t, out.ImageList.Results, 1)
	}

	require.Equal(t, int64(1), atomic.LoadInt64(&newConns),
		"gqlQuery must drain resp.Body to EOF so the persistent connection is reused (keepalive)")
}

// TestDecodeGraphQL_LimitReader — envelope search-ext GraphQL (ImageList/GlobalSearch)
// декодируется под io.LimitReader (defense-in-depth, CWE-770): ответ в пределах лимита
// разбирается штатно, а тело сверх лимита усекается LimitReader'ом → decode рвётся →
// fail-closed ErrUnavailable. Иначе tenant-controlled tag/repo-count материализуется в
// память целиком на каждый ListTags/ListRepositories (zot ImageList не поддерживает
// server-side tag-пагинацию); паритет с decodeManifest / maxManifestBytes. Сырой
// zot-текст наружу не течёт.
func TestDecodeGraphQL_LimitReader(t *testing.T) {
	// В пределах лимита — разбирается штатно.
	var out gqlImageListData
	require.NoError(t, decodeGraphQL(
		strings.NewReader(`{"data":{"ImageList":{"Results":[{"Tag":"v1"}]}}}`), 1<<20, &out))
	require.Len(t, out.ImageList.Results, 1)
	require.Equal(t, "v1", out.ImageList.Results[0].Tag)

	// Тело сверх лимита → LimitReader усекает → decode падает → failClosed ErrUnavailable.
	oversized := `{"data":{"ImageList":{"Results":[{"Tag":"` + strings.Repeat("a", 500) + `"}]}}}`
	var out2 gqlImageListData
	err := decodeGraphQL(strings.NewReader(oversized), 50, &out2)
	require.ErrorIs(t, err, regerrors.ErrUnavailable)
}

// TestDecodeGraphQL_ErrorsAndUnmarshal — errors-массив в envelope и оборачивание data
// сохраняют прежнюю семантику после экстракта из gqlQuery: непустой errors → fail-closed
// (наружу только sentinel), валидный data → unmarshal в out.
func TestDecodeGraphQL_ErrorsAndUnmarshal(t *testing.T) {
	var out gqlImageListData
	err := decodeGraphQL(
		strings.NewReader(`{"errors":[{"message":"cannot query field ImageList"}]}`), 1<<20, &out)
	require.ErrorIs(t, err, regerrors.ErrUnavailable)
}
