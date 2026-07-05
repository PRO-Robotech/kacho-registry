// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// blob_scope_cache_internal_test.go — BlobInRepo мемоизирует решение о принадлежности
// digest→repo коротким TTL-кэшем: на горячем docker-pull-пути повторный blob-GET того
// же слоя не пере-сканирует все теги repo (CWE-400 амплификация backend-нагрузки).
// Internal-тест (package zot) — ссылается на unexported blobCache/now.
package zot

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// countingManifestZot — httptest-zot, считающий ОБЩЕЕ число manifest-GET'ов (не пик
// параллелизма) — для проверки, что кэш реально гасит пере-скан.
type countingManifestZot struct {
	manifestFetches atomic.Int32
	tags            []string
	// hitDigest лежит в config манифеста hitTag (позитивный кейс); пусто → все absent.
	hitDigest string
	hitTag    string
}

func (z *countingManifestZot) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/tags/list"):
			_ = json.NewEncoder(w).Encode(map[string]any{"name": "reg-A/app", "tags": z.tags})
		case strings.Contains(path, "/manifests/"):
			z.manifestFetches.Add(1)
			ref := path[strings.Index(path, "/manifests/")+len("/manifests/"):]
			cfg := "sha256:cfg-" + ref
			if z.hitDigest != "" && ref == z.hitTag {
				cfg = z.hitDigest
			}
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
				"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "size": 1, "digest": cfg},
				"layers": []any{},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestBlobInRepo_MemoizesMembership — второй BlobInRepo для того же (repo,digest) не
// делает НИ ОДНОГО нового manifest-GET (решение взято из кэша). Позитивный digest.
func TestBlobInRepo_MemoizesMembership(t *testing.T) {
	z := &countingManifestZot{tags: []string{"v1"}, hitDigest: "sha256:hit", hitTag: "v1"}
	cli := New(z.server(t).URL)

	in, err := cli.BlobInRepo(context.Background(), "reg-A", "app", "sha256:hit")
	if err != nil || !in {
		t.Fatalf("first call: in=%v err=%v", in, err)
	}
	after1 := z.manifestFetches.Load()
	if after1 == 0 {
		t.Fatal("first call must hit zot manifests")
	}

	in2, err := cli.BlobInRepo(context.Background(), "reg-A", "app", "sha256:hit")
	if err != nil || !in2 {
		t.Fatalf("second call: in=%v err=%v", in2, err)
	}
	if got := z.manifestFetches.Load(); got != after1 {
		t.Fatalf("second call re-scanned manifests (fetches %d→%d); membership must be memoized", after1, got)
	}
}

// TestBlobInRepo_CacheExpiresAfterTTL — по истечении TTL кэш инвалидируется и повторный
// вызов пере-сканирует (кэш не «вечный» — свежий контент виден после окна).
func TestBlobInRepo_CacheExpiresAfterTTL(t *testing.T) {
	z := &countingManifestZot{tags: []string{"v1"}, hitDigest: "sha256:hit", hitTag: "v1"}
	cli := New(z.server(t).URL)

	clock := time.Now()
	cli.blobCache.now = func() time.Time { return clock }

	if _, err := cli.BlobInRepo(context.Background(), "reg-A", "app", "sha256:hit"); err != nil {
		t.Fatalf("first: %v", err)
	}
	after1 := z.manifestFetches.Load()

	// В пределах TTL — кэш-хит, без новых fetch'ей.
	if _, err := cli.BlobInRepo(context.Background(), "reg-A", "app", "sha256:hit"); err != nil {
		t.Fatalf("cached: %v", err)
	}
	if z.manifestFetches.Load() != after1 {
		t.Fatal("within TTL must be cache hit")
	}

	// TTL истёк → пере-скан.
	clock = clock.Add(blobCacheTTL + time.Second)
	if _, err := cli.BlobInRepo(context.Background(), "reg-A", "app", "sha256:hit"); err != nil {
		t.Fatalf("post-ttl: %v", err)
	}
	if z.manifestFetches.Load() <= after1 {
		t.Fatal("cache must expire after TTL and re-scan")
	}
}
