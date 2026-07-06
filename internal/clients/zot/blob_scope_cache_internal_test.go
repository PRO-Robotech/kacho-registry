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
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

// TestMembershipCache_ConcurrentGetSet_RaceSafe — BlobInRepo сидит на горячем
// data-plane blob-pull-пути (serveBlob → BlobInRepo), обслуживаемом HTTP-сервером
// конкурентно. Мьютекс-защищённые get/set membershipCache обязаны выдерживать
// параллельные горутины под -race, включая eviction-петлю set() при переполнении
// (маленький maxSize форсирует её). Регресс coarse-mutex → finer-grained схемы
// (или sync.Map с check-then-act eviction-багом) ловится тут паникой map
// concurrent-write под -race — раньше он проходил бы, т.к. существующие тесты
// звали BlobInRepo строго последовательно.
func TestMembershipCache_ConcurrentGetSet_RaceSafe(t *testing.T) {
	const (
		goroutines = 32
		iterations = 400
		maxSize    = 64 // маленький потолок → set() гоняет eviction под гонкой
	)
	c := newMembershipCache(time.Minute, maxSize)
	const hot = "reg-A/app|sha256:hot" // все горутины бьют в один ключ (contested)

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				// hot key — всегда true; никакой конкурентный set не переворачивает его.
				c.set(hot, true)
				if in, ok := c.get(hot); ok && !in {
					t.Errorf("hot key verdict flipped to false under contention")
				}
				// distinct keys — раздувают map до потолка, гоняя eviction-ветку set().
				key := blobCacheKey("reg-A", "app", fmt.Sprintf("sha256:%d-%d", g, i))
				c.set(key, i%2 == 0)
				c.get(key)
			}
		}(g)
	}
	wg.Wait()

	// Потолок соблюдён даже под конкурентными set с eviction (все горутины
	// завершены — прямой доступ к entries безопасен).
	if got := len(c.entries); got > maxSize {
		t.Fatalf("cache exceeded maxSize under contention: %d > %d", got, maxSize)
	}
}

// TestBlobInRepo_ConcurrentSameKey_RaceSafe — реальный горячий путь: N параллельных
// BlobInRepo для одного (repo,digest) (как одновременные docker-pull одного слоя)
// не паникуют и дают когерентный вердикт под -race. Кэш get/set гоняется через
// backend.go, а не напрямую.
func TestBlobInRepo_ConcurrentSameKey_RaceSafe(t *testing.T) {
	z := &countingManifestZot{tags: []string{"v1"}, hitDigest: "sha256:hit", hitTag: "v1"}
	cli := New(z.server(t).URL)

	const goroutines = 24
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			in, err := cli.BlobInRepo(context.Background(), "reg-A", "app", "sha256:hit")
			if err != nil {
				t.Errorf("BlobInRepo: %v", err)
				return
			}
			if !in {
				t.Errorf("want in-repo verdict true for hit digest, got false")
			}
		}()
	}
	wg.Wait()
}
