// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// stats_tags_concurrency_internal_test.go — Stats читает per-repo tags/list
// bounded-concurrency fan-out'ом (cap blobScopeConcurrency), а НЕ последовательно
// перед manifest-фазой: namespace с тысячами repo иначе выдал бы тысячи серийных
// round-trip'ов и упёрся бы в inbound-дедлайн Internal-RPC. Internal-тест (package
// zot) — ссылается на unexported blobScopeConcurrency.
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

// tagsConcZot — httptest-zot, считающий пик одновременных /tags/list-запросов.
// Структурный барьер (barrierN одновременных прибытий) детерминированно доказывает
// параллелизм tags-фазы: при серийном чтении (регрессия) barrierN никогда не
// набирается, запросы высвобождаются по barrierTimeout с пиком 1 → assert падает.
type tagsConcZot struct {
	repos []string // full-repo-имена (с namespace-префиксом), каждый несёт 1 тег

	cur     atomic.Int32
	maxSeen atomic.Int32

	barrierN       int
	barrierTimeout time.Duration
	bmu            sync.Mutex
	arrived        int
	release        chan struct{}
}

func (z *tagsConcZot) awaitBarrier() {
	if z.barrierN <= 0 {
		return
	}
	z.bmu.Lock()
	z.arrived++
	if z.arrived == z.barrierN {
		close(z.release)
	}
	z.bmu.Unlock()
	select {
	case <-z.release:
	case <-time.After(z.barrierTimeout):
	}
}

func (z *tagsConcZot) server(t *testing.T) *httptest.Server {
	t.Helper()
	if z.barrierN > 0 && z.release == nil {
		z.release = make(chan struct{})
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case path == "/v2/" || path == "/v2":
			w.WriteHeader(http.StatusOK)
		case path == "/v2/_catalog":
			_ = json.NewEncoder(w).Encode(map[string]any{"repositories": z.repos})
		case strings.HasSuffix(path, "/tags/list"):
			cur := z.cur.Add(1)
			for {
				old := z.maxSeen.Load()
				if cur <= old || z.maxSeen.CompareAndSwap(old, cur) {
					break
				}
			}
			z.awaitBarrier() // структурное окно перекрытия параллельных tags-fetch'ей
			z.cur.Add(-1)
			repo := strings.TrimSuffix(strings.TrimPrefix(path, "/v2/"), "/tags/list")
			_ = json.NewEncoder(w).Encode(map[string]any{"name": repo, "tags": []string{"v0"}})
		case strings.Contains(path, "/manifests/"):
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
				"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "size": 1, "digest": "sha256:cfg"},
				"layers": []any{},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestStats_TagsReadConcurrent — на namespace с несколькими repo Stats читает
// per-repo tags/list параллельно (пик ≥2, детерминированно через барьер), но в
// пределах cap blobScopeConcurrency. Серийная регрессия (tags-serial-then-manifests)
// высвобождает запросы по barrierTimeout с пиком 1 → assert `< 2` падает штатно.
func TestStats_TagsReadConcurrent(t *testing.T) {
	repos := make([]string, 4)
	for i := range repos {
		repos[i] = fmt.Sprintf("reg-A/app%02d", i)
	}
	z := &tagsConcZot{repos: repos, barrierN: 2, barrierTimeout: 500 * time.Millisecond}
	cli := New(z.server(t).URL)

	stats, err := cli.Stats(context.Background(), "reg-A")
	if err != nil {
		t.Fatalf("Stats err: %v", err)
	}
	if stats.RepositoryCount != int32(len(repos)) {
		t.Fatalf("RepositoryCount = %d, want %d", stats.RepositoryCount, len(repos))
	}
	if stats.TagCount != int32(len(repos)) {
		t.Fatalf("TagCount = %d, want %d", stats.TagCount, len(repos))
	}
	if got := z.maxSeen.Load(); got > int32(blobScopeConcurrency) {
		t.Fatalf("tags fan-out concurrency %d exceeds cap %d", got, blobScopeConcurrency)
	}
	if got := z.maxSeen.Load(); got < 2 {
		t.Fatalf("expected bounded parallel tags reads (>1), got %d", got)
	}
}
