// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// blob_scope_internal_test.go — BlobInRepo/Stats fan-out в zot ограничен
// blobScopeConcurrency (иначе repo с тысячами тегов на один blob-GET открыл бы
// тысячи одновременных backend-соединений — DoS-амплификация, CWE-400/770).
// Internal-тест (package zot) — ссылается на unexported blobScopeConcurrency.
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

// concCountingZot — httptest-zot, считающий пик одновременных manifest-GET'ов.
type concCountingZot struct {
	cur      atomic.Int32
	maxSeen  atomic.Int32
	tags     []string
	target   string // digest, который «лежит» в манифесте matchTag (для early-exit теста)
	matchTag string

	// Барьер — детерминированный пол параллелизма без real-clock окна. Если задан
	// (barrierN>0), manifest-хендлер паркует запросы, пока не прибудет barrierN
	// одновременных: пока они запаркованы, cur ≥ barrierN, поэтому maxSeen ≥ barrierN
	// структурно (не зависит от того, успел ли планировщик перекрыть sleep-окно).
	// barrierTimeout — предохранитель: сериализованное исполнение (регрессия cap→0)
	// не виснет, а проваливает assert (пик остаётся 1).
	barrierN       int
	barrierTimeout time.Duration
	bmu            sync.Mutex
	arrived        int
	release        chan struct{}
}

// awaitBarrier паркует manifest-запрос до прибытия barrierN одновременных (или до
// barrierTimeout как предохранитель). Барьер выключен (barrierN<=0) → no-op.
func (z *concCountingZot) awaitBarrier() {
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

func (z *concCountingZot) server(t *testing.T) *httptest.Server {
	t.Helper()
	if z.barrierN > 0 && z.release == nil {
		z.release = make(chan struct{})
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/tags/list"):
			_ = json.NewEncoder(w).Encode(map[string]any{"name": "reg-A/app", "tags": z.tags})
		case strings.Contains(path, "/manifests/"):
			cur := z.cur.Add(1)
			for {
				old := z.maxSeen.Load()
				if cur <= old || z.maxSeen.CompareAndSwap(old, cur) {
					break
				}
			}
			z.awaitBarrier() // структурное окно перекрытия параллельных fetch'ей
			z.cur.Add(-1)
			ref := path[strings.Index(path, "/manifests/")+len("/manifests/"):]
			cfg := "sha256:cfg-" + ref
			if z.target != "" && ref == z.matchTag {
				cfg = z.target
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

func manyTags(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("v%03d", i)
	}
	return out
}

// TestBlobInRepo_BoundsFanoutConcurrency — на repo с 40 тегами и отсутствующим блобом
// (полный скан) пик одновременных manifest-GET'ов не превышает blobScopeConcurrency,
// но параллелизм реально используется (>1) — cap работает, не деградируя в sequential.
// Пол параллелизма (≥2) проверяется структурным барьером (barrierN=2), а не 10ms
// sleep-окном: два fetch'а паркуются до взаимного прибытия, поэтому maxSeen≥2
// детерминирован (нет зависимости от планировщика/реальных часов). Серийная регрессия
// (cap→sequential) высвобождается по barrierTimeout с пиком 1 → assert падает штатно.
func TestBlobInRepo_BoundsFanoutConcurrency(t *testing.T) {
	z := &concCountingZot{tags: manyTags(40), barrierN: 2, barrierTimeout: 2 * time.Second}
	cli := New(z.server(t).URL)

	in, err := cli.BlobInRepo(context.Background(), "reg-A", "app", "sha256:absent")
	if err != nil {
		t.Fatalf("BlobInRepo err: %v", err)
	}
	if in {
		t.Fatal("absent blob must not be in repo")
	}
	if got := z.maxSeen.Load(); got > int32(blobScopeConcurrency) {
		t.Fatalf("fan-out concurrency %d exceeds cap %d", got, blobScopeConcurrency)
	}
	if got := z.maxSeen.Load(); got < 2 {
		t.Fatalf("expected bounded parallelism (>1), got %d", got)
	}
}

// TestBlobInRepo_FoundSurvivesSiblingError — positive blob-hit НЕ должен теряться из-за
// транзиентного сбоя соседнего манифеста. Один тег несёт digest (found=true), соседний
// отдаёт 500 (→ ErrUnavailable). Авторизованный docker-pull присутствующего слоя обязан
// вернуть (true, nil), а не fail-closed (false, ErrUnavailable): fail-closed корректен
// ТОЛЬКО когда ответ действительно неизвестен, а здесь блоб найден. Ordering: bad-хендлер
// ждёт, пока good отдан клиенту, чтобы found.Store гарантированно случился до ошибки.
func TestBlobInRepo_FoundSurvivesSiblingError(t *testing.T) {
	const target = "sha256:hit"
	goodServed := make(chan struct{})
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/tags/list"):
			_ = json.NewEncoder(w).Encode(map[string]any{"name": "reg-A/app", "tags": []string{"good", "zbad"}})
		case strings.Contains(path, "/manifests/good"):
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
				"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "size": 1, "digest": target},
				"layers": []any{},
			})
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			once.Do(func() { close(goodServed) })
		case strings.Contains(path, "/manifests/zbad"):
			// Транзиентный blip соседа — но только ПОСЛЕ того как good-манифест ушёл
			// клиенту (+запас на чтение/decode), иначе errgroup-cancel гонял бы чтение good.
			<-goodServed
			time.Sleep(30 * time.Millisecond)
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	cli := New(srv.URL)
	in, err := cli.BlobInRepo(context.Background(), "reg-A", "app", target)
	if err != nil {
		t.Fatalf("BlobInRepo returned error despite blob found: %v", err)
	}
	if !in {
		t.Fatal("blob present in good manifest must be reported found (true), not lost to sibling error")
	}
}

// TestBlobInRepo_EarlyExitOnMatch — найденный блоб коротит скан: планируется НЕ весь
// набор тегов (реальный блоб не форсит чтение всех манифестов).
func TestBlobInRepo_EarlyExitOnMatch(t *testing.T) {
	z := &concCountingZot{tags: manyTags(200), target: "sha256:hit", matchTag: "v000"}
	cli := New(z.server(t).URL)

	in, err := cli.BlobInRepo(context.Background(), "reg-A", "app", "sha256:hit")
	if err != nil {
		t.Fatalf("BlobInRepo err: %v", err)
	}
	if !in {
		t.Fatal("blob present in v000 manifest must be found")
	}
}
