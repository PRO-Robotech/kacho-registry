// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package zot

import (
	"sync"
	"time"
)

// blobCacheTTL — TTL решения о принадлежности digest→repo. Короткий: membership
// (какие digest'ы входят в манифесты repo) меняется медленно, но кэш не должен
// «залипать» надолго (свежий/удалённый контент виден после окна). Гасит амплификацию
// пере-скана всех тегов repo на каждый blob-GET горячего docker-pull-пути (CWE-400).
const blobCacheTTL = time.Minute

// blobCacheMaxEntries — потолок записей кэша (защита от cache-fill: атакующий не
// раздувает память бесконечным потоком уникальных (repo,digest)). При переполнении
// эвиктятся протухшие, затем — произвольные записи.
const blobCacheMaxEntries = 8192

// membershipCache — потокобезопасный TTL-кэш решения BlobInRepo, ключ
// "<registryID>/<repo>|<digest>" → (in-repo, срок). Кэшируются и позитивные, и
// негативные вердикты: повторный pull легитимного слоя И повторный запрос чужого
// digest'а одинаково не пере-сканируют теги repo.
type membershipCache struct {
	mu      sync.Mutex
	entries map[string]membershipEntry
	ttl     time.Duration
	maxSize int
	now     func() time.Time
}

type membershipEntry struct {
	inRepo  bool
	expires time.Time
}

// newMembershipCache строит кэш с заданным TTL и потолком записей.
func newMembershipCache(ttl time.Duration, maxSize int) *membershipCache {
	return &membershipCache{
		entries: make(map[string]membershipEntry),
		ttl:     ttl,
		maxSize: maxSize,
		now:     time.Now,
	}
}

// get возвращает закэшированный вердикт, если запись есть и не протухла.
func (c *membershipCache) get(key string) (inRepo bool, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, present := c.entries[key]
	if !present {
		return false, false
	}
	if !c.now().Before(e.expires) {
		delete(c.entries, key) // протухла
		return false, false
	}
	return e.inRepo, true
}

// set сохраняет вердикт с TTL. При переполнении сначала сбрасывает протухшие записи,
// затем — произвольные (map-порядок), пока не освободит место.
func (c *membershipCache) set(key string, inRepo bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if len(c.entries) >= c.maxSize {
		for k, e := range c.entries {
			if !now.Before(e.expires) {
				delete(c.entries, k)
			}
		}
		for k := range c.entries {
			if len(c.entries) < c.maxSize {
				break
			}
			delete(c.entries, k)
		}
	}
	c.entries[key] = membershipEntry{inRepo: inRepo, expires: now.Add(c.ttl)}
}

// blobCacheKey строит ключ кэша принадлежности. Включает registryID+repo (одинаковый
// content-addressable digest в разных repo — разные ключи, без коллизии).
func blobCacheKey(registryID, repo, digest string) string {
	return registryID + "/" + repo + "|" + digest
}
