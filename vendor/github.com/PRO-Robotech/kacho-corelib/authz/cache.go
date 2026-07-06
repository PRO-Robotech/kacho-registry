// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package authz

import (
	"sync"
	"time"
)

// Cache хранит positive Check-results c TTL = 5s.
//
// Семантика:
//   - Кешируются ТОЛЬКО `allowed=true` (positive results).
//   - Negative (deny) НЕ кешируются — иначе grant binding'а не проявится до
//     истечения TTL → расходится с UX «дал права — почему не работает?».
//   - На revoke binding'а → `pg_notify('kacho_iam_subjects', subject_id)` →
//     `Cache.InvalidateBySubject(subject_id)` (см. listen_invalidate.go).
//
// Thread-safe: используется из нескольких gRPC-handler goroutines одновременно.
type Cache struct {
	mu  sync.RWMutex
	ttl time.Duration

	// store: ключ = subjectID, значение = map[entryKey]entry.
	// Двухуровневый dict позволяет O(1) invalidateBySubject(subjectID) —
	// просто `delete(c.store, subjectID)`.
	store map[string]map[entryKey]entry

	// now — функция текущего времени, переопределяема в тестах.
	now func() time.Time
}

// entryKey — composite-ключ (relation, object_type, object_id).
// subjectID — внешний уровень map.
type entryKey struct {
	relation   string
	objectType string
	objectID   string
}

// entry — кешируемое значение.
type entry struct {
	allowed   bool      // всегда true (negative не кешируется); поле для future
	expiresAt time.Time // unix-time истечения
}

// NewCache создает кеш с указанным TTL. ttl ≤ 0 → defaults to 5*time.Second.
func NewCache(ttl time.Duration) *Cache {
	if ttl <= 0 {
		ttl = 5 * time.Second
	}
	return &Cache{
		ttl:   ttl,
		store: make(map[string]map[entryKey]entry, 64),
		now:   time.Now,
	}
}

// Get возвращает (true, true) если есть валидная positive-запись.
// Возвращает (false, false) в остальных случаях (miss / expired).
//
// На expiry — синхронно удаляет stale-entry (lazy eviction).
func (c *Cache) Get(subjectID, relation, objectType, objectID string) (allowed bool, ok bool) {
	c.mu.RLock()
	subMap, exists := c.store[subjectID]
	if !exists {
		c.mu.RUnlock()
		return false, false
	}
	e, exists := subMap[entryKey{relation, objectType, objectID}]
	c.mu.RUnlock()

	if !exists {
		return false, false
	}
	if c.now().After(e.expiresAt) {
		// Lazy delete.
		c.mu.Lock()
		if subMap, ok := c.store[subjectID]; ok {
			delete(subMap, entryKey{relation, objectType, objectID})
			if len(subMap) == 0 {
				delete(c.store, subjectID)
			}
		}
		c.mu.Unlock()
		return false, false
	}
	return e.allowed, true
}

// SetAllowed — кеширует positive result (TTL).
//
// Set negative — не делается; если allowed=false, вызывающий не должен
// звать SetAllowed.
func (c *Cache) SetAllowed(subjectID, relation, objectType, objectID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	subMap, exists := c.store[subjectID]
	if !exists {
		subMap = make(map[entryKey]entry, 8)
		c.store[subjectID] = subMap
	}
	subMap[entryKey{relation, objectType, objectID}] = entry{
		allowed:   true,
		expiresAt: c.now().Add(c.ttl),
	}
}

// InvalidateBySubject удаляет ВСЕ записи для subjectID.
//
// Вызывается:
//   - из listen_invalidate.go при NOTIFY `kacho_iam_subjects` (push-invalidate).
//   - может вызываться вручную (например в тесте).
//
// Idempotent.
func (c *Cache) InvalidateBySubject(subjectID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.store, subjectID)
}

// InvalidateAll удаляет весь кеш. Используется:
//   - в periodic full-cache-clear (см. KACHO_<SVC>_AUTHZ__FULL_CACHE_CLEAR_INTERVAL).
//   - в LISTEN-loop reconnect (conservative — иначе риск пропустить NOTIFY
//     во время disconnect).
func (c *Cache) InvalidateAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store = make(map[string]map[entryKey]entry, 64)
}

// Size возвращает (subjectsCount, entriesCount). Используется в метриках.
func (c *Cache) Size() (subjects int, entries int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	subjects = len(c.store)
	for _, sm := range c.store {
		entries += len(sm)
	}
	return
}

// SetNowFunc — для тестов: подмена time.Now.
func (c *Cache) SetNowFunc(now func() time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}
