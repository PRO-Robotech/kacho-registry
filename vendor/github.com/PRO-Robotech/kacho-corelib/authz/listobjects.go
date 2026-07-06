// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package authz — listobjects.go.
//
// Реализация FGA-filtered List filtering для backend-сервисов Kachō:
// вместо клиентского "fetch-all → filter-after" pattern (TOCTOU + leak в empty
// list) — единый ListAllowedIDs(p, objectType, relation) → set of allowed ids,
// который сервис подставляет в SQL `WHERE id = ANY($1::text[])`.
//
// # Архитектура
//
//	┌──────────────┐                          ┌──────────────────────────┐
//	│   handler    │ ─ ListAllowedIDs(p,t,r) ─►│  authz.ListObjectsService│
//	│  (List RPC)  │                          │  (per-service)           │
//	└──────────────┘                          │                          │
//	                                          │  1. cacheKey(p,t,r,m)    │
//	                                          │  2. cache.Get (≤0.5ms)   │
//	                                          │  3. miss → client call   │
//	                                          │  4. cache.Put (TTL=5s)   │
//	                                          │  5. return ids           │
//	                                          └──────────────────────────┘
//	                                                  │
//	                                                  ▼ ListObjects(subject,
//	                                                               resource_type,
//	                                                               action)
//	                                          ┌──────────────────────────┐
//	                                          │  kacho-iam :9090         │
//	                                          │  AuthorizeService        │
//	                                          │    .ListObjects          │
//	                                          └──────────────────────────┘
//	                                                  │
//	                                                  ▼
//	                                          ┌──────────────────────────┐
//	                                          │  OpenFGA (ListObjects)   │
//	                                          └──────────────────────────┘
//
// # Cache invalidation
//
//   - Cache TTL = 5s positive-only.
//   - Push-invalidation через тот же channel `kacho_iam_subjects` (re-uses
//     existing LISTEN-invalidator из listen_invalidate.go).
//   - Worst-case: TTL=5s + NOTIFY≤1s = ≤6s.
//
// # Fail modes
//
//   - kacho-iam unreachable → ErrUnavailable (fail-closed); если fresh entry
//     в кэше — оно возвращается (graceful degradation).
//   - Если KACHO_AUTHZ_LISTOBJECTS_FAIL_OPEN=true → caller инструктирован
//     fallback'нуть на unfiltered List (degraded mode; WARN-log + Critical-alert).
//   - Empty grant (len(ids)==0) → caller возвращает empty Response (HTTP 200),
//     НЕ PermissionDenied.
//
// # Decoupling от kacho-proto
//
// Пакет НЕ импортирует kacho-proto stubs (как и весь corelib/authz, см. doc.go).
// Определяет узкий port-интерфейс ListObjectsClient. Реализация —
// `<service>/internal/clients/iam_listobjects_client.go` поверх iamv1.AuthorizeServiceClient.
package authz

import (
	"context"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ListObjectsClient — port-интерфейс для kacho-iam AuthorizeService.ListObjects.
// Реализация — adapter в каждом сервисе (decoupling corelib от kacho-proto).
//
// Семантика:
//   - subjectID: FGA-style subject "user:usr_xxx" / "service_account:sva_xxx".
//   - resourceType: FGA object type, например "vpc_network".
//   - action: domain.resource.verb, например "vpc.networks.read".
//   - maxResults: hard cap (≤10000). 0 → server default.
//   - pageToken: для pagination больших списков.
//
// Возвращает: bare ids (без "<type>:" префикса), nextPageToken (empty == done).
// err != nil → fail-closed.
type ListObjectsClient interface {
	ListObjects(ctx context.Context, req ListObjectsRequest) (ListObjectsResponse, error)
}

// ListObjectsRequest — параметры одного ListObjects-вызова.
type ListObjectsRequest struct {
	Subject      string
	ResourceType string
	Action       string
	MaxResults   uint32
	PageToken    string
	// AuthzModelID — pinned authorization_model_id.
	// Empty → server default. Передается через ctx-metadata (см. impl).
	AuthzModelID string
}

// ListObjectsResponse — результат FGA ListObjects.
type ListObjectsResponse struct {
	ResourceIDs   []string
	NextPageToken string
	Truncated     bool
}

// ListObjectsClientFunc — adapter, позволяющий использовать функцию как ListObjectsClient
// (для тестов).
type ListObjectsClientFunc func(ctx context.Context, req ListObjectsRequest) (ListObjectsResponse, error)

// ListObjects satisfies ListObjectsClient.
func (f ListObjectsClientFunc) ListObjects(ctx context.Context, req ListObjectsRequest) (ListObjectsResponse, error) {
	return f(ctx, req)
}

// ListObjectsConfig — конфигурация ListObjectsService.
type ListObjectsConfig struct {
	// TTL — TTL положительных entry в кэше (default 5s).
	TTL time.Duration

	// MaxEntries — hard-cap на размер кэша (LRU eviction). Default 10000.
	MaxEntries int

	// MaxResults — default max_results, если caller не указал в opts.
	// Default 10000.
	MaxResults uint32

	// FollowupTimeout — таймаут одного RPC-вызова к ListObjectsClient
	// (default 500ms). Acceptance: per-RPC list latency budget ≤100ms p95
	// cache miss + roundtrip + FGA evaluation.
	FollowupTimeout time.Duration

	// AuthzModelID — pinned FGA authorization_model_id.
	// Передается на каждый Request.
	AuthzModelID string

	// ServiceName — для метрик/логов (например "kacho-vpc").
	ServiceName string
}

// ListObjectsService — оркестратор cache + client. Thread-safe.
type ListObjectsService struct {
	client ListObjectsClient
	cfg    ListObjectsConfig
	cache  *listObjectsCache
}

// NewListObjectsService собирает сервис из ListObjectsClient и config.
// client == nil → service все равно создается, но любой ListAllowedIDs вернет
// ErrUnavailable (fail-closed; используется, когда IAM endpoint не сконфигурирован).
func NewListObjectsService(client ListObjectsClient, cfg ListObjectsConfig) *ListObjectsService {
	if cfg.TTL <= 0 {
		cfg.TTL = 5 * time.Second
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 10000
	}
	if cfg.MaxResults == 0 {
		cfg.MaxResults = 10000
	}
	if cfg.FollowupTimeout <= 0 {
		cfg.FollowupTimeout = 500 * time.Millisecond
	}
	return &ListObjectsService{
		client: client,
		cfg:    cfg,
		cache:  newListObjectsCache(cfg.MaxEntries, cfg.TTL),
	}
}

// ListAllowedIDsOptions — per-call overrides.
type ListAllowedIDsOptions struct {
	// MaxResults — override-cap. 0 → используется cfg.MaxResults.
	MaxResults uint32

	// ScopeHint — опциональный scope для cache key separation (например project_id);
	// разные scopes → разные cache entries.
	ScopeHint string

	// AuthzModelID — override pinned model id. 0 → cfg.AuthzModelID.
	AuthzModelID string

	// SkipCache — если true, bypass cache (для post-write read-your-own-writes).
	SkipCache bool
}

// ListAllowedIDs — основной метод. Возвращает все ids ресурсов типа resourceType,
// на которые subject имеет relation action.
//
// Семантика:
//   - subjectID == "" → ErrUnavailable (нет анонимного listing'а с FGA; caller
//     обязан выставить principal).
//   - cache hit → возвращает cached (≤1ms p95).
//   - cache miss → client.ListObjects + cache.Put + return.
//   - client error → fail-closed: ErrUnavailable.
//   - len(ids) == 0 → возвращает ([], nil) — caller вернет empty response.
func (s *ListObjectsService) ListAllowedIDs(
	ctx context.Context,
	subjectID, resourceType, action string,
	opts ListAllowedIDsOptions,
) ([]string, error) {
	if s == nil || s.client == nil {
		return nil, ErrUnavailable
	}
	if subjectID == "" || resourceType == "" || action == "" {
		return nil, fmt.Errorf("authz.ListAllowedIDs: subject/resourceType/action required")
	}

	modelID := opts.AuthzModelID
	if modelID == "" {
		modelID = s.cfg.AuthzModelID
	}
	maxResults := opts.MaxResults
	if maxResults == 0 {
		maxResults = s.cfg.MaxResults
	}

	key := cacheKeyFor(subjectID, resourceType, action, opts.ScopeHint, modelID)
	if !opts.SkipCache {
		if ids, ok := s.cache.get(key); ok {
			return ids, nil
		}
	}

	// Cache miss: вызов client под FollowupTimeout.
	callCtx, cancel := context.WithTimeout(ctx, s.cfg.FollowupTimeout)
	defer cancel()

	allIDs := make([]string, 0, 64)
	pageToken := ""
	for {
		resp, err := s.client.ListObjects(callCtx, ListObjectsRequest{
			Subject:      subjectID,
			ResourceType: resourceType,
			Action:       action,
			MaxResults:   maxResults,
			PageToken:    pageToken,
			AuthzModelID: modelID,
		})
		if err != nil {
			// Разделяем PermissionDenied (легитимный denial → 403)
			// от Unavailable (infra недоступна → 503). До этого fix'а оба
			// сваливались в ErrUnavailable, и стенд возвращал UI 503 на cases
			// где FGA model просто не имела пути для subject (что должно быть
			// 403 — "у тебя нет прав", а не "сервис сломан").
			if status.Code(err) == codes.PermissionDenied {
				return nil, fmt.Errorf("%w: %v", ErrPermissionDenied, err)
			}
			// Fail-closed default: все остальное (timeout, connection-refused, …) → Unavailable.
			return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		allIDs = append(allIDs, resp.ResourceIDs...)
		if resp.NextPageToken == "" {
			break
		}
		if uint32(len(allIDs)) >= maxResults {
			break
		}
		pageToken = resp.NextPageToken
	}

	// Cache result (даже empty — empty grant нужно кешировать чтобы не звать
	// FGA на каждый poll). InvalidateBySubject выкинет это на revoke.
	s.cache.put(key, subjectID, allIDs)
	return allIDs, nil
}

// InvalidateBySubject — вызывается из LISTEN-invalidator при NOTIFY
// kacho_iam_subjects (re-uses пакет-level Cache мехнизма из listen_invalidate.go).
func (s *ListObjectsService) InvalidateBySubject(subjectID string) {
	if s == nil || s.cache == nil {
		return
	}
	s.cache.invalidateBySubject(subjectID)
}

// InvalidateAll — periodic / reconnect safety net.
func (s *ListObjectsService) InvalidateAll() {
	if s == nil || s.cache == nil {
		return
	}
	s.cache.invalidateAll()
}

// Size — (subjects, entries) для метрик.
func (s *ListObjectsService) Size() (subjects, entries int) {
	if s == nil || s.cache == nil {
		return 0, 0
	}
	return s.cache.size()
}

// cacheKeyFor собирает ключ в детерминированном формате:
//
//	"<subject>|<resource_type>|<action>|<scope>|<model_id>"
//
// Principal type/id ужé encoded в subject string FGA-style
// ("user:usr_alice"), поэтому отдельные поля не нужны.
func cacheKeyFor(subject, resourceType, action, scope, modelID string) string {
	return subject + "|" + resourceType + "|" + action + "|" + scope + "|" + modelID
}

// listObjectsCache — простой two-level cache:
//
//	subject_id → map[cacheKey]entry
//
// Двухуровневая структура дает O(1) invalidateBySubject (one delete on
// outer map).
//
// LRU eviction — вторичная функция (защита от memory leak); основной механизм
// — TTL.
type listObjectsCache struct {
	mu      sync.RWMutex
	maxSize int
	ttl     time.Duration
	now     func() time.Time

	// store: subject → set of entries
	store map[string]map[string]listObjectsEntry
}

type listObjectsEntry struct {
	ids       []string
	expiresAt time.Time
}

func newListObjectsCache(maxSize int, ttl time.Duration) *listObjectsCache {
	if maxSize <= 0 {
		maxSize = 10000
	}
	if ttl <= 0 {
		ttl = 5 * time.Second
	}
	return &listObjectsCache{
		maxSize: maxSize,
		ttl:     ttl,
		now:     time.Now,
		store:   make(map[string]map[string]listObjectsEntry, 64),
	}
}

// extractSubjectFromKey — first field в "subject|...".
func extractSubjectFromKey(key string) string {
	for i := 0; i < len(key); i++ {
		if key[i] == '|' {
			return key[:i]
		}
	}
	return key
}

func (c *listObjectsCache) get(key string) ([]string, bool) {
	c.mu.RLock()
	subject := extractSubjectFromKey(key)
	subMap, ok := c.store[subject]
	if !ok {
		c.mu.RUnlock()
		return nil, false
	}
	e, ok := subMap[key]
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if c.now().After(e.expiresAt) {
		c.mu.Lock()
		if subMap, ok := c.store[subject]; ok {
			delete(subMap, key)
			if len(subMap) == 0 {
				delete(c.store, subject)
			}
		}
		c.mu.Unlock()
		return nil, false
	}
	// Defensive copy — caller doesn't get internal slice.
	out := make([]string, len(e.ids))
	copy(out, e.ids)
	return out, true
}

func (c *listObjectsCache) put(key, subjectID string, ids []string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Defensive copy.
	stored := make([]string, len(ids))
	copy(stored, ids)

	subMap, ok := c.store[subjectID]
	if !ok {
		subMap = make(map[string]listObjectsEntry, 4)
		c.store[subjectID] = subMap
	}
	subMap[key] = listObjectsEntry{
		ids:       stored,
		expiresAt: c.now().Add(c.ttl),
	}

	// LRU-ish eviction — если total > maxSize, выбрасываем oldest entries
	// (linear scan — приемлемо до ~10k, что соответствует maxSize default).
	c.evictIfNeededLocked()
}

func (c *listObjectsCache) evictIfNeededLocked() {
	total := 0
	for _, sm := range c.store {
		total += len(sm)
	}
	if total <= c.maxSize {
		return
	}
	// Удаляем 10% oldest entries (batch eviction).
	toEvict := total - c.maxSize + c.maxSize/10
	type ref struct {
		subj string
		key  string
		exp  time.Time
	}
	var oldest []ref
	for subj, sm := range c.store {
		for k, e := range sm {
			oldest = append(oldest, ref{subj: subj, key: k, exp: e.expiresAt})
		}
	}
	// Сортировка по exp ascending — берем первые `toEvict`. Insertion-sort
	// для маленьких N приемлем.
	for i := 1; i < len(oldest); i++ {
		j := i
		for j > 0 && oldest[j-1].exp.After(oldest[j].exp) {
			oldest[j-1], oldest[j] = oldest[j], oldest[j-1]
			j--
		}
	}
	if toEvict > len(oldest) {
		toEvict = len(oldest)
	}
	for _, r := range oldest[:toEvict] {
		if sm, ok := c.store[r.subj]; ok {
			delete(sm, r.key)
			if len(sm) == 0 {
				delete(c.store, r.subj)
			}
		}
	}
}

func (c *listObjectsCache) invalidateBySubject(subjectID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.store, subjectID)
}

func (c *listObjectsCache) invalidateAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store = make(map[string]map[string]listObjectsEntry, 64)
}

func (c *listObjectsCache) size() (subjects, entries int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	subjects = len(c.store)
	for _, sm := range c.store {
		entries += len(sm)
	}
	return
}
