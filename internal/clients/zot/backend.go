// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package zot

// backend.go — data-plane Backend authz-интроспекция (не reverse-proxy):
// RepoExists (push-new vs push-existing verb-map), CatalogRepoNames (per-repo
// listauthz-фильтр _catalog) и BlobInRepo (per-repo blob-scope existence-hiding).
// Реализует часть порта dataplane.Backend; blob-scope мемоизируется в
// blob_scope_cache.go.

import (
	"context"
	"errors"
	"sort"
	"sync/atomic"

	"golang.org/x/sync/errgroup"

	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// RepoExists сообщает, зарегистрирован ли repo (несёт ≥1 тег) — data-plane
// verb-map push-new (v_create@namespace) vs push-existing (v_update@repo). zot
// недоступен → ErrUnavailable (fail-closed: не решаем new/existing вслепую).
func (c *Client) RepoExists(ctx context.Context, registryID, repo string) (bool, error) {
	if err := c.ready(); err != nil {
		return false, err
	}
	tags, err := c.repoTags(ctx, registryID+"/"+repo)
	if err != nil {
		return false, err
	}
	return len(tags) > 0, nil
}

// CatalogRepoNames возвращает полный zot-каталог (full-repo-имена всех namespace'ов)
// для per-repo listauthz-фильтрации _catalog в data-plane. zot недоступен →
// ErrUnavailable (fail-closed — не отдаём частичный каталог).
func (c *Client) CatalogRepoNames(ctx context.Context) ([]string, error) {
	if err := c.ready(); err != nil {
		return nil, err
	}
	var cat catalogResponse
	if err := c.getJSON(ctx, "/v2/_catalog", &cat); err != nil {
		return nil, err
	}
	out := append([]string(nil), cat.Repositories...)
	sort.Strings(out)
	return out, nil
}

// blobScopeConcurrency ограничивает число ПАРАЛЛЕЛЬНЫХ manifest-fetch'ей одного
// BlobInRepo/Stats-скана. Cap fan-out в zot: repo с тысячами тегов иначе на один
// blob-GET открыл бы тысячи одновременных backend-соединений (DoS-амплификация,
// CWE-400/770). ctx-дедлайн запроса пробрасывается в каждый fetch (gctx) — скан
// аборт'ится по дедлайну, не работая за его пределами.
const blobScopeConcurrency = 8

// manifestHasDigest — <digest> входит в config или layers манифеста.
func manifestHasDigest(mb manifestBody, digest string) bool {
	if mb.Config.Digest == digest {
		return true
	}
	for _, l := range mb.Layers {
		if l.Digest == digest {
			return true
		}
	}
	return false
}

// blobScopeVerdict сводит результат tag-скана к (in, err, cacheable):
//   - found → true, кэшируемо: positive-hit — единственный вердикт, достоверный из
//     ЧАСТИЧНОГО скана (приоритетнее транзиентного блипа соседа).
//   - соседний fetch блипнул (werr!=nil) → fail-closed werr, НЕ кэшируем.
//   - скан НЕПОЛНЫЙ (parent-ctx отменён до просмотра всех тегов, но ни один запущенный
//     fetch не вернул ошибки → werr==nil), блоб не найден → ответ ДЕЙСТВИТЕЛЬНО неизвестен
//     → fail-closed ErrUnavailable, НЕ кэшируем. Кэш ложного not-in-repo (blobCacheTTL)
//     иначе ловил бы легитимный pull присутствующего слоя в 404 на всё окно (cross-client).
//   - полный скан без совпадения → достоверный not-in-repo, кэшируемо.
func blobScopeVerdict(found bool, werr error, scannedAll bool) (in bool, err error, cacheable bool) {
	if found {
		return true, nil, true
	}
	if werr != nil {
		return false, werr, false
	}
	if !scannedAll {
		return false, regerrors.ErrUnavailable, false
	}
	return false, nil, true
}

// BlobInRepo проверяет per-repo blob-scope (REG-37): <digest> достижим только если
// входит в config/layers манифеста(ов) авторизованного repo. Cross-reference:
// перебирает теги repo (bounded-concurrency fan-out, cap blobScopeConcurrency),
// читает манифесты, ищет digest. Чужой content-addressable блоб (принадлежит
// манифесту другого repo) → false. Найден → перестаём планировать новые fetch'и
// (early-exit) и возвращаем true, даже если параллельный fetch соседнего тега блипнул
// ErrUnavailable (positive-hit приоритетнее — ответ известен). Решение мемоизируется
// коротким TTL-кэшем (blob_scope_cache.go) — повторный blob-GET того же слоя не
// пере-сканирует теги. Блоб НЕ найден и zot недоступен → ErrUnavailable (fail-closed:
// ответ действительно неизвестен).
func (c *Client) BlobInRepo(ctx context.Context, registryID, repo, digest string) (bool, error) {
	if err := c.ready(); err != nil {
		return false, err
	}
	// Мемоизация: повторный blob-GET того же слоя (горячий docker-pull) не
	// пере-сканирует все теги repo. Короткий TTL (blobCacheTTL) держит staleness в узде.
	key := blobCacheKey(registryID, repo, digest)
	if c.blobCache != nil {
		if in, ok := c.blobCache.get(key); ok {
			return in, nil
		}
	}
	fullRepo := registryID + "/" + repo
	tags, err := c.repoTags(ctx, fullRepo)
	if err != nil {
		return false, err
	}

	var found atomic.Bool
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(blobScopeConcurrency)
	// scannedAll различает полный скан от прерванного отменой parent-ctx: при break по
	// gctx.Err() оставшиеся теги НЕ просмотрены — вердикт «не найден» недостоверен.
	scannedAll := true
	for _, tag := range tags {
		if found.Load() {
			break // блоб найден — новые fetch'и не планируем (early-exit)
		}
		if gctx.Err() != nil {
			scannedAll = false // дедлайн/отмена — остаток тегов не просканирован
			break
		}
		tag := tag
		g.Go(func() error {
			if found.Load() {
				return nil
			}
			mb, merr := c.getManifest(gctx, fullRepo, tag)
			if merr != nil {
				if errors.Is(merr, errNotFound) {
					return nil // тег исчез между list и read — пропускаем
				}
				return merr
			}
			if manifestHasDigest(mb, digest) {
				found.Store(true)
			}
			return nil
		})
	}
	werr := g.Wait()
	// Positive-hit приоритетнее транзиентного сбоя соседа (ответ известен из частичного
	// скана); неполный скан без совпадения — fail-closed ErrUnavailable, НЕ кэшируется.
	in, err, cacheable := blobScopeVerdict(found.Load(), werr, scannedAll)
	if cacheable && c.blobCache != nil {
		c.blobCache.set(key, in)
	}
	return in, err
}
