// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package zot — adapter-клиент к zot (data/registry-API). Реализует порт
// registry.ZotClient: проекции Repository/Tag на request-path, удаление тегов,
// GC, инфра-статистику namespace. zot никогда не публично достижим — клиент
// ходит на internal-endpoint (localhost/cluster, mTLS от proxy-SA).
//
// Мультитенантность — через storage-path-prefix "<registryID>/<repo>": в zot репо
// именуется полным путём с namespace-префиксом. Проекции Repository/Tag — output-only
// зеркало zot (source of truth = zot); в БД kacho-registry НЕ хранятся. Все HTTP-сбои
// zot → ErrUnavailable (fail-closed: проекции не отдают stale-фикцию, Delete-
// precondition не «считает пустым»).
//
// Проекции Repository/Tag читаются через zot search-extension GraphQL
// (POST /v2/_zot/ext/search): GlobalSearch отдаёт per-repo агрегаты (размер, момент
// последнего push, download-count) одним запросом, ImageList — теги repo с размером,
// платформой, push/pull-таймстампами и типом артефакта. Distribution-API остаётся для
// удаления тегов, инфра-статистики (Stats), catalog-листинга и per-repo blob-scope.
//
// Файлы пакета (единый концерн на файл): zot_client.go — Client-ядро; graphql.go —
// search-ext проекции; distribution.go — Distribution-API (tag-delete/GC/stats);
// backend.go — data-plane Backend authz-интроспекция; httpclient.go — низкоуровневые
// HTTP-помощники; blob_scope_cache.go — TTL-мемоизация BlobInRepo.
package zot

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	registry "github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/api/registry"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// Client — adapter к zot registry-API поверх HTTP.
type Client struct {
	http      *http.Client
	baseURL   string
	blobCache *membershipCache // TTL-мемоизация BlobInRepo (digest→repo membership)
}

// New строит Client для zot-endpoint (baseURL, напр. https://zot.internal:5000).
// Пустой baseURL → клиент не сконфигурирован (методы отвечают Unavailable).
func New(baseURL string) *Client {
	return &Client{
		http:      &http.Client{Timeout: 30 * time.Second},
		baseURL:   strings.TrimRight(baseURL, "/"),
		blobCache: newMembershipCache(blobCacheTTL, blobCacheMaxEntries),
	}
}

// ready — endpoint zot обязан быть подан (иначе Unavailable, fail-closed).
func (c *Client) ready() error {
	if c.baseURL == "" || c.http == nil {
		return regerrors.ErrUnavailable
	}
	return nil
}

// failClosed логирует discarded root-cause fail-closed ветки zot-адаптера ПЕРЕД
// возвратом фиксированного ErrUnavailable (CWE-778: сырой zot-текст наружу не течёт,
// но оператор получает сигнал — иначе пустые Repository/Tag-проекции неотличимы от
// сетевого сбоя / GraphQL-разрыва). Логгер — slog.Default() (та же конвенция, что у
// iam-адаптера). Возвращает sentinel для прямого `return`.
func failClosed(op string, attrs ...any) error {
	slog.Default().Error("zot adapter fail-closed: "+op, attrs...)
	return regerrors.ErrUnavailable
}

var _ registry.ZotClient = (*Client)(nil)
