// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package zot — adapter-клиент к zot (data/registry-API). Реализует порт
// registry.ZotClient: проекции Repository/Tag на request-path, удаление тегов,
// GC, инфра-статистика namespace. zot никогда не публично достижим — клиент
// ходит на internal-endpoint (localhost/cluster, mTLS от proxy-SA).
//
// Тела HTTP-вызовов (v2/OCI Distribution API, `_catalog`, `tags/list`,
// `manifests`, GC) наполняет rpc-implementer строгим TDD; здесь — скелет-адаптер
// с зафиксированными сигнатурами порта.
package zot

import (
	"context"
	"net/http"
	"time"

	registry "github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/api/registry"
	"github.com/PRO-Robotech/kacho-registry/internal/domain"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// Client — adapter к zot registry-API поверх HTTP.
type Client struct {
	http    *http.Client
	baseURL string
}

// New строит Client для zot-endpoint (baseURL, напр. https://zot.internal:5000).
// Пустой baseURL → клиент не сконфигурирован (методы отвечают Unavailable).
func New(baseURL string) *Client {
	return &Client{
		http:    &http.Client{Timeout: 30 * time.Second},
		baseURL: baseURL,
	}
}

// ready — endpoint zot обязан быть подан (иначе Unavailable, fail-closed).
func (c *Client) ready() error {
	if c.baseURL == "" || c.http == nil {
		return regerrors.ErrUnavailable
	}
	return nil
}

// ListRepositories возвращает repos namespace (GET /v2/_catalog, per-repo filter).
// Реализует rpc-implementer.
func (c *Client) ListRepositories(ctx context.Context, q registry.RepoListQuery) ([]*domain.Repository, string, error) {
	if err := c.ready(); err != nil {
		return nil, "", err
	}
	return nil, "", regerrors.ErrUnimplemented
}

// ListTags возвращает теги repo (GET /v2/<repo>/tags/list). Реализует rpc-implementer.
func (c *Client) ListTags(ctx context.Context, q registry.TagListQuery) ([]*domain.Tag, string, error) {
	if err := c.ready(); err != nil {
		return nil, "", err
	}
	return nil, "", regerrors.ErrUnimplemented
}

// DeleteTag удаляет тег/манифест (DELETE /v2/<repo>/manifests/<digest>).
// Реализует rpc-implementer.
func (c *Client) DeleteTag(ctx context.Context, registryID, repository, tag string) error {
	if err := c.ready(); err != nil {
		return err
	}
	return regerrors.ErrUnimplemented
}

// NamespaceEmpty сообщает, пуст ли namespace реестра. Реализует rpc-implementer.
func (c *Client) NamespaceEmpty(ctx context.Context, registryID string) (bool, error) {
	if err := c.ready(); err != nil {
		return false, err
	}
	return false, regerrors.ErrUnimplemented
}

// RemoveNamespace снимает storage-namespace реестра в zot. Реализует rpc-implementer.
func (c *Client) RemoveNamespace(ctx context.Context, registryID string) error {
	if err := c.ready(); err != nil {
		return err
	}
	return regerrors.ErrUnimplemented
}

// TriggerGC запускает garbage collection namespace в zot. Реализует rpc-implementer.
func (c *Client) TriggerGC(ctx context.Context, registryID string) error {
	if err := c.ready(); err != nil {
		return err
	}
	return regerrors.ErrUnimplemented
}

// Stats возвращает инфра-статистику namespace. Реализует rpc-implementer.
func (c *Client) Stats(ctx context.Context, registryID string) (*domain.RegistryStats, error) {
	if err := c.ready(); err != nil {
		return nil, err
	}
	return nil, regerrors.ErrUnimplemented
}

var _ registry.ZotClient = (*Client)(nil)
