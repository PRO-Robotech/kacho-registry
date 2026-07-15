// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	"context"

	"github.com/PRO-Robotech/kacho-registry/internal/domain"
)

// repository_config.go — port-АНКЕРЫ config-overlay Repository (RG-1). CQRS-
// разделение read/write. Реализуется internal/repo/kacho/pg.RepositoryConfigRepo;
// в unit-тестах use-case подменяется mock. Все within-service инварианты overlay —
// на DB-уровне (PRIMARY KEY(registry_id,name), visibility CHECK, single-statement
// re-key/visibility CAS, FK ON DELETE CASCADE); adapter лишь маппит SQLSTATE→sentinel
// (data-integrity.md ban #10). Use-case-слой (Create/Get/Update/Delete/Rename
// Repository) потребляет эти порты — тела мутаций добавляются отдельным срезом.

// RepositoryConfigUpdate — вход partial-Update overlay-строки. Handler после
// mask-discipline (immutable-switch → UpdateMask с known-set {description,labels,
// visibility}) выставляет Apply*-флаги; adapter строит частичный single-statement
// UPDATE ... RETURNING по ним (visibility-flip сериализуется row-lock'ом — B09).
// Пустая карта Labels при ApplyLabels=true реально очищает метки (full-object PATCH).
type RepositoryConfigUpdate struct {
	RegistryID       string
	Name             string
	Description      string
	Labels           map[string]string
	Visibility       domain.Visibility
	ApplyDescription bool
	ApplyLabels      bool
	ApplyVisibility  bool
}

// OutboxIntent — пара «event-type + FGA-intent» для transactional-outbox эмиссии в
// той же writer-tx, что overlay-DML. Event — domain.FGAEventRegister /
// FGAEventUnregister (register/unregister owner/parent/public-grant tuple). Позволяет
// одному writer'у эмитить смешанный набор (напр. rename: unregister old + register new).
type OutboxIntent struct {
	Event  string
	Intent domain.RegisterIntent
}

// RepositoryConfigReader — read-порт overlay-таблицы repository_configs.
type RepositoryConfigReader interface {
	// GetConfig возвращает overlay-строку по натуральному ключу (registry_id, name).
	// Строки нет (ephemeral/absent) → ErrNotFound (existence-hiding — в handler).
	GetConfig(ctx context.Context, registryID, name string) (*domain.RepositoryConfig, error)
	// ListConfigs возвращает overlay-строки реестра (created_at, name) ASC. Use-case
	// объединяет их с projection (zot) в overlay ⊔ projection union (A20).
	ListConfigs(ctx context.Context, registryID string) ([]*domain.RepositoryConfig, error)
}

// RepositoryConfigWriter — write-порт overlay-таблицы. Мутации атомарны на DB-уровне
// (single-statement INSERT/UPDATE/DELETE ... RETURNING) — никакого software
// check-then-act (ban #10). Каждый writer оборачивает DML в tx с ACTIVE-guard
// (SELECT registries.status FOR UPDATE; DELETING → ErrFailedPrecondition "registry is
// being deleted", A24) и эмитит переданные FGA register/unregister intent'ы в
// registry_outbox В ТОЙ ЖЕ tx (transactional-outbox: adopt-owner/public-grant
// governance atomic с overlay-DML, at-least-once; iam-недоступность НЕ откатывает
// мутацию, X03). Пустой набор intent'ов → чистый DML под guard.
type RepositoryConfigWriter interface {
	// InsertConfig вставляет overlay-строку (Create durable; adopt-additive поверх
	// существующей проекции — overlay ⟂ projection). PK(registry_id,name)-конфликт →
	// 23505 → ErrAlreadyExists ("repository already exists"). Тот же INSERT-путь —
	// ephemeral rename auto-promote (D-5/A23: INSERT под new_name).
	InsertConfig(ctx context.Context, cfg *domain.RepositoryConfig, intents ...OutboxIntent) (*domain.RepositoryConfig, error)
	// UpdateConfig применяет mutable-поля (Apply*-флаги) одним UPDATE ... RETURNING;
	// visibility-flip сериализуется row-lock'ом (детерминированный терминал, B09).
	// 0 rows (строки нет) → ErrNotFound. intents (public-grant по итоговому visibility)
	// эмитятся в той же tx (governance конвергирует по commit-порядку, B09/X03).
	UpdateConfig(ctx context.Context, spec RepositoryConfigUpdate, intents ...OutboxIntent) (*domain.RepositoryConfig, error)
	// RekeyConfig — durable rename: одностейтментный перенос name-колонки
	// (UPDATE ... SET name=$new WHERE registry_id=$reg AND name=$old RETURNING).
	// Занятое целевое имя (overlay) → 23505 → ErrAlreadyExists (A16/A17/A18);
	// исходной строки нет → ErrNotFound. intents (re-register new / unregister old /
	// public-grant governance) — в той же tx.
	RekeyConfig(ctx context.Context, registryID, oldName, newName string, intents ...OutboxIntent) (*domain.RepositoryConfig, error)
	// DeleteConfig снимает overlay-строку (DELETE ... RETURNING). 0 rows → ErrNotFound.
	// intents (unregister repo-tuples + public-grant) — в той же tx.
	DeleteConfig(ctx context.Context, registryID, name string, intents ...OutboxIntent) error
}

// RepositoryConfigRepo — композитный CQRS-порт (read+write) для composition root.
type RepositoryConfigRepo interface {
	RepositoryConfigReader
	RepositoryConfigWriter
}
