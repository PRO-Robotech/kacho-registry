// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package pg — Postgres-adapter (handwritten pgx) для таблицы registries
// kacho-registry. Реализует CQRS-порты registry.RegistryReader/RegistryWriter.
//
// Мутации обязаны быть атомарными на DB-уровне (INSERT/UPDATE ... RETURNING,
// CAS-переход ACTIVE→DELETING через UPDATE ... WHERE status='ACTIVE') и писать
// owner-tuple intent в registry_outbox в той же writer-tx — без software
// check-then-act. Тела SQL наполняет rpc-implementer строгим TDD; здесь —
// скелет-адаптер с зафиксированными сигнатурами портов.
package pg

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	registry "github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/api/registry"
	"github.com/PRO-Robotech/kacho-registry/internal/domain"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// outboxTable — таблица owner-tuple outbox для fga-proxy (конвенция
// <domain>_outbox; owner/project-tuple эмитятся атомарно в writer-tx мутации).
const outboxTable = "registry_outbox"

// RegistryRepo — реализация registry.RegistryRepo поверх pgxpool.
type RegistryRepo struct {
	pool *pgxpool.Pool
}

// NewRegistryRepo создаёт RegistryRepo поверх pgxpool.
func NewRegistryRepo(pool *pgxpool.Pool) *RegistryRepo { return &RegistryRepo{pool: pool} }

// ready — pool обязан быть подан composition root'ом (иначе Unavailable, не паника).
func (r *RegistryRepo) ready() error {
	if r.pool == nil {
		return regerrors.ErrUnavailable
	}
	return nil
}

// Get возвращает реестр по id. Реализует rpc-implementer (SELECT ... WHERE id=$1;
// pgx.ErrNoRows → ErrNotFound через errors.Wrap).
func (r *RegistryRepo) Get(ctx context.Context, id string) (*domain.Registry, error) {
	if err := r.ready(); err != nil {
		return nil, err
	}
	return nil, regerrors.ErrUnimplemented
}

// List возвращает реестры project'а с cursor-пагинацией (created_at,id) ASC.
// Реализует rpc-implementer.
func (r *RegistryRepo) List(ctx context.Context, q registry.ListQuery) ([]*domain.Registry, string, error) {
	if err := r.ready(); err != nil {
		return nil, "", err
	}
	return nil, "", regerrors.ErrUnimplemented
}

// Insert создаёт реестр + owner-tuple intent в registry_outbox (одна tx). partial
// UNIQUE(project_id,name) WHERE status<>'DELETING' → 23505 → ErrAlreadyExists.
// Реализует rpc-implementer.
func (r *RegistryRepo) Insert(ctx context.Context, reg *domain.Registry) (*domain.Registry, error) {
	if err := r.ready(); err != nil {
		return nil, err
	}
	return nil, regerrors.ErrUnimplemented
}

// Update применяет mutable-поля одним UPDATE ... RETURNING (без Get/TOCTOU).
// Реализует rpc-implementer.
func (r *RegistryRepo) Update(ctx context.Context, spec registry.UpdateSpec) (*domain.Registry, error) {
	if err := r.ready(); err != nil {
		return nil, err
	}
	return nil, regerrors.ErrUnimplemented
}

// MarkDeleting — атомарный CAS ACTIVE→DELETING (UPDATE ... WHERE status='ACTIVE'
// RETURNING); 0 rows → ErrNotFound/idempotent. Реализует rpc-implementer.
func (r *RegistryRepo) MarkDeleting(ctx context.Context, id string) (*domain.Registry, error) {
	if err := r.ready(); err != nil {
		return nil, err
	}
	return nil, regerrors.ErrUnimplemented
}

// Delete удаляет строку реестра + Unregister-intent в registry_outbox (одна tx).
// Реализует rpc-implementer.
func (r *RegistryRepo) Delete(ctx context.Context, id string) error {
	if err := r.ready(); err != nil {
		return err
	}
	return regerrors.ErrUnimplemented
}

var _ registry.RegistryRepo = (*RegistryRepo)(nil)
