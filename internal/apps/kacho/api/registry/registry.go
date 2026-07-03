// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package registry — use-case (бизнес-логика) реестра образов kacho-registry.
//
// Use-case слой чистой архитектуры: импортирует domain + порты + corelib
// operations; НЕ тянет pgx/grpc/transport. Здесь объявлены port-интерфейсы
// (RegistryReader/RegistryWriter — CQRS, ZotClient, IAMClient) — это АНКЕРЫ для
// rpc-implementer: сигнатуры зафиксированы, тела наполняются строгим TDD.
//
// Формы RPC (api-conventions.md): Get/List/ListRepositories/ListTags — sync;
// Create/Update/Delete/DeleteTag — async через operation.Operation. Мутации в
// скелете возвращают codes.Unimplemented (ErrUnimplemented) — LRO-оркестрация
// (id-gen, project-валидация через iam, worker с проброшенным principal,
// owner-tuple в registry_outbox) реализуется rpc-implementer'ом.
package registry

import (
	"context"

	"github.com/PRO-Robotech/kacho-corelib/operations"

	"github.com/PRO-Robotech/kacho-registry/internal/domain"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// ListQuery — вход для List реестров project'а (cursor-пагинация).
type ListQuery struct {
	ProjectID string
	PageSize  int64
	PageToken string
	Filter    string
}

// RepoListQuery — вход для ListRepositories namespace (cursor-пагинация).
type RepoListQuery struct {
	RegistryID string
	PageSize   int64
	PageToken  string
}

// TagListQuery — вход для ListTags конкретного repo (cursor-пагинация).
type TagListQuery struct {
	RegistryID string
	Repository string
	PageSize   int64
	PageToken  string
}

// CreateSpec — вход на создание Registry (тело CreateRegistryRequest, распарсенное
// тонким handler'ом в нейтральную форму).
type CreateSpec struct {
	ProjectID   string
	Name        string
	Description string
	Labels      map[string]string
}

// UpdateSpec — mutable-поля Update (name/project immutable — в spec не входят).
// Description/Labels — nil означает «поле не в update_mask» (partial PATCH).
type UpdateSpec struct {
	RegistryID  string
	Description *string
	Labels      map[string]string
	Mask        []string
}

// ---- Порты (АНКЕРЫ для rpc-implementer; CQRS-разделение read/write) ----------

// RegistryReader — read-порт таблицы registries. Реализуется
// internal/repo/kacho/pg.RegistryRepo; в unit-тестах подменяется mock.
type RegistryReader interface {
	// Get возвращает реестр по id (well-formed-но-нет → ErrNotFound).
	Get(ctx context.Context, id string) (*domain.Registry, error)
	// List возвращает реестры project'а (cursor-пагинация; listauthz-фильтр — в handler).
	List(ctx context.Context, q ListQuery) ([]*domain.Registry, string, error)
}

// RegistryWriter — write-порт таблицы registries. Мутации атомарны на DB-уровне
// (INSERT/UPDATE ... RETURNING, CAS-переход ACTIVE→DELETING) и пишут owner-tuple
// intent в registry_outbox в той же writer-tx. Никакого software check-then-act.
type RegistryWriter interface {
	// Insert создаёт реестр (partial UNIQUE(project_id,name) WHERE status<>'DELETING').
	Insert(ctx context.Context, r *domain.Registry) (*domain.Registry, error)
	// Update применяет mutable-поля (description/labels) одним UPDATE ... RETURNING.
	Update(ctx context.Context, spec UpdateSpec) (*domain.Registry, error)
	// MarkDeleting — атомарный CAS ACTIVE→DELETING (UPDATE ... WHERE status='ACTIVE'
	// RETURNING); 0 rows → ErrNotFound/idempotent. DELETING терминальный (forward-only).
	MarkDeleting(ctx context.Context, id string) (*domain.Registry, error)
	// Delete удаляет строку реестра (после снятия zot-namespace) + Unregister-intent.
	Delete(ctx context.Context, id string) error
}

// RegistryRepo — композитный CQRS-порт (read+write) для composition root.
type RegistryRepo interface {
	RegistryReader
	RegistryWriter
}

// ZotClient — порт к data/registry-API zot (source of truth образов). Проекции
// Repository/Tag читаются на request-path; удаление тегов/GC — через этот же порт.
type ZotClient interface {
	// ListRepositories возвращает repos namespace (проекция из zot).
	ListRepositories(ctx context.Context, q RepoListQuery) ([]*domain.Repository, string, error)
	// ListTags возвращает теги repo (проекция из zot).
	ListTags(ctx context.Context, q TagListQuery) ([]*domain.Tag, string, error)
	// DeleteTag удаляет тег/манифест repo в zot.
	DeleteTag(ctx context.Context, registryID, repository, tag string) error
	// NamespaceEmpty сообщает, пуст ли namespace (Delete непустого → FailedPrecondition).
	NamespaceEmpty(ctx context.Context, registryID string) (bool, error)
	// RemoveNamespace снимает storage-namespace реестра в zot (шаг async-Delete).
	RemoveNamespace(ctx context.Context, registryID string) error
	// TriggerGC запускает garbage collection namespace в zot.
	TriggerGC(ctx context.Context, registryID string) error
	// Stats возвращает инфра-статистику namespace (только для Internal-API).
	Stats(ctx context.Context, registryID string) (*domain.RegistryStats, error)
}

// IAMClient — порт к kacho-iam: cross-domain валидация project (ProjectService.Get)
// на Create + запись/снятие owner-tuple через fga-proxy (RegisterResource /
// UnregisterResource, Internal :9091, идемпотентно).
type IAMClient interface {
	// ProjectExists валидирует project-владельца на Create (не найдено →
	// ErrInvalidArg; iam недоступен → ErrUnavailable, мутация fail-closed).
	ProjectExists(ctx context.Context, projectID string) error
	// RegisterResource пишет owner/project owner-tuple созданного реестра.
	RegisterResource(ctx context.Context, registryID, projectID, subjectID string) error
	// UnregisterResource снимает owner-tuple удалённого реестра.
	UnregisterResource(ctx context.Context, registryID string) error
}

// UseCase — бизнес-логика Registry поверх портов (CQRS repo + zot + iam) и
// LRO-стека operations.
type UseCase struct {
	reader RegistryReader
	writer RegistryWriter
	zot    ZotClient
	iam    IAMClient
	ops    operations.Repo
}

// New собирает UseCase. reader/writer — одна pg-реализация (CQRS-разделение на
// уровне портов); ops — corelib LRO-репозиторий (async-мутации).
func New(reader RegistryReader, writer RegistryWriter, zot ZotClient, iam IAMClient, ops operations.Repo) *UseCase {
	return &UseCase{reader: reader, writer: writer, zot: zot, iam: iam, ops: ops}
}

// assertWired — defensive-гейт: composition root обязан подать все коллабораторы.
// Незаполненная зависимость → Unavailable (не паника в prod-path).
func (u *UseCase) assertWired() error {
	if u.reader == nil || u.writer == nil || u.zot == nil || u.iam == nil || u.ops == nil {
		return regerrors.ErrUnavailable
	}
	return nil
}

// Get возвращает Registry по id. Тонкий pass-through к read-порту.
func (u *UseCase) Get(ctx context.Context, id string) (*domain.Registry, error) {
	if err := u.assertWired(); err != nil {
		return nil, err
	}
	return u.reader.Get(ctx, id)
}

// List возвращает реестры project'а (listauthz-фильтр выполняет handler).
func (u *UseCase) List(ctx context.Context, q ListQuery) ([]*domain.Registry, string, error) {
	if err := u.assertWired(); err != nil {
		return nil, "", err
	}
	return u.reader.List(ctx, q)
}

// ListRepositories возвращает проекцию repos namespace из zot.
func (u *UseCase) ListRepositories(ctx context.Context, q RepoListQuery) ([]*domain.Repository, string, error) {
	if err := u.assertWired(); err != nil {
		return nil, "", err
	}
	return u.zot.ListRepositories(ctx, q)
}

// ListTags возвращает проекцию тегов repo из zot.
func (u *UseCase) ListTags(ctx context.Context, q TagListQuery) ([]*domain.Tag, string, error) {
	if err := u.assertWired(); err != nil {
		return nil, "", err
	}
	return u.zot.ListTags(ctx, q)
}

// Stats возвращает инфра-статистику namespace (Internal-API).
func (u *UseCase) Stats(ctx context.Context, registryID string) (*domain.RegistryStats, error) {
	if err := u.assertWired(); err != nil {
		return nil, err
	}
	return u.zot.Stats(ctx, registryID)
}

// Create — async создание реестра. Реализует rpc-implementer (id-gen prefix "reg",
// domain-валидация, ProjectExists через iam, LRO-worker с проброшенным principal,
// RegisterResource owner-tuple в registry_outbox).
func (u *UseCase) Create(ctx context.Context, spec CreateSpec) (*operations.Operation, error) {
	if err := u.assertWired(); err != nil {
		return nil, err
	}
	return nil, regerrors.ErrUnimplemented
}

// Update — async смена mutable-полей (labels/description). Реализует rpc-implementer.
func (u *UseCase) Update(ctx context.Context, spec UpdateSpec) (*operations.Operation, error) {
	if err := u.assertWired(); err != nil {
		return nil, err
	}
	return nil, regerrors.ErrUnimplemented
}

// Delete — async удаление реестра (CAS ACTIVE→DELETING, снятие zot-namespace,
// UnregisterResource). Реализует rpc-implementer.
func (u *UseCase) Delete(ctx context.Context, registryID string) (*operations.Operation, error) {
	if err := u.assertWired(); err != nil {
		return nil, err
	}
	return nil, regerrors.ErrUnimplemented
}

// DeleteTag — async удаление тега/манифеста в zot (единственный destructive-путь
// для образов; data-plane DELETE отвергается 405). Реализует rpc-implementer.
func (u *UseCase) DeleteTag(ctx context.Context, registryID, repository, tag string) (*operations.Operation, error) {
	if err := u.assertWired(); err != nil {
		return nil, err
	}
	return nil, regerrors.ErrUnimplemented
}

// TriggerGC — async garbage collection namespace в zot (Internal admin). Реализует rpc-implementer.
func (u *UseCase) TriggerGC(ctx context.Context, registryID string) (*operations.Operation, error) {
	if err := u.assertWired(); err != nil {
		return nil, err
	}
	return nil, regerrors.ErrUnimplemented
}
