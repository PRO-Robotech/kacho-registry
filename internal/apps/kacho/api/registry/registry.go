// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package registry — use-case (бизнес-логика) реестра образов kacho-registry.
//
// Use-case слой чистой архитектуры: импортирует domain + порты + corelib
// operations; НЕ тянет pgx/grpc/transport. Здесь объявлены port-интерфейсы
// (RegistryReader/RegistryWriter — CQRS, ZotClient, IAMClient) и общая часть
// UseCase; тела мутаций — в create.go / update.go / delete.go.
//
// Формы RPC (api-conventions.md): Get/List/ListRepositories/ListTags — sync;
// Create/Update/Delete/DeleteTag — async через operation.Operation. Read-часть
// (Get/List) — sync pass-through к репозиторию; мутации sync-валидируют вход и
// project-existence, затем LRO-worker (с проброшенным principal) финализирует.
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

// UpdateSpec — вход Update. project immutable (в spec не входит); name — mutable.
// Handler подаёт сырые Name/Description/Labels + Mask; use-case после mask-discipline
// выставляет ApplyName/ApplyDescription/ApplyLabels — по ним репозиторий строит
// частичный UPDATE (пустая карта Labels при ApplyLabels=true реально очищает метки).
type UpdateSpec struct {
	RegistryID       string
	Name             string
	Description      string
	Labels           map[string]string
	Mask             []string
	ApplyName        bool
	ApplyDescription bool
	ApplyLabels      bool
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
// intent в registry_outbox в ТОЙ ЖЕ writer-tx. Никакого software check-then-act.
type RegistryWriter interface {
	// Insert создаёт реестр + register-intent в registry_outbox одной tx. partial
	// UNIQUE(project_id,name) WHERE status<>'DELETING' → 23505 → ErrAlreadyExists.
	Insert(ctx context.Context, r *domain.Registry, intent domain.RegisterIntent) (*domain.Registry, error)
	// Update применяет mutable-поля (по Apply*-флагам) одним UPDATE ... RETURNING;
	// mirror register-intent строится callback'ом ИЗ обновлённой строки (нужны
	// её project_id + новые labels) и эмитится в ТОЙ ЖЕ tx (без Get/TOCTOU).
	Update(ctx context.Context, spec UpdateSpec, mirror func(*domain.Registry) domain.RegisterIntent) (*domain.Registry, error)
	// MarkDeleting — атомарный CAS ACTIVE→DELETING (UPDATE ... WHERE status='ACTIVE'
	// RETURNING); 0 rows → ErrNotFound (уже DELETING/удалён — идемпотентно).
	// DELETING терминальный (forward-only): revert в ACTIVE невозможен.
	MarkDeleting(ctx context.Context, id string) (*domain.Registry, error)
	// Delete удаляет строку реестра + unregister-intent в registry_outbox одной tx.
	Delete(ctx context.Context, id string, intent domain.RegisterIntent) error
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
// на Create. Owner-tuple lifecycle идёт НЕ отсюда, а через registry_outbox +
// register-drainer (fga-proxy) — чтобы атомарно с DML и at-least-once.
type IAMClient interface {
	// ProjectExists валидирует project-владельца на Create (не найдено →
	// ErrInvalidArg; iam недоступен → ErrUnavailable, мутация fail-closed).
	ProjectExists(ctx context.Context, projectID string) error
}

// RepoRegistrar — порт эмита owner/parent-tuple intent'ов репозитория в
// registry_outbox (тот же transactional-outbox, что CRUD реестра). Repo как
// authz-объект появляется на первом push (register) и снимается на удалении
// последнего тега (unregister) — оба через durable-intent, применяемый
// register-drainer'ом через fga-proxy идемпотентно. Реализуется pg.RegistryRepo.
type RepoRegistrar interface {
	// RegisterRepository эмитит register-intent (parent+owner tuple) нового repo.
	RegisterRepository(ctx context.Context, intent domain.RegisterIntent) error
	// UnregisterRepository эмитит unregister-intent repo (снятие parent-tuple).
	UnregisterRepository(ctx context.Context, intent domain.RegisterIntent) error
}

// UseCase — бизнес-логика Registry поверх портов (CQRS repo + zot + iam +
// repo-registrar) и LRO-стека operations.
type UseCase struct {
	reader       RegistryReader
	writer       RegistryWriter
	zot          ZotClient
	iam          IAMClient
	repoReg      RepoRegistrar
	ops          operations.Repo
	endpointBase string
}

// New собирает UseCase. reader/writer — одна pg-реализация (CQRS-разделение на
// уровне портов); repoReg эмитит repo-tuple intent'ы (register-on-first-push /
// unregister-on-last-tag); ops — corelib LRO-репозиторий; endpointBase —
// tenant-facing база для output-only Registry.endpoint ("<base>/<id>").
func New(reader RegistryReader, writer RegistryWriter, zot ZotClient, iam IAMClient, repoReg RepoRegistrar, ops operations.Repo, endpointBase string) *UseCase {
	if endpointBase == "" {
		endpointBase = "registry.kacho.local"
	}
	return &UseCase{reader: reader, writer: writer, zot: zot, iam: iam, repoReg: repoReg, ops: ops, endpointBase: endpointBase}
}

// EndpointFor возвращает tenant-facing OCI-endpoint реестра ("<base>/<id>").
// Output-only проекция; используется handler'ом (Get/List) и worker'ом (Create).
func (u *UseCase) EndpointFor(id string) string {
	if id == "" {
		return ""
	}
	return u.endpointBase + "/" + id
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
	if err := ValidateRegistryID(id); err != nil {
		return nil, err
	}
	r, err := u.reader.Get(ctx, id)
	if err != nil {
		return nil, mapRepoErr(err)
	}
	return r, nil
}

// List возвращает реестры project'а (listauthz-фильтр выполняет handler).
// Sync: валидирует page_size (0→default 50, max 1000; вне диапазона →
// InvalidArgument), затем cursor-запрос; garbage page_token → InvalidArgument.
func (u *UseCase) List(ctx context.Context, q ListQuery) ([]*domain.Registry, string, error) {
	if err := u.assertWired(); err != nil {
		return nil, "", err
	}
	size, err := validatePageSize(q.PageSize)
	if err != nil {
		return nil, "", err
	}
	q.PageSize = size
	items, next, err := u.reader.List(ctx, q)
	if err != nil {
		return nil, "", mapRepoErr(err)
	}
	return items, next, nil
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
	// malformed id → sync InvalidArgument первым стейтментом (parity с TriggerGC/Get);
	// без этого malformed id доходил бы до zot-бэкенда вместо fail-fast reject.
	if err := ValidateRegistryID(registryID); err != nil {
		return nil, err
	}
	return u.zot.Stats(ctx, registryID)
}
