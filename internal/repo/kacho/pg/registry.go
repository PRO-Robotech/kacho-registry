// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package pg — Postgres-adapter (handwritten pgx) для таблицы registries
// kacho-registry. Реализует CQRS-порты registry.RegistryReader/RegistryWriter.
//
// Мутации атомарны на DB-уровне (INSERT/UPDATE ... RETURNING, CAS-переход
// ACTIVE→DELETING через UPDATE ... WHERE, DELETE ... RETURNING) и пишут owner-tuple
// register/unregister intent в registry_outbox в ТОЙ ЖЕ writer-tx — transactional
// outbox, без software check-then-act и без dual-write.
package pg

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho-corelib/filter"

	registry "github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/api/registry"
	"github.com/PRO-Robotech/kacho-registry/internal/domain"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// schema — квалификатор таблиц kacho-registry (не полагаемся на search_path).
const schema = "kacho_registry"

// registryColumns — канонический порядок SELECT/RETURNING строки реестра.
const registryColumns = `id, project_id, name, description, labels, status, created_at`

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

// Get возвращает реестр по id. pgx.ErrNoRows → ErrNotFound через errors.Wrap.
func (r *RegistryRepo) Get(ctx context.Context, id string) (*domain.Registry, error) {
	if err := r.ready(); err != nil {
		return nil, err
	}
	q := fmt.Sprintf(`SELECT %s FROM %s.registries WHERE id = $1`, registryColumns, schema)
	reg, err := scanRegistry(r.pool.QueryRow(ctx, q, id))
	if err != nil {
		return nil, regerrors.Wrap(err, "Registry", id)
	}
	return reg, nil
}

// RegistryProjectID — узкий lookup owning-project реестра по id (data-plane
// register-on-first-push: интент репо должен нести ParentProjectID для containment
// scope в iam-mirror). pgx.ErrNoRows → ErrNotFound через errors.Wrap.
func (r *RegistryRepo) RegistryProjectID(ctx context.Context, id string) (string, error) {
	if err := r.ready(); err != nil {
		return "", err
	}
	var projectID string
	q := fmt.Sprintf(`SELECT project_id FROM %s.registries WHERE id = $1`, schema)
	if err := r.pool.QueryRow(ctx, q, id).Scan(&projectID); err != nil {
		return "", regerrors.Wrap(err, "Registry", id)
	}
	return projectID, nil
}

// List возвращает реестры project'а cursor-пагинацией (created_at,id) ASC.
// filter — whitelist `name=` (corelib filter.Parse; garbage → InvalidArgument);
// garbage page_token → InvalidArgument. Запрашивает pageSize+1 для next-cursor.
func (r *RegistryRepo) List(ctx context.Context, q registry.ListQuery) ([]*domain.Registry, string, error) {
	if err := r.ready(); err != nil {
		return nil, "", err
	}

	conds := []string{}
	args := []any{}
	idx := 1
	if q.ProjectID != "" {
		conds = append(conds, fmt.Sprintf("project_id = $%d", idx))
		args = append(args, q.ProjectID)
		idx++
	}

	ast, err := filter.Parse(q.Filter, []string{"name"})
	if err != nil {
		return nil, "", invalidFilterErr(err)
	}
	if ast != nil {
		conds = append(conds, fmt.Sprintf("name = $%d", idx))
		args = append(args, ast.Value)
		idx++
	}

	if q.PageToken != "" {
		cur, derr := decodePageToken(q.PageToken)
		if derr != nil {
			return nil, "", invalidPageTokenErr(derr)
		}
		conds = append(conds, fmt.Sprintf("(created_at, id) > ($%d, $%d)", idx, idx+1))
		args = append(args, cur.CreatedAt, cur.ID)
		idx += 2
	}

	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}
	pageSize := q.PageSize
	if pageSize <= 0 {
		pageSize = 50
	}
	sql := fmt.Sprintf(
		`SELECT %s FROM %s.registries %s ORDER BY created_at ASC, id ASC LIMIT $%d`,
		registryColumns, schema, where, idx,
	)
	args = append(args, pageSize+1)

	rows, err := r.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, "", regerrors.Wrap(err, "Registry", "")
	}
	defer rows.Close()

	var out []*domain.Registry
	for rows.Next() {
		reg, serr := scanRegistry(rows)
		if serr != nil {
			return nil, "", regerrors.Wrap(serr, "Registry", "")
		}
		out = append(out, reg)
	}
	if rerr := rows.Err(); rerr != nil {
		return nil, "", regerrors.Wrap(rerr, "Registry", "")
	}

	var next string
	if int64(len(out)) > pageSize {
		last := out[pageSize-1]
		next = encodePageToken(last.CreatedAt, last.ID)
		out = out[:pageSize]
	}
	return out, next, nil
}

// Insert создаёт реестр + register-intent в registry_outbox ОДНОЙ writer-tx.
// partial UNIQUE(project_id,name)WHERE status<>'DELETING' → 23505 → ErrAlreadyExists.
func (r *RegistryRepo) Insert(ctx context.Context, reg *domain.Registry, intent domain.RegisterIntent) (*domain.Registry, error) {
	if err := r.ready(); err != nil {
		return nil, err
	}
	labels, err := marshalLabels(reg.Labels)
	if err != nil {
		return nil, regerrors.ErrInternal
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, regerrors.Wrap(err, "Registry", reg.ID)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	q := fmt.Sprintf(`
		INSERT INTO %s.registries (id, project_id, name, description, labels, status)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6)
		RETURNING %s`, schema, registryColumns)
	created, err := scanRegistry(tx.QueryRow(ctx, q,
		reg.ID, reg.ProjectID, reg.Name, reg.Description, labels, statusString(reg.Status)))
	if err != nil {
		return nil, regerrors.Wrap(err, "Registry", reg.ID)
	}

	if err := emitFGAIntent(ctx, tx, domain.FGAEventRegister, intent); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, regerrors.Wrap(err, "Registry", reg.ID)
	}
	return created, nil
}

// Update применяет mutable-поля по Apply*-флагам одним UPDATE ... RETURNING;
// mirror register-intent (обновлённые labels) строится callback'ом из RETURNING
// строки и эмитится в той же tx. 0 rows (нет ACTIVE-реестра) → ErrNotFound.
func (r *RegistryRepo) Update(ctx context.Context, spec registry.UpdateSpec, mirror func(*domain.Registry) domain.RegisterIntent) (*domain.Registry, error) {
	if err := r.ready(); err != nil {
		return nil, err
	}

	sets := []string{}
	args := []any{spec.RegistryID}
	idx := 2
	if spec.ApplyName {
		// Смена имени: partial-UNIQUE(project_id,name) WHERE status<>'DELETING' →
		// конфликт даёт 23505 → regerrors.Wrap → ErrAlreadyExists.
		sets = append(sets, fmt.Sprintf("name = $%d", idx))
		args = append(args, spec.Name)
		idx++
	}
	if spec.ApplyDescription {
		sets = append(sets, fmt.Sprintf("description = $%d", idx))
		args = append(args, spec.Description)
		idx++
	}
	if spec.ApplyLabels {
		labels, err := marshalLabels(spec.Labels)
		if err != nil {
			return nil, regerrors.ErrInternal
		}
		sets = append(sets, fmt.Sprintf("labels = $%d::jsonb", idx))
		args = append(args, labels)
		idx++
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, regerrors.Wrap(err, "Registry", spec.RegistryID)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var updated *domain.Registry
	if len(sets) == 0 {
		// Пустой набор применяемых полей (mask без mutable-полей) — возвращаем
		// текущую ACTIVE-строку; mirror по-прежнему re-register'ит labels.
		q := fmt.Sprintf(`SELECT %s FROM %s.registries WHERE id = $1 AND status = 'ACTIVE'`,
			registryColumns, schema)
		updated, err = scanRegistry(tx.QueryRow(ctx, q, spec.RegistryID))
	} else {
		q := fmt.Sprintf(`
			UPDATE %s.registries SET %s
			WHERE id = $1 AND status = 'ACTIVE'
			RETURNING %s`, schema, strings.Join(sets, ", "), registryColumns)
		updated, err = scanRegistry(tx.QueryRow(ctx, q, args...))
	}
	if err != nil {
		return nil, regerrors.Wrap(err, "Registry", spec.RegistryID)
	}

	if err := emitFGAIntent(ctx, tx, domain.FGAEventRegister, mirror(updated)); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, regerrors.Wrap(err, "Registry", spec.RegistryID)
	}
	return updated, nil
}

// MarkDeleting — атомарный forward-only CAS в DELETING: ACTIVE→DELETING (или
// идемпотентно DELETING→DELETING, чтобы retry/крэш-рекавери довели удаление до
// конца). 0 rows только когда строки нет (уже удалена) → ErrNotFound. revert в
// ACTIVE невозможен (нет пути DELETING→ACTIVE).
func (r *RegistryRepo) MarkDeleting(ctx context.Context, id string) (*domain.Registry, error) {
	if err := r.ready(); err != nil {
		return nil, err
	}
	q := fmt.Sprintf(`
		UPDATE %s.registries SET status = 'DELETING'
		WHERE id = $1 AND status IN ('ACTIVE', 'DELETING')
		RETURNING %s`, schema, registryColumns)
	reg, err := scanRegistry(r.pool.QueryRow(ctx, q, id))
	if err != nil {
		return nil, regerrors.Wrap(err, "Registry", id)
	}
	return reg, nil
}

// Delete физически удаляет строку реестра + unregister-intent в той же writer-tx.
// unregister-intent эмитится ТОЛЬКО когда строка реально удалена (DELETE RETURNING
// 1 row) — конкурентный/повторный Delete видит 0 rows → ErrNotFound без второго
// destructive unregister-дубля.
func (r *RegistryRepo) Delete(ctx context.Context, id string, intent domain.RegisterIntent) error {
	if err := r.ready(); err != nil {
		return err
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return regerrors.Wrap(err, "Registry", id)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var deletedID string
	q := fmt.Sprintf(`DELETE FROM %s.registries WHERE id = $1 RETURNING id`, schema)
	if err := tx.QueryRow(ctx, q, id).Scan(&deletedID); err != nil {
		return regerrors.Wrap(err, "Registry", id)
	}

	if err := emitFGAIntent(ctx, tx, domain.FGAEventUnregister, intent); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return regerrors.Wrap(err, "Registry", id)
	}
	return nil
}

// RegisterRepository эмитит register-intent (parent+owner tuple) нового repo в
// registry_outbox. У repo нет собственной ресурсной строки в БД (source of truth =
// zot) — outbox-строка durable сама по себе, поэтому пишется одиночной tx. Register-
// drainer применяет её через fga-proxy идемпотентно (повторный push того же repo даёт
// дубль-intent, iam дедуплицирует → AlreadyApplied).
func (r *RegistryRepo) RegisterRepository(ctx context.Context, intent domain.RegisterIntent) error {
	return r.emitRepoIntent(ctx, domain.FGAEventRegister, intent)
}

// UnregisterRepository эмитит unregister-intent repo (снятие parent-tuple) в
// registry_outbox — снятие висячего authz-объекта на удалении последнего тега.
func (r *RegistryRepo) UnregisterRepository(ctx context.Context, intent domain.RegisterIntent) error {
	return r.emitRepoIntent(ctx, domain.FGAEventUnregister, intent)
}

// emitRepoIntent — durable-emit repo-intent одиночной tx (у repo нет ресурсной DML,
// с которой надо было бы атомарить). Пустой набор tuple → no-op.
func (r *RegistryRepo) emitRepoIntent(ctx context.Context, eventType string, intent domain.RegisterIntent) error {
	if err := r.ready(); err != nil {
		return err
	}
	if len(intent.Tuples) == 0 {
		return nil
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return regerrors.Wrap(err, "registry_outbox", intent.ResourceID)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := emitFGAIntent(ctx, tx, eventType, intent); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return regerrors.Wrap(err, "registry_outbox", intent.ResourceID)
	}
	return nil
}

// ---- helpers ----

// scanRegistry читает строку реестра из pgx.Row/pgx.Rows в domain.Registry.
func scanRegistry(row pgx.Row) (*domain.Registry, error) {
	var (
		reg       domain.Registry
		labelsRaw []byte
		statusRaw string
	)
	if err := row.Scan(&reg.ID, &reg.ProjectID, &reg.Name, &reg.Description, &labelsRaw, &statusRaw, &reg.CreatedAt); err != nil {
		return nil, err
	}
	labels, err := unmarshalLabels(labelsRaw)
	if err != nil {
		return nil, err
	}
	reg.Labels = labels
	reg.Status = statusFromString(statusRaw)
	return &reg, nil
}

// emitFGAIntent пишет register/unregister intent в registry_outbox в текущей tx.
// source_version штампуется BEFORE INSERT триггером как BIGSERIAL id самой строки
// (миграция 0002) — commit-order-monotonic per-object маркер: воркер, закоммитивший
// позже, получил больший id (его INSERT выполнился позже под row-lock сериализацией),
// поэтому last-source-state-wins в iam-mirror корректен. Пустой набор tuple → no-op.
func emitFGAIntent(ctx context.Context, tx pgx.Tx, eventType string, intent domain.RegisterIntent) error {
	if len(intent.Tuples) == 0 {
		return nil
	}
	payload, err := intent.Marshal()
	if err != nil {
		return regerrors.ErrInternal
	}
	q := fmt.Sprintf(`
		INSERT INTO %s.registry_outbox (event_type, payload, resource_kind, resource_id)
		VALUES ($1, $2::jsonb, $3, $4)`, schema)
	if _, err := tx.Exec(ctx, q, eventType, string(payload), intent.Kind, intent.ResourceID); err != nil {
		return regerrors.Wrap(err, "registry_outbox", intent.ResourceID)
	}
	return nil
}

// marshalLabels сериализует карту labels в JSON-строку (jsonb-колонка через
// `$N::jsonb`). nil/пустая карта → "{}".
func marshalLabels(labels map[string]string) (string, error) {
	if len(labels) == 0 {
		return "{}", nil
	}
	b, err := json.Marshal(labels)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// unmarshalLabels разбирает jsonb-колонку labels в карту (пусто → nil).
func unmarshalLabels(raw []byte) (map[string]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if len(m) == 0 {
		return nil, nil
	}
	return m, nil
}

// statusString / statusFromString — маппинг domain-enum ↔ TEXT-колонка status.
func statusString(s domain.RegistryStatus) string {
	if s == domain.RegistryStatusDeleting {
		return "DELETING"
	}
	return "ACTIVE"
}

func statusFromString(s string) domain.RegistryStatus {
	if s == "DELETING" {
		return domain.RegistryStatusDeleting
	}
	return domain.RegistryStatusActive
}

// invalidFilterErr оборачивает ошибку парсинга filter в domain-sentinel
// ErrInvalidArg (repo НЕ формирует gRPC-статус — единый маппинг sentinel→gRPC в
// serviceerr; §CLAUDE.md dependency rule). serviceerr.ToStatus срежет префикс →
// клиент видит стабильное "invalid filter: <причина>" с кодом INVALID_ARGUMENT.
func invalidFilterErr(err error) error {
	return fmt.Errorf("%w: invalid filter: %v", regerrors.ErrInvalidArg, err)
}

var _ registry.RegistryRepo = (*RegistryRepo)(nil)
var _ registry.RepoRegistrar = (*RegistryRepo)(nil)
