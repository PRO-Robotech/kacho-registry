// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	registry "github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/api/registry"
	"github.com/PRO-Robotech/kacho-registry/internal/domain"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// repository_config.go — Postgres-adapter (handwritten pgx) config-overlay Repository
// (таблица repository_configs, RG-1). Реализует CQRS-порты
// registry.RepositoryConfigReader/RepositoryConfigWriter. Все инварианты — DB-level
// (PRIMARY KEY(registry_id,name), visibility CHECK, single-statement re-key/visibility
// CAS, FK ON DELETE CASCADE); adapter лишь маппит SQLSTATE→sentinel (ban #10).

// configColumns — канонический порядок SELECT/RETURNING overlay-строки.
const configColumns = `registry_id, name, description, labels, visibility, created_at`

// RepositoryConfigRepo — реализация registry.RepositoryConfigRepo поверх pgxpool.
type RepositoryConfigRepo struct {
	pool *pgxpool.Pool
}

// NewRepositoryConfigRepo создаёт RepositoryConfigRepo поверх pgxpool.
func NewRepositoryConfigRepo(pool *pgxpool.Pool) *RepositoryConfigRepo {
	return &RepositoryConfigRepo{pool: pool}
}

// ready — pool обязан быть подан composition root'ом (иначе Unavailable, не паника).
func (r *RepositoryConfigRepo) ready() error {
	if r.pool == nil {
		return regerrors.ErrUnavailable
	}
	return nil
}

// GetConfig возвращает overlay-строку по натуральному ключу (registry_id, name).
// pgx.ErrNoRows → ErrNotFound "repository not found" (existence-hiding — в handler).
func (r *RepositoryConfigRepo) GetConfig(ctx context.Context, registryID, name string) (*domain.RepositoryConfig, error) {
	if err := r.ready(); err != nil {
		return nil, err
	}
	q := fmt.Sprintf(`SELECT %s FROM %s.repository_configs WHERE registry_id = $1 AND name = $2`,
		configColumns, schema)
	cfg, err := scanConfig(r.pool.QueryRow(ctx, q, registryID, name))
	if err != nil {
		return nil, mapConfigErr(err)
	}
	return cfg, nil
}

// ListConfigs возвращает overlay-строки реестра (created_at, name) ASC. Use-case
// объединяет их с projection (zot) в overlay ⊔ projection union (A20).
func (r *RepositoryConfigRepo) ListConfigs(ctx context.Context, registryID string) ([]*domain.RepositoryConfig, error) {
	if err := r.ready(); err != nil {
		return nil, err
	}
	q := fmt.Sprintf(`SELECT %s FROM %s.repository_configs WHERE registry_id = $1
		ORDER BY created_at ASC, name ASC`, configColumns, schema)
	rows, err := r.pool.Query(ctx, q, registryID)
	if err != nil {
		return nil, mapConfigErr(err)
	}
	defer rows.Close()

	var out []*domain.RepositoryConfig
	for rows.Next() {
		cfg, serr := scanConfig(rows)
		if serr != nil {
			return nil, mapConfigErr(serr)
		}
		out = append(out, cfg)
	}
	if rerr := rows.Err(); rerr != nil {
		return nil, mapConfigErr(rerr)
	}
	return out, nil
}

// InsertConfig вставляет overlay-строку (Create durable; adopt-additive поверх
// проекции — overlay ⟂ projection). PRIMARY KEY(registry_id,name)-конфликт → 23505 →
// ErrAlreadyExists ("repository already exists"). FK 23503 (реестр отсутствует) →
// ErrFailedPrecondition. Тот же INSERT-путь — ephemeral rename auto-promote (A23).
func (r *RepositoryConfigRepo) InsertConfig(ctx context.Context, cfg *domain.RepositoryConfig) (*domain.RepositoryConfig, error) {
	if err := r.ready(); err != nil {
		return nil, err
	}
	labels, err := marshalLabels(cfg.Labels)
	if err != nil {
		return nil, regerrors.ErrInternal
	}
	q := fmt.Sprintf(`
		INSERT INTO %s.repository_configs (registry_id, name, description, labels, visibility)
		VALUES ($1, $2, $3, $4::jsonb, $5)
		RETURNING %s`, schema, configColumns)
	created, err := scanConfig(r.pool.QueryRow(ctx, q,
		cfg.RegistryID, cfg.Name, cfg.Description, labels, cfg.Visibility.String()))
	if err != nil {
		return nil, mapConfigErr(err)
	}
	return created, nil
}

// UpdateConfig применяет mutable-поля (Apply*-флаги) одним UPDATE ... RETURNING.
// visibility-flip сериализуется row-lock'ом (детерминированный терминал, B09).
// 0 rows (строки нет) → ErrNotFound. Пустой набор Apply-флагов → возврат текущей
// строки (FOR UPDATE берёт тот же row-lock, что и SET-ветка).
func (r *RepositoryConfigRepo) UpdateConfig(ctx context.Context, spec registry.RepositoryConfigUpdate) (*domain.RepositoryConfig, error) {
	if err := r.ready(); err != nil {
		return nil, err
	}
	sets := []string{}
	args := []any{spec.RegistryID, spec.Name}
	idx := 3
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
	if spec.ApplyVisibility {
		sets = append(sets, fmt.Sprintf("visibility = $%d", idx))
		args = append(args, spec.Visibility.String())
		// visibility — последнее применяемое поле; idx дальше не читается (финальный
		// UPDATE строится из sets/args). Инкремент здесь был бы ineffectual.
	}

	var (
		updated *domain.RepositoryConfig
		err     error
	)
	if len(sets) == 0 {
		q := fmt.Sprintf(`SELECT %s FROM %s.repository_configs
			WHERE registry_id = $1 AND name = $2 FOR UPDATE`, configColumns, schema)
		updated, err = scanConfig(r.pool.QueryRow(ctx, q, spec.RegistryID, spec.Name))
	} else {
		q := fmt.Sprintf(`
			UPDATE %s.repository_configs SET %s
			WHERE registry_id = $1 AND name = $2
			RETURNING %s`, schema, strings.Join(sets, ", "), configColumns)
		updated, err = scanConfig(r.pool.QueryRow(ctx, q, args...))
	}
	if err != nil {
		return nil, mapConfigErr(err)
	}
	return updated, nil
}

// RekeyConfig — durable rename: одностейтментный перенос name-колонки существующей
// overlay-строки (UPDATE ... SET name=$3 WHERE registry_id=$1 AND name=$2 RETURNING).
// Занятое целевое имя → PRIMARY KEY 23505 → ErrAlreadyExists (A16/A17/A18); исходной
// строки нет → 0 rows → ErrNotFound. Ephemeral auto-promote (нет overlay-строки) —
// НЕ этот путь: он идёт через InsertConfig под new_name (D-5/A23).
func (r *RepositoryConfigRepo) RekeyConfig(ctx context.Context, registryID, oldName, newName string) (*domain.RepositoryConfig, error) {
	if err := r.ready(); err != nil {
		return nil, err
	}
	q := fmt.Sprintf(`
		UPDATE %s.repository_configs SET name = $3
		WHERE registry_id = $1 AND name = $2
		RETURNING %s`, schema, configColumns)
	renamed, err := scanConfig(r.pool.QueryRow(ctx, q, registryID, oldName, newName))
	if err != nil {
		return nil, mapConfigErr(err)
	}
	return renamed, nil
}

// DeleteConfig снимает overlay-строку (DELETE ... RETURNING name). 0 rows (строки
// нет / уже снята) → ErrNotFound — конкурентный/повторный Delete не даёт дубля.
func (r *RepositoryConfigRepo) DeleteConfig(ctx context.Context, registryID, name string) error {
	if err := r.ready(); err != nil {
		return err
	}
	var deleted string
	q := fmt.Sprintf(`DELETE FROM %s.repository_configs
		WHERE registry_id = $1 AND name = $2 RETURNING name`, schema)
	if err := r.pool.QueryRow(ctx, q, registryID, name).Scan(&deleted); err != nil {
		return mapConfigErr(err)
	}
	return nil
}

// ---- helpers ----

// scanConfig читает overlay-строку из pgx.Row/pgx.Rows в domain.RepositoryConfig.
func scanConfig(row pgx.Row) (*domain.RepositoryConfig, error) {
	var (
		cfg       domain.RepositoryConfig
		labelsRaw []byte
		visRaw    string
	)
	if err := row.Scan(&cfg.RegistryID, &cfg.Name, &cfg.Description, &labelsRaw, &visRaw, &cfg.CreatedAt); err != nil {
		return nil, err
	}
	labels, err := unmarshalLabels(labelsRaw)
	if err != nil {
		return nil, err
	}
	cfg.Labels = labels
	cfg.Visibility = domain.VisibilityFromString(visRaw)
	return &cfg, nil
}

// mapConfigErr транслирует pgx/SQLSTATE в sentinel kacho-registry с ТОЧНЫМ
// контракт-текстом overlay Repository (api-conventions.md error-format). Сырой pgx
// наружу не течёт (некатегоризированное → фикс. INTERNAL, security.md hardening #1).
//
//	pgx.ErrNoRows → ErrNotFound            "repository not found"
//	23505 PK/UNIQUE → ErrAlreadyExists     "repository already exists"
//	23503 FK        → ErrFailedPrecondition "registry not found"
//	23514 CHECK     → ErrInvalidArg        "invalid repository config"
//	иначе           → ErrInternal (+ внутренний лог SQLSTATE)
func mapConfigErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: repository not found", regerrors.ErrNotFound)
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505": // unique_violation — PRIMARY KEY(registry_id, name)
			return fmt.Errorf("%w: repository already exists", regerrors.ErrAlreadyExists)
		case "23503": // foreign_key_violation — registry_id → registries(id)
			return fmt.Errorf("%w: registry not found", regerrors.ErrFailedPrecondition)
		case "23514": // check_violation — visibility / labels-object
			return fmt.Errorf("%w: invalid repository config", regerrors.ErrInvalidArg)
		}
		slog.Default().Error("registry repo: unclassified repository_configs error",
			"sqlstate", pgErr.Code, "pg_message", pgErr.Message, "pg_detail", pgErr.Detail)
		return regerrors.ErrInternal
	}
	slog.Default().Error("registry repo: unclassified repository_configs error", "err", err.Error())
	return regerrors.ErrInternal
}

var _ registry.RepositoryConfigRepo = (*RepositoryConfigRepo)(nil)
