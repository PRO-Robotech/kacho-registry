// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// errmap.go — pgx/SQLSTATE→sentinel трансляция. Живёт в repo-adapter (package pg),
// а НЕ в leaf-пакете internal/errors: перенос сюда убирает pgx/pgconn из
// dependency-графа use-case (internal/apps/kacho/api/registry импортит только
// голые sentinel'ы) — clean-arch dependency-rule (adapter не течёт в use-case).

// wrapPgErr транслирует ошибку pgx/pgconn в sentinel kacho-registry, прикрепляя
// стабильное сообщение без утечек. Маппинг SQLSTATE:
//
//	pgx.ErrNoRows → ErrNotFound
//	23505 UNIQUE  → ErrAlreadyExists
//	23503 FK      → ErrFailedPrecondition
//	23514 CHECK   → ErrInvalidArg
//	все остальное → ErrInternal
//
// resource — человекочитаемый ярлык ("Registry"); id — id ресурса (может быть "").
func wrapPgErr(err error, resource, id string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: %s %s not found", regerrors.ErrNotFound, resource, id)
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505": // unique_violation
			return fmt.Errorf("%w: %s %s already exists", regerrors.ErrAlreadyExists, resource, id)
		case "23503": // foreign_key_violation
			return fmt.Errorf("%w: %s %s violates a reference constraint", regerrors.ErrFailedPrecondition, resource, id)
		case "23514": // check_violation
			return fmt.Errorf("%w: invalid %s", regerrors.ErrInvalidArg, resource)
		}
		// Неклассифицированный SQLSTATE (42P01 undefined_table после goose-divergence,
		// 42703 undefined_column, 22P02 type-mismatch, …). Сырой pgx наружу НЕ отдаём
		// (фиксированный INTERNAL), но ВНУТРЕННИЙ лог обязан нести причину — иначе живой
		// сбой = «internal database error» без единой строки о SQLSTATE.
		slog.Default().Error("registry repo: unclassified database error",
			"sqlstate", pgErr.Code,
			"pg_message", pgErr.Message,
			"pg_detail", pgErr.Detail,
			"resource", resource,
			"resource_id", id)
		return regerrors.ErrInternal
	}
	// Non-pg неизвестная ошибка — тоже логируем сырой текст перед схлопом (не течёт наружу).
	slog.Default().Error("registry repo: unclassified error",
		"err", err.Error(), "resource", resource, "resource_id", id)
	return regerrors.ErrInternal
}
