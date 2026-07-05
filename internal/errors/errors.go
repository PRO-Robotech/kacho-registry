// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package errors — sentinel-ошибки kacho-registry + трансляция SQLSTATE→sentinel.
// Живет в leaf-пакете (без import-цикла pgx/grpc): repo/clients заворачивают
// сырые ошибки в эти sentinel'ы, а use-case/serviceerr маппят sentinel → gRPC.
package errors

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Sentinel-ошибки repo/clients-слоя. Сырой pgx/SQL-текст наружу не утекает
// (serviceerr маппит некатегоризированное в фиксированный gRPC INTERNAL).
var (
	// ErrNotFound — строки не существует (pgx.ErrNoRows).
	ErrNotFound = errors.New("not found")
	// ErrAlreadyExists — нарушение UNIQUE / PK (SQLSTATE 23505).
	ErrAlreadyExists = errors.New("already exists")
	// ErrFailedPrecondition — FK / конфликт состояния (23503) либо не-пустой namespace.
	ErrFailedPrecondition = errors.New("failed precondition")
	// ErrInvalidArg — нарушение CHECK (23514) либо невалидный вход.
	ErrInvalidArg = errors.New("invalid argument")
	// ErrUnavailable — peer (iam/zot) недоступен; мутации fail-closed.
	ErrUnavailable = errors.New("unavailable")
	// ErrInternal — некатегоризированная ошибка (без утечки сырого текста).
	ErrInternal = errors.New("internal database error")
)

// Wrap транслирует ошибку pgx/pgconn в sentinel kacho-registry, прикрепляя
// стабильное сообщение без утечек. Маппинг SQLSTATE:
//
//	pgx.ErrNoRows → ErrNotFound
//	23505 UNIQUE  → ErrAlreadyExists
//	23503 FK      → ErrFailedPrecondition
//	23514 CHECK   → ErrInvalidArg
//	все остальное → ErrInternal
//
// resource — человекочитаемый ярлык ("Registry"); id — id ресурса (может быть "").
func Wrap(err error, resource, id string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: %s %s not found", ErrNotFound, resource, id)
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505": // unique_violation
			return fmt.Errorf("%w: %s %s already exists", ErrAlreadyExists, resource, id)
		case "23503": // foreign_key_violation
			return fmt.Errorf("%w: %s %s violates a reference constraint", ErrFailedPrecondition, resource, id)
		case "23514": // check_violation
			return fmt.Errorf("%w: invalid %s", ErrInvalidArg, resource)
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
		return ErrInternal
	}
	// Non-pg неизвестная ошибка — тоже логируем сырой текст перед схлопом (не течёт наружу).
	slog.Default().Error("registry repo: unclassified error",
		"err", err.Error(), "resource", resource, "resource_id", id)
	return ErrInternal
}
