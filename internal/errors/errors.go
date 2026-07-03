// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package errors — sentinel-ошибки kacho-registry + трансляция SQLSTATE→sentinel.
// Живет в leaf-пакете (без import-цикла pgx/grpc): repo/clients заворачивают
// сырые ошибки в эти sentinel'ы, а use-case/serviceerr маппят sentinel → gRPC.
package errors

import (
	"errors"
	"fmt"

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
	// ErrUnimplemented — метод-анкер скелета: реализация в rpc-implementer.
	// Скелет собирается и отдаёт клиенту codes.Unimplemented до наполнения логикой.
	ErrUnimplemented = errors.New("not implemented")
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
	}
	// Защитно: сырой pgx-текст наружу не отдаем — фиксированный sentinel.
	return ErrInternal
}
