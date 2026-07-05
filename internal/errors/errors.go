// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package errors — sentinel-ошибки kacho-registry. Чистый leaf-пакет БЕЗ
// pgx/grpc-зависимостей: repo/clients заворачивают сырые ошибки в эти sentinel'ы,
// а use-case/serviceerr маппят sentinel → gRPC. SQLSTATE→sentinel трансляция
// (pgx-специфичная) живёт в repo-adapter (internal/repo/kacho/pg/errmap.go) —
// чтобы pgx не протекал в dependency-граф use-case (clean-arch dependency-rule).
package errors

import "errors"

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
