// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package migrations встраивает goose SQL-миграции kacho-registry (схема
// kacho_registry). Источник истины — эта директория. Применённую миграцию не
// редактируем — только новая (ban #5).
package migrations

import "embed"

// FS — встроенные миграции kacho-registry (формат goose).
//
//go:embed *.sql
var FS embed.FS
