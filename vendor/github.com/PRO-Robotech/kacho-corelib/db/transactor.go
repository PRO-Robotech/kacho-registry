// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package db

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Transactor оборачивает pgxpool и предоставляет транзакционный метод InTx.
type Transactor struct{ pool *pgxpool.Pool }

// NewTransactor создает новый Transactor поверх существующего пула.
func NewTransactor(p *pgxpool.Pool) *Transactor { return &Transactor{pool: p} }

// InTx запускает fn в транзакции. Если fn возвращает err — транзакция откатывается.
func (t *Transactor) InTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, t.pool, fn)
}
