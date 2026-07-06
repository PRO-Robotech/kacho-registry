// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package operations

import "context"

// Owner — ключ владельца операции для ownership-scoped доступа (Get/Cancel).
// Operative-ключ — пара (PrincipalType, PrincipalID) создателя операции
// (не project_id): видимость операции creator-principal-scoped. AccountID —
// дополнительный IAM-only ключ: gate ДОПОЛНИТЕЛЬНО матчит по account там, где
// колонка account_id NOT NULL; для сервисов без account-metadata (vpc/compute/
// nlb) AccountID == "" и эта ветка инертна.
type Owner struct {
	PrincipalType string
	PrincipalID   string
	AccountID     string
}

// OwnerFromPrincipal строит Owner из доверенного Principal (резолвится
// исключительно из ctx — operations.PrincipalFromContext). AccountID не
// заполняется (principal-ключ); IAM-сервис при необходимости выставляет его сам.
func OwnerFromPrincipal(p Principal) Owner {
	return Owner{PrincipalType: p.Type, PrincipalID: p.ID}
}

// OwnedOperationRepo — узкий ownership-scoped порт чтения/отмены операции.
// Ownership-предикат — внутри SQL WHERE / атомарного CAS (within-service
// инвариант на DB-уровне; software-side Get→check исключен). Чужой owner →
// ErrNotFound (no-leak, неотличимо от «нет такой»).
//
// Это ОТДЕЛЬНЫЙ от Repo интерфейс: новые методы не добавляются в общий
// operations.Repo, чтобы не ломать его mock-реализации в других сервисах
// (iam/compute/nlb/geo). Реализуется конкретным pgRepo; consumer получает его
// через AsOwned(repo).
type OwnedOperationRepo interface {
	// GetOwned возвращает операцию по id ТОЛЬКО если она принадлежит owner.
	// 0 строк (нет такой ИЛИ не владелец) → ErrNotFound.
	GetOwned(ctx context.Context, id string, owner Owner) (*Operation, error)
	// CancelOwned атомарно отменяет операцию owner'а (CAS WHERE done=false AND
	// ownership-предикат, RETURNING терминальное состояние без reload-Get).
	// Идемпотентно на уже-CANCELLED (→ OK с тем же Operation); на терминале
	// SUCCESS/ERROR → ErrAlreadyDone; чужая/нет → ErrNotFound.
	CancelOwned(ctx context.Context, id string, owner Owner) (*Operation, error)
}

// AsOwned проверяет, что Repo поддерживает ownership-scoped доступ, и возвращает
// узкий порт. Для pgRepo (NewRepo) — true. Composition root vpc-handler'а:
//
//	owned, ok := operations.AsOwned(opsRepo)
//	if !ok { /* fail-fast при wiring'е */ }
func AsOwned(r Repo) (OwnedOperationRepo, bool) {
	o, ok := r.(OwnedOperationRepo)
	return o, ok
}
