// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package authz

import "context"

// CheckClient — port-интерфейс (DIP). Реализация — клиентский adapter в
// сервисе (например `kacho-vpc/internal/clients/iam_authz_client.go`),
// который импортирует kacho-proto stubs и кальзывает
// `iamv1.InternalIAMServiceClient.Check(...)`.
//
// Decoupling: corelib НЕ зависит от kacho-proto stubs (см. comment в doc.go).
type CheckClient interface {
	// Check возвращает (allowed, err).
	//
	//   - subjectID: "user:usr_xxx" | "service_account:sva_xxx" | "group:grp_xxx#member"
	//   - relation:  "viewer" | "editor" | "admin" | "use" | ...
	//   - object:    "project:prj_xxx" | "vpc_network:enp_xxx" | ...
	//
	// Error semantics:
	//   - returned err = nil + allowed=true  → пропустить RPC
	//   - returned err = nil + allowed=false → DENY (PermissionDenied)
	//   - returned err != nil                → considered Unavailable
	//     → fail-closed PermissionDenied (если не выставлен break-glass)
	Check(ctx context.Context, subjectID, relation, object string) (allowed bool, err error)
}

// CheckClientFunc — adapter, который позволяет использовать функцию как CheckClient.
//
// Использование в тестах:
//
//	stub := authz.CheckClientFunc(func(ctx context.Context, s, r, o string) (bool, error) {
//	    return s == "user:usr_alice" && r == "viewer", nil
//	})
type CheckClientFunc func(ctx context.Context, subjectID, relation, object string) (bool, error)

// Check satisfies CheckClient.
func (f CheckClientFunc) Check(ctx context.Context, subjectID, relation, object string) (bool, error) {
	return f(ctx, subjectID, relation, object)
}

// CreatorTupleWriter — port-интерфейс для sync FGA-write own-creator
// tuple. Реализуется client'ом в kacho-vpc / kacho-compute / kacho-lb (одна
// реализация на сервис; обычно тот же gRPC client, что и CheckClient — две
// разные RPC на одном connection'е).
//
// Семантика:
//   - subjectID — "user:usr_creator" / "service_account:sva_creator"
//   - relation  — обычно "admin"
//   - object    — "vpc_network:enp_new" / "compute_instance:inst_new"
//
// Вызывается из Create handler'а ДО `tx.Commit()`. На err — Create handler
// должен `tx.Rollback()` и вернуть Unavailable клиенту.
type CreatorTupleWriter interface {
	WriteCreatorTuple(ctx context.Context, subjectID, relation, object string) error
}
