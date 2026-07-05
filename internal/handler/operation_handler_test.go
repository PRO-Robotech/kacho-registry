// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package handler

import (
	"context"
	"testing"

	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho-corelib/operations"
	operationpb "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/operation"
)

// fakeOwnedOpsRepo — минимальный operations.Repo, который ДОПОЛНИТЕЛЬНО реализует
// operations.OwnedOperationRepo с честным ownership-предикатом (match по паре
// principal_type/principal_id). Всё, что не относится к Get/Cancel-пути хендлера,
// оставлено panic-стабами: тест их не касается.
type fakeOwnedOpsRepo struct {
	op    *operations.Operation
	owner operations.Owner
}

func (f *fakeOwnedOpsRepo) ownsMatches(o operations.Owner) bool {
	return o.PrincipalType == f.owner.PrincipalType && o.PrincipalID == f.owner.PrincipalID
}

func (f *fakeOwnedOpsRepo) GetOwned(_ context.Context, id string, o operations.Owner) (*operations.Operation, error) {
	if f.op == nil || f.op.ID != id || !f.ownsMatches(o) {
		return nil, operations.ErrNotFound
	}
	return f.op, nil
}

func (f *fakeOwnedOpsRepo) CancelOwned(_ context.Context, id string, o operations.Owner) (*operations.Operation, error) {
	if f.op == nil || f.op.ID != id || !f.ownsMatches(o) {
		return nil, operations.ErrNotFound
	}
	if f.op.Done {
		return nil, operations.ErrAlreadyDone
	}
	f.op.Done = true
	return f.op, nil
}

// Unscoped Repo methods — не должны вызываться из Get/Cancel-пути хендлера.
func (f *fakeOwnedOpsRepo) Create(context.Context, operations.Operation) error { panic("unexpected") }
func (f *fakeOwnedOpsRepo) CreateWithPrincipal(context.Context, operations.Operation, operations.Principal) error {
	panic("unexpected")
}
func (f *fakeOwnedOpsRepo) Get(context.Context, string) (*operations.Operation, error) {
	panic("unscoped Get must not be used — ownership bypass")
}
func (f *fakeOwnedOpsRepo) List(context.Context, operations.ListFilter) ([]operations.Operation, string, error) {
	panic("unexpected")
}
func (f *fakeOwnedOpsRepo) MarkDone(context.Context, string, *anypb.Any) error { panic("unexpected") }
func (f *fakeOwnedOpsRepo) MarkError(context.Context, string, *rpcstatus.Status) error {
	panic("unexpected")
}
func (f *fakeOwnedOpsRepo) Cancel(context.Context, string) error {
	panic("unscoped Cancel must not be used — ownership bypass")
}

func ctxWith(principalID string) context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{
		Type: "user", ID: principalID, DisplayName: principalID,
	})
}

// TestOperationHandler_Get_OwnerScoped — владелец видит свою операцию, чужой
// principal получает NotFound (BOLA fix, no-leak).
func TestOperationHandler_Get_OwnerScoped(t *testing.T) {
	repo := &fakeOwnedOpsRepo{
		op:    &operations.Operation{ID: "op0000000000000000aa"},
		owner: operations.Owner{PrincipalType: "user", PrincipalID: "alice"},
	}
	h := NewOperationHandler(repo)

	got, err := h.Get(ctxWith("alice"), &operationpb.GetOperationRequest{OperationId: "op0000000000000000aa"})
	if err != nil {
		t.Fatalf("owner Get: unexpected err %v", err)
	}
	if got.GetId() != "op0000000000000000aa" {
		t.Fatalf("owner Get: got id %q", got.GetId())
	}

	_, err = h.Get(ctxWith("bob"), &operationpb.GetOperationRequest{OperationId: "op0000000000000000aa"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("stranger Get: want NotFound, got %v", err)
	}
}

// TestOperationHandler_Cancel_OwnerScoped — чужой principal не может отменить
// чужую операцию (NotFound); владелец отменяет успешно.
func TestOperationHandler_Cancel_OwnerScoped(t *testing.T) {
	repo := &fakeOwnedOpsRepo{
		op:    &operations.Operation{ID: "op0000000000000000bb"},
		owner: operations.Owner{PrincipalType: "user", PrincipalID: "alice"},
	}
	h := NewOperationHandler(repo)

	_, err := h.Cancel(ctxWith("bob"), &operationpb.CancelOperationRequest{OperationId: "op0000000000000000bb"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("stranger Cancel: want NotFound, got %v", err)
	}
	if repo.op.Done {
		t.Fatalf("stranger Cancel mutated op — ownership bypass")
	}

	got, err := h.Cancel(ctxWith("alice"), &operationpb.CancelOperationRequest{OperationId: "op0000000000000000bb"})
	if err != nil {
		t.Fatalf("owner Cancel: unexpected err %v", err)
	}
	if !got.GetDone() {
		t.Fatalf("owner Cancel: op not done")
	}
}
