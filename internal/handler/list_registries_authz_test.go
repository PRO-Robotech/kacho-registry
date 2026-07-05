// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package handler — unit-тесты handler-level listauthz для RegistryService.List
// (ScopeFiltered collection): interceptor пропускает per-RPC Check (single-object
// Check на пустом collection-id → «empty object id» → 403), авторизация — row-filter
// В ХЕНДЛЕРЕ по registry_registry v_list. non-member → 200+empty, member → свои,
// iam-error → UNAVAILABLE (fail-closed), breakglass → все. REG-06.
package handler

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	registry "github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/api/registry"
	"github.com/PRO-Robotech/kacho-registry/internal/domain"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
	registryv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/registry/v1"
)

// listReader — фейк RegistryReader, возвращающий заранее заданный набор реестров
// (сервер-side курсор эмулируется полем next).
type listReader struct {
	regs []*domain.Registry
	next string
}

func (r listReader) Get(context.Context, string) (*domain.Registry, error) {
	return nil, regerrors.ErrNotFound
}
func (r listReader) List(context.Context, registry.ListQuery) ([]*domain.Registry, string, error) {
	return r.regs, r.next, nil
}

func newListHandler(reader registry.RegistryReader, az Authorizer) *RegistryHandler {
	uc := registry.New(reader, stubRepo{}, &fakeZotH{}, stubIAM{}, stubRepo{}, newMemOpsH(), "registry.kacho.local")
	return NewRegistryHandler(uc, az)
}

const (
	regA = "regA0000000000000000A"
	regB = "regB0000000000000000B"
)

// REG-06 — List row-filter: subject с v_list на registry_registry:regA но НЕ regB →
// ответ содержит ТОЛЬКО regA (namespace-viewer НЕ видит чужие реестры).
func TestHandler_REG06_List_RowFiltered(t *testing.T) {
	reader := listReader{regs: []*domain.Registry{
		{ID: regA, ProjectID: "prj-P", Name: "team-a", Status: domain.RegistryStatusActive},
		{ID: regB, ProjectID: "prj-P", Name: "team-b", Status: domain.RegistryStatusActive},
	}}
	az := &recordingAuthorizer{allow: map[string]bool{
		registryObjectRef(regA): true, // v_list на regA, regB — нет
	}}
	h := newListHandler(reader, az)

	resp, err := h.List(carolCtx(), &registryv1.ListRegistriesRequest{ProjectId: "prj-P"})
	require.NoError(t, err)
	require.Len(t, resp.GetRegistries(), 1)
	require.Equal(t, regA, resp.GetRegistries()[0].GetId())
}

// REG-06 — non-member (нет v_list ни на один реестр) → 200 + пустой список (НЕ 403,
// exempt-parity: List не гейтится per-object Check).
func TestHandler_REG06_List_NonMember_EmptyNot403(t *testing.T) {
	reader := listReader{regs: []*domain.Registry{
		{ID: regA, ProjectID: "prj-P", Name: "team-a", Status: domain.RegistryStatusActive},
	}}
	az := &recordingAuthorizer{allow: map[string]bool{}} // ничего не разрешено
	h := newListHandler(reader, az)

	resp, err := h.List(carolCtx(), &registryv1.ListRegistriesRequest{ProjectId: "prj-P"})
	require.NoError(t, err, "non-member List → 200, не 403")
	require.Empty(t, resp.GetRegistries())
}

// REG-06 — iam.Check недоступен → fail-closed UNAVAILABLE (НЕ отдаём
// нефильтрованный список).
func TestHandler_REG06_List_IAMError_Unavailable(t *testing.T) {
	reader := listReader{regs: []*domain.Registry{
		{ID: regA, ProjectID: "prj-P", Name: "team-a", Status: domain.RegistryStatusActive},
	}}
	az := &recordingAuthorizer{err: regerrors.ErrUnavailable}
	h := newListHandler(reader, az)

	_, err := h.List(carolCtx(), &registryv1.ListRegistriesRequest{ProjectId: "prj-P"})
	require.Equal(t, codes.Unavailable, codeOf(t, err))
}

// REG-06 — breakglass (nil Authorizer) → row-filter пропускается, все реестры видны.
func TestHandler_REG06_List_Breakglass_All(t *testing.T) {
	reader := listReader{regs: []*domain.Registry{
		{ID: regA, ProjectID: "prj-P", Name: "team-a", Status: domain.RegistryStatusActive},
		{ID: regB, ProjectID: "prj-P", Name: "team-b", Status: domain.RegistryStatusActive},
	}}
	h := newListHandler(reader, nil)

	resp, err := h.List(carolCtx(), &registryv1.ListRegistriesRequest{ProjectId: "prj-P"})
	require.NoError(t, err)
	require.Len(t, resp.GetRegistries(), 2)
}

// REG-06 — next-page-token сохраняется после row-filter (курсор сервера не теряется,
// клиент продолжает пагинацию даже если страница «схлопнулась» фильтром).
func TestHandler_REG06_List_PreservesNextToken(t *testing.T) {
	reader := listReader{
		regs: []*domain.Registry{{ID: regA, ProjectID: "prj-P", Name: "team-a", Status: domain.RegistryStatusActive}},
		next: "cursor-token",
	}
	az := &recordingAuthorizer{allow: map[string]bool{registryObjectRef(regA): true}}
	h := newListHandler(reader, az)

	resp, err := h.List(carolCtx(), &registryv1.ListRegistriesRequest{ProjectId: "prj-P"})
	require.NoError(t, err)
	require.Equal(t, "cursor-token", resp.GetNextPageToken())
}
