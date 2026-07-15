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
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	registryv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/registry/v1"
	registry "github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/api/registry"
	"github.com/PRO-Robotech/kacho-registry/internal/domain"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// barrierAuthorizer — Check блокируется до тех пор, пока в barrier не соберётся `want`
// одновременных вызовов; затем все разблокируются. Если filterRegistries вызывает
// Check последовательно, второй вызов никогда не стартует → barrier не наберётся →
// filterRegistries зависнет (тест ловит по таймауту). Доказывает bounded-concurrency
// fan-out (паритет с filterRepos/filterOperations).
type barrierAuthorizer struct {
	want    int
	arrived chan struct{}
	release chan struct{}
}

func newBarrierAuthorizer(want int) *barrierAuthorizer {
	return &barrierAuthorizer{want: want, arrived: make(chan struct{}, want), release: make(chan struct{})}
}

func (b *barrierAuthorizer) Check(_ context.Context, _, _, _ string) (bool, error) {
	b.arrived <- struct{}{}
	if len(b.arrived) == b.want {
		close(b.release) // достигнут порог одновременности → отпускаем всех
	}
	<-b.release
	return true, nil
}

// REG-06 concurrency — filterRegistries фанит per-registry Check bounded-concurrency
// (как filterRepos), а не последовательно: barrier требует 2 одновременных Check →
// последовательная реализация зависла бы (второй Check не стартовал бы, пока первый
// блокирован). Тест проходит только при параллельном fan-out.
func TestRepoAuthz_REG06_FilterRegistries_Concurrent(t *testing.T) {
	az := newBarrierAuthorizer(2)
	ra := newRepoAuthz(az)
	regs := []*domain.Registry{
		{ID: regA, ProjectID: "prj-P", Name: "team-a", Status: domain.RegistryStatusActive},
		{ID: regB, ProjectID: "prj-P", Name: "team-b", Status: domain.RegistryStatusActive},
	}
	done := make(chan struct{})
	var got []*domain.Registry
	var ferr error
	go func() {
		got, ferr = ra.filterRegistries(carolCtx(), regs)
		close(done)
	}()
	select {
	case <-done:
		require.NoError(t, ferr)
		require.Len(t, got, 2, "оба реестра allow → оба видны")
	case <-time.After(2 * time.Second):
		t.Fatal("filterRegistries не фанит Check concurrently (barrier не набрался) — последовательная реализация")
	}
}

// REG-06 order — row-filter сохраняет входной порядок реестров (детерминизм после
// параллельного fan-out): allow всех → выход в том же порядке, что вход.
func TestRepoAuthz_REG06_FilterRegistries_PreservesOrder(t *testing.T) {
	az := &recordingAuthorizer{allow: map[string]bool{
		registryObjectRef(regA): true,
		registryObjectRef(regB): true,
	}}
	regs := []*domain.Registry{
		{ID: regA, ProjectID: "prj-P", Name: "team-a", Status: domain.RegistryStatusActive},
		{ID: regB, ProjectID: "prj-P", Name: "team-b", Status: domain.RegistryStatusActive},
	}
	got, err := newRepoAuthz(az).filterRegistries(carolCtx(), regs)
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.Equal(t, regA, got[0].ID)
	require.Equal(t, regB, got[1].ID)
}

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
	uc := registry.New(reader, stubRepo{}, stubCfg{}, &fakeZotH{}, stubIAM{}, stubRepo{}, newMemOpsH(), "registry.kacho.local")
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
