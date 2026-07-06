// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package handler — unit-тесты handler-слоя authz для ScopeFiltered registry-RPC
// (ListRepositories/ListTags/DeleteTag): namespace call-gate + per-repo row-filter +
// existence-hiding (deny→NOT_FOUND) + fail-closed (iam-error→UNAVAILABLE). Interceptor
// эти RPC пропускает (ScopeFiltered) — authz энфорсится ЗДЕСЬ. REG-22/23/24/25.
package handler

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho-corelib/operations"

	registryv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/registry/v1"
	registry "github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/api/registry"
	"github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/shared/namepage"
	"github.com/PRO-Robotech/kacho-registry/internal/domain"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// recordingAuthorizer — mock Authorizer: allow[object]=true → allowed; err → сбой
// (iam недоступен, fail-closed). Записывает вызовы для трассировки.
type recordingAuthorizer struct {
	mu    sync.Mutex
	allow map[string]bool
	err   error
	calls []string
}

func (r *recordingAuthorizer) Check(_ context.Context, _, relation, object string) (bool, error) {
	r.mu.Lock()
	r.calls = append(r.calls, relation+" "+object)
	r.mu.Unlock()
	if r.err != nil {
		return false, r.err
	}
	return r.allow[object], nil
}

// callCount — число зафиксированных Check-вызовов (thread-safe: filterRepos —
// bounded-concurrency).
func (r *recordingAuthorizer) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

// validReg — well-formed registry id (prefix "reg") для handler-method тестов,
// проходящих id-формат-валидацию (в отличие от читаемого "reg-A" в repoAuthz-юнитах).
const validReg = "regTEST00000000000000"

// carolCtx — ctx с аутентифицированным principal usr-carol.
func carolCtx() context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr-carol", DisplayName: "carol"})
}

func codeOf(t *testing.T, err error) codes.Code {
	t.Helper()
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok, "expected gRPC status, got %v", err)
	return st.Code()
}

// ---- repoAuthz helper (ядро handler-authz) --------------------------------

// REG-22 — row-filter: subject с v_list на reg-A/app но НЕ reg-A/web → filterRepos
// оставляет только app (namespace-viewer НЕ видит все repos автоматически).
func TestRepoAuthz_REG22_FilterRepos_PerRepo(t *testing.T) {
	az := &recordingAuthorizer{allow: map[string]bool{
		repositoryObjectRef("reg-A", "app"): true,
		// reg-A/web — НЕ разрешён.
	}}
	ra := newRepoAuthz(az)
	repos := []*domain.Repository{
		{RegistryID: "reg-A", Name: "app", TagCount: 2},
		{RegistryID: "reg-A", Name: "web", TagCount: 1},
	}
	got, err := ra.filterRepos(carolCtx(), "reg-A", repos)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "app", got[0].Name)
}

// REG-22 — namespace call-gate: v_list на registry_registry:<reg>; deny → NOT_FOUND
// (existence-hiding), allow → nil.
func TestRepoAuthz_REG22_NamespaceGate(t *testing.T) {
	t.Run("allow", func(t *testing.T) {
		az := &recordingAuthorizer{allow: map[string]bool{registryObjectRef("reg-A"): true}}
		require.NoError(t, newRepoAuthz(az).namespaceGate(carolCtx(), "reg-A"))
	})
	t.Run("deny_hides_existence", func(t *testing.T) {
		az := &recordingAuthorizer{allow: map[string]bool{}}
		err := newRepoAuthz(az).namespaceGate(carolCtx(), "reg-A")
		require.Equal(t, codes.NotFound, codeOf(t, err))
	})
}

// REG-24 — ListTags per-repo Check v_list на registry_repository:<reg>/<repo>; deny →
// NOT_FOUND (existence-hiding), НЕ PermissionDenied (не раскрывать чужой repo).
func TestRepoAuthz_REG24_CheckRepo_ListDeny_NotFound(t *testing.T) {
	az := &recordingAuthorizer{allow: map[string]bool{}} // нет v_list на web
	err := newRepoAuthz(az).checkRepo(carolCtx(), "reg-A", "web", relationVList)
	require.Equal(t, codes.NotFound, codeOf(t, err))
	require.Contains(t, az.calls, relationVList+" "+repositoryObjectRef("reg-A", "web"))
}

// REG-25 — DeleteTag per-repo Check v_delete; deny → NOT_FOUND (existence-hiding).
func TestRepoAuthz_REG25_CheckRepo_DeleteDeny_NotFound(t *testing.T) {
	az := &recordingAuthorizer{allow: map[string]bool{}}
	err := newRepoAuthz(az).checkRepo(carolCtx(), "reg-A", "app", relationVDelete)
	require.Equal(t, codes.NotFound, codeOf(t, err))
}

// REG-22/24 edge — iam недоступен → fail-closed UNAVAILABLE (не отдаём
// нефильтрованный список и не считаем deny).
func TestRepoAuthz_FailClosed_IAMError(t *testing.T) {
	az := &recordingAuthorizer{err: regerrors.ErrUnavailable}
	ra := newRepoAuthz(az)
	require.Equal(t, codes.Unavailable, codeOf(t, ra.namespaceGate(carolCtx(), "reg-A")))
	_, ferr := ra.filterRepos(carolCtx(), "reg-A", []*domain.Repository{{RegistryID: "reg-A", Name: "app"}})
	require.Equal(t, codes.Unavailable, codeOf(t, ferr))
	require.Equal(t, codes.Unavailable, codeOf(t, ra.checkRepo(carolCtx(), "reg-A", "app", relationVList)))
}

// Breakglass — nil Authorizer: authz пропускается (bypass), как interceptor при
// breakglass. namespaceGate/checkRepo → nil, filterRepos → все repos.
func TestRepoAuthz_Breakglass_NilAuthorizer_Bypass(t *testing.T) {
	ra := newRepoAuthz(nil)
	require.NoError(t, ra.namespaceGate(carolCtx(), "reg-A"))
	require.NoError(t, ra.checkRepo(carolCtx(), "reg-A", "app", relationVDelete))
	repos := []*domain.Repository{{RegistryID: "reg-A", Name: "app"}, {RegistryID: "reg-A", Name: "web"}}
	got, err := ra.filterRepos(carolCtx(), "reg-A", repos)
	require.NoError(t, err)
	require.Len(t, got, 2)
}

// ---- handler-method wiring (authz + use-case + zot) -----------------------

// REG-22 — RegistryService.ListRepositories: namespace allow + per-repo filter →
// ответ содержит ТОЛЬКО разрешённые repos (crit-1: call-gate + row-filter в handler).
func TestHandler_REG22_ListRepositories_RowFiltered(t *testing.T) {
	zot := &fakeZotH{repos: []*domain.Repository{
		{RegistryID: validReg, Name: "app", TagCount: 2},
		{RegistryID: validReg, Name: "web", TagCount: 1},
	}}
	az := &recordingAuthorizer{allow: map[string]bool{
		registryObjectRef(validReg):          true,
		repositoryObjectRef(validReg, "app"): true,
	}}
	h := newTestHandler(zot, az)

	resp, err := h.ListRepositories(carolCtx(), &registryv1.ListRepositoriesRequest{RegistryId: validReg})
	require.NoError(t, err)
	require.Len(t, resp.GetRepositories(), 1)
	require.Equal(t, "app", resp.GetRepositories()[0].GetName())
}

// REG-22 — ListRepositories namespace-deny → NOT_FOUND (existence-hiding); zot не
// раскрывается.
func TestHandler_REG22_ListRepositories_NamespaceDeny_NotFound(t *testing.T) {
	zot := &fakeZotH{repos: []*domain.Repository{{RegistryID: validReg, Name: "app"}}}
	az := &recordingAuthorizer{allow: map[string]bool{}}
	h := newTestHandler(zot, az)
	_, err := h.ListRepositories(carolCtx(), &registryv1.ListRepositoriesRequest{RegistryId: validReg})
	require.Equal(t, codes.NotFound, codeOf(t, err))
}

// REG-DOS — ListRepositories ОБЯЗАН ограничивать per-repo authz-Check fan-out окном
// страницы (page_size), а НЕ полной проекцией namespace. Регресс-гейт против
// CWE-770/400 self-amplifying DoS: N репо + page_size=k → не больше k repo-Check
// (+1 namespace-gate), а не N последовательных iam.Check до пагинации.
func TestHandler_ListRepositories_BoundsCheckFanoutToPage(t *testing.T) {
	const total = 200
	repos := make([]*domain.Repository, total)
	allow := map[string]bool{registryObjectRef(validReg): true}
	for i := range repos {
		name := fmt.Sprintf("repo-%04d", i)
		repos[i] = &domain.Repository{RegistryID: validReg, Name: name}
		allow[repositoryObjectRef(validReg, name)] = true
	}
	az := &recordingAuthorizer{allow: allow}
	h := newTestHandler(&fakeZotH{repos: repos}, az)

	resp, err := h.ListRepositories(carolCtx(),
		&registryv1.ListRepositoriesRequest{RegistryId: validReg, PageSize: 5})
	require.NoError(t, err)
	require.Len(t, resp.GetRepositories(), 5, "страница ограничена page_size")
	require.NotEmpty(t, resp.GetNextPageToken(), "есть ещё репо → next-token")

	// namespace-gate (1 Check) + окно (page_size Check) — НЕ по всему каталогу.
	require.LessOrEqualf(t, az.callCount(), 1+5,
		"per-repo Check fan-out обязан быть ограничен окном страницы, а не %d репо", total)
}

// REG-DOS — пагинация корректна при window-before-filter: обходя все страницы,
// клиент видит РОВНО разрешённое подмножество (фильтр может схлопнуть страницу, но
// next-token над сырыми именами достижимо доводит до всех разрешённых репо).
func TestHandler_ListRepositories_PaginateWindowBeforeFilter_AllAllowedReachable(t *testing.T) {
	repos := make([]*domain.Repository, 12)
	allow := map[string]bool{registryObjectRef(validReg): true}
	wantAllowed := map[string]bool{}
	for i := range repos {
		name := fmt.Sprintf("r%02d", i)
		repos[i] = &domain.Repository{RegistryID: validReg, Name: name}
		if i%3 == 0 { // только каждый третий разрешён
			allow[repositoryObjectRef(validReg, name)] = true
			wantAllowed[name] = true
		}
	}
	h := newTestHandler(&fakeZotH{repos: repos}, &recordingAuthorizer{allow: allow})

	got := map[string]bool{}
	token := ""
	for i := 0; i < 100; i++ { // guard против бесконечного цикла
		resp, err := h.ListRepositories(carolCtx(),
			&registryv1.ListRepositoriesRequest{RegistryId: validReg, PageSize: 2, PageToken: token})
		require.NoError(t, err)
		for _, r := range resp.GetRepositories() {
			got[r.GetName()] = true
		}
		token = resp.GetNextPageToken()
		if token == "" {
			break
		}
	}
	require.Equal(t, wantAllowed, got, "все разрешённые репо достижимы пагинацией, чужие — нет")
}

// REG-24 — ListTags per-repo allow → теги; deny → NOT_FOUND.
func TestHandler_REG24_ListTags_PerRepoCheck(t *testing.T) {
	zot := &fakeZotH{tags: []*domain.Tag{{RegistryID: validReg, Repository: "app", Tag: "v1", Digest: "sha256:x"}}}
	t.Run("allow", func(t *testing.T) {
		az := &recordingAuthorizer{allow: map[string]bool{repositoryObjectRef(validReg, "app"): true}}
		h := newTestHandler(zot, az)
		resp, err := h.ListTags(carolCtx(), &registryv1.ListTagsRequest{RegistryId: validReg, Repository: "app"})
		require.NoError(t, err)
		require.Len(t, resp.GetTags(), 1)
	})
	t.Run("deny_not_found", func(t *testing.T) {
		az := &recordingAuthorizer{allow: map[string]bool{}}
		h := newTestHandler(zot, az)
		_, err := h.ListTags(carolCtx(), &registryv1.ListTagsRequest{RegistryId: validReg, Repository: "web"})
		require.Equal(t, codes.NotFound, codeOf(t, err))
	})
}

// REG-25 — DeleteTag: deny → sync NOT_FOUND, Operation НЕ создаётся (zot не
// трогается); allow → Operation (async).
func TestHandler_REG25_DeleteTag_AuthzGate(t *testing.T) {
	t.Run("deny_no_operation", func(t *testing.T) {
		zot := &fakeZotH{}
		az := &recordingAuthorizer{allow: map[string]bool{}}
		h := newTestHandler(zot, az)
		_, err := h.DeleteTag(carolCtx(), &registryv1.DeleteTagRequest{RegistryId: validReg, Repository: "app", Tag: "v1"})
		require.Equal(t, codes.NotFound, codeOf(t, err))
		require.Zero(t, zot.deleteTagCalls, "deny → worker not started, zot untouched")
	})
	t.Run("allow_operation", func(t *testing.T) {
		zot := &fakeZotH{}
		az := &recordingAuthorizer{allow: map[string]bool{repositoryObjectRef(validReg, "app"): true}}
		h := newTestHandler(zot, az)
		op, err := h.DeleteTag(carolCtx(), &registryv1.DeleteTagRequest{RegistryId: validReg, Repository: "app", Tag: "v1"})
		require.NoError(t, err)
		require.NotNil(t, op)
		require.False(t, op.GetDone())
	})
}

// ---- fakes для handler-method тестов --------------------------------------

func newTestHandler(zot registry.ZotClient, az Authorizer) *RegistryHandler {
	uc := registry.New(stubRepo{}, stubRepo{}, zot, stubIAM{}, stubRepo{}, newMemOpsH(), "registry.kacho.local")
	return NewRegistryHandler(uc, az)
}

type stubRepo struct{}

func (stubRepo) Get(context.Context, string) (*domain.Registry, error) {
	return nil, regerrors.ErrNotFound
}
func (stubRepo) List(context.Context, registry.ListQuery) ([]*domain.Registry, string, error) {
	return nil, "", nil
}
func (stubRepo) Insert(context.Context, *domain.Registry, domain.RegisterIntent) (*domain.Registry, error) {
	return nil, nil
}
func (stubRepo) Update(context.Context, registry.UpdateSpec, func(*domain.Registry) domain.RegisterIntent) (*domain.Registry, error) {
	return nil, nil
}
func (stubRepo) MarkDeleting(context.Context, string) (*domain.Registry, error)    { return nil, nil }
func (stubRepo) Delete(context.Context, string, domain.RegisterIntent) error       { return nil }
func (stubRepo) RegisterRepository(context.Context, domain.RegisterIntent) error   { return nil }
func (stubRepo) UnregisterRepository(context.Context, domain.RegisterIntent) error { return nil }

type stubIAM struct{}

func (stubIAM) ProjectExists(context.Context, string) error { return nil }

type fakeZotH struct {
	repos          []*domain.Repository
	tags           []*domain.Tag
	deleteTagCalls int
}

// ListRepositories имитирует реальный zot-адаптер: режет окно у источника
// (page_size/page_token) ДО отдачи handler'у — так handler-тесты проверяют, что
// authz-фильтр применяется к УЖЕ-ограниченному окну (а не всей проекции).
func (f *fakeZotH) ListRepositories(_ context.Context, q registry.RepoListQuery) ([]*domain.Repository, string, error) {
	return namepage.Window(f.repos, func(r *domain.Repository) string { return r.Name },
		q.PageSize, q.PageToken)
}
func (f *fakeZotH) ListTags(context.Context, registry.TagListQuery) ([]*domain.Tag, string, error) {
	return f.tags, "", nil
}
func (f *fakeZotH) DeleteTag(context.Context, string, string, string) error {
	f.deleteTagCalls++
	return nil
}
func (f *fakeZotH) NamespaceEmpty(context.Context, string) (bool, error) { return true, nil }
func (f *fakeZotH) RemoveNamespace(context.Context, string) error        { return nil }
func (f *fakeZotH) TriggerGC(context.Context, string) error              { return nil }
func (f *fakeZotH) Stats(context.Context, string) (*domain.RegistryStats, error) {
	return &domain.RegistryStats{}, nil
}

// memOpsH — минимальный in-memory operations.Repo для handler-тестов.
type memOpsH struct {
	mu  sync.Mutex
	ops map[string]*operations.Operation
}

func newMemOpsH() *memOpsH { return &memOpsH{ops: map[string]*operations.Operation{}} }

func (m *memOpsH) put(op operations.Operation) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := op
	m.ops[op.ID] = &cp
}
func (m *memOpsH) Create(_ context.Context, op operations.Operation) error { m.put(op); return nil }
func (m *memOpsH) CreateWithPrincipal(_ context.Context, op operations.Operation, p operations.Principal) error {
	op.Principal = p
	m.put(op)
	return nil
}
func (m *memOpsH) Get(_ context.Context, id string) (*operations.Operation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	op, ok := m.ops[id]
	if !ok {
		return nil, operations.ErrNotFound
	}
	cp := *op
	return &cp, nil
}
func (m *memOpsH) List(context.Context, operations.ListFilter) ([]operations.Operation, string, error) {
	return nil, "", nil
}
func (m *memOpsH) MarkDone(_ context.Context, id string, response *anypb.Any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if op, ok := m.ops[id]; ok {
		op.Done = true
		op.Response = response
	}
	return nil
}
func (m *memOpsH) MarkError(_ context.Context, id string, s *rpcstatus.Status) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if op, ok := m.ops[id]; ok {
		op.Done = true
		op.Error = s
	}
	return nil
}
func (m *memOpsH) Cancel(context.Context, string) error { return nil }
