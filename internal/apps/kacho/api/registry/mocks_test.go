// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package registry_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho-corelib/operations"

	registry "github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/api/registry"
	"github.com/PRO-Robotech/kacho-registry/internal/domain"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// ---- mock RegistryReader / RegistryWriter (CQRS-порты) --------------------

type mockRepo struct {
	mu sync.Mutex

	getFn    func(ctx context.Context, id string) (*domain.Registry, error)
	listFn   func(ctx context.Context, q registry.ListQuery) ([]*domain.Registry, string, error)
	insertFn func(ctx context.Context, r *domain.Registry, intent domain.RegisterIntent) (*domain.Registry, error)
	updateFn func(ctx context.Context, spec registry.UpdateSpec, mirror func(*domain.Registry) domain.RegisterIntent) (*domain.Registry, error)
	markFn   func(ctx context.Context, id string) (*domain.Registry, error)
	deleteFn func(ctx context.Context, id string, intent domain.RegisterIntent) error

	// Записанные вызовы для ассертов.
	insertIntent domain.RegisterIntent
	insertReg    *domain.Registry
	updateSpec   registry.UpdateSpec
	deleteIntent domain.RegisterIntent
	// updatePrincipal — principal, извлечённый из ctx worker'а на вызове Update
	// (проверка проброса principal в worker-ctx, иначе peer-вызовы анонимны).
	updatePrincipal operations.Principal
}

func (m *mockRepo) Get(ctx context.Context, id string) (*domain.Registry, error) {
	if m.getFn != nil {
		return m.getFn(ctx, id)
	}
	return nil, regerrors.ErrNotFound
}

func (m *mockRepo) List(ctx context.Context, q registry.ListQuery) ([]*domain.Registry, string, error) {
	if m.listFn != nil {
		return m.listFn(ctx, q)
	}
	return nil, "", nil
}

func (m *mockRepo) Insert(ctx context.Context, r *domain.Registry, intent domain.RegisterIntent) (*domain.Registry, error) {
	m.mu.Lock()
	m.insertReg = r
	m.insertIntent = intent
	m.mu.Unlock()
	if m.insertFn != nil {
		return m.insertFn(ctx, r, intent)
	}
	return r, nil
}

func (m *mockRepo) Update(ctx context.Context, spec registry.UpdateSpec, mirror func(*domain.Registry) domain.RegisterIntent) (*domain.Registry, error) {
	m.mu.Lock()
	m.updateSpec = spec
	m.updatePrincipal = operations.PrincipalFromContext(ctx)
	m.mu.Unlock()
	if m.updateFn != nil {
		return m.updateFn(ctx, spec, mirror)
	}
	return &domain.Registry{ID: spec.RegistryID, Status: domain.RegistryStatusActive}, nil
}

func (m *mockRepo) MarkDeleting(ctx context.Context, id string) (*domain.Registry, error) {
	if m.markFn != nil {
		return m.markFn(ctx, id)
	}
	return &domain.Registry{ID: id, ProjectID: "prj-P", Status: domain.RegistryStatusDeleting}, nil
}

func (m *mockRepo) Delete(ctx context.Context, id string, intent domain.RegisterIntent) error {
	m.mu.Lock()
	m.deleteIntent = intent
	m.mu.Unlock()
	if m.deleteFn != nil {
		return m.deleteFn(ctx, id, intent)
	}
	return nil
}

// ---- mock ZotClient -------------------------------------------------------

// deleteTagCall — записанный вызов DeleteTag с principal из worker-ctx (проверка
// проброса principal, REG-27).
type deleteTagCall struct {
	registryID string
	repository string
	tag        string
	principal  operations.Principal
}

type mockZot struct {
	mu       sync.Mutex
	removeFn func(ctx context.Context, registryID string) error

	removedNS []string
	// namespaceEmpty — значение, возвращаемое NamespaceEmpty (default false = НЕ пуст);
	// namespaceEmptyErr — инъекция ошибки (zot недоступен, fail-closed).
	namespaceEmpty    bool
	namespaceEmptyErr error

	deleteTagErr  error
	deleteTagCall []deleteTagCall

	// listTagsResult / listTagsErr — то, что вернёт ListTags (проверка
	// unregister-on-last-tag: после DeleteTag worker читает остаток тегов repo).
	listTagsResult []*domain.Tag
	listTagsErr    error

	triggerGCErr   error
	triggerGCCalls []string

	// statsResult / statsErr — управляемый ответ Stats; statsCalls — записанные
	// registryID (проверка проброса domain.RegistryStats из zot-бэкенда наружу
	// без изменения и что sync-reject не трогает бэкенд).
	statsResult *domain.RegistryStats
	statsErr    error
	statsCalls  []string
}

func (z *mockZot) ListRepositories(ctx context.Context, q registry.RepoListQuery) ([]*domain.Repository, string, error) {
	return nil, "", nil
}
func (z *mockZot) ListTags(ctx context.Context, q registry.TagListQuery) ([]*domain.Tag, string, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	return z.listTagsResult, "", z.listTagsErr
}
func (z *mockZot) DeleteTag(ctx context.Context, registryID, repository, tag string) error {
	z.mu.Lock()
	z.deleteTagCall = append(z.deleteTagCall, deleteTagCall{
		registryID: registryID, repository: repository, tag: tag,
		principal: operations.PrincipalFromContext(ctx),
	})
	z.mu.Unlock()
	return z.deleteTagErr
}
func (z *mockZot) NamespaceEmpty(ctx context.Context, registryID string) (bool, error) {
	if z.namespaceEmptyErr != nil {
		return false, z.namespaceEmptyErr
	}
	return z.namespaceEmpty, nil
}
func (z *mockZot) RemoveNamespace(ctx context.Context, registryID string) error {
	z.mu.Lock()
	z.removedNS = append(z.removedNS, registryID)
	z.mu.Unlock()
	if z.removeFn != nil {
		return z.removeFn(ctx, registryID)
	}
	return nil
}
func (z *mockZot) TriggerGC(ctx context.Context, registryID string) error {
	z.mu.Lock()
	z.triggerGCCalls = append(z.triggerGCCalls, registryID)
	z.mu.Unlock()
	return z.triggerGCErr
}
func (z *mockZot) Stats(ctx context.Context, registryID string) (*domain.RegistryStats, error) {
	z.mu.Lock()
	z.statsCalls = append(z.statsCalls, registryID)
	z.mu.Unlock()
	if z.statsErr != nil {
		return nil, z.statsErr
	}
	if z.statsResult != nil {
		return z.statsResult, nil
	}
	return &domain.RegistryStats{RegistryID: registryID}, nil
}

// ---- mock IAMClient (ProjectExists) --------------------------------------

type mockIAM struct {
	projectFn func(ctx context.Context, projectID string) error
	called    bool
}

func (i *mockIAM) ProjectExists(ctx context.Context, projectID string) error {
	i.called = true
	if i.projectFn != nil {
		return i.projectFn(ctx, projectID)
	}
	return nil
}

// ---- mock RepoRegistrar (register/unregister repo-tuple outbox intent) -----

type mockRepoReg struct {
	mu               sync.Mutex
	registerIntents  []domain.RegisterIntent
	unregisterIntent []domain.RegisterIntent
	registerErr      error
	unregisterErr    error
}

func (m *mockRepoReg) RegisterRepository(ctx context.Context, intent domain.RegisterIntent) error {
	m.mu.Lock()
	m.registerIntents = append(m.registerIntents, intent)
	m.mu.Unlock()
	return m.registerErr
}

func (m *mockRepoReg) UnregisterRepository(ctx context.Context, intent domain.RegisterIntent) error {
	m.mu.Lock()
	m.unregisterIntent = append(m.unregisterIntent, intent)
	m.mu.Unlock()
	return m.unregisterErr
}

// ---- in-memory operations.Repo + AwaitOpDone -----------------------------

type memOps struct {
	mu  sync.Mutex
	ops map[string]*operations.Operation
	// listErr — если задан, List возвращает его (no-leak тест: сырой repo-текст
	// не должен протечь наружу в gRPC Internal).
	listErr error
}

func newMemOps() *memOps { return &memOps{ops: map[string]*operations.Operation{}} }

func (m *memOps) put(op operations.Operation) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := op
	m.ops[op.ID] = &cp
}

func (m *memOps) Create(ctx context.Context, op operations.Operation) error { m.put(op); return nil }
func (m *memOps) CreateWithPrincipal(ctx context.Context, op operations.Operation, p operations.Principal) error {
	op.Principal = p
	m.put(op)
	return nil
}
func (m *memOps) Get(ctx context.Context, id string) (*operations.Operation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	op, ok := m.ops[id]
	if !ok {
		return nil, operations.ErrNotFound
	}
	cp := *op
	return &cp, nil
}
func (m *memOps) List(ctx context.Context, f operations.ListFilter) ([]operations.Operation, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.listErr != nil {
		return nil, "", m.listErr
	}
	out := make([]operations.Operation, 0, len(m.ops))
	for _, op := range m.ops {
		out = append(out, *op)
	}
	return out, "", nil
}
func (m *memOps) MarkDone(ctx context.Context, id string, response *anypb.Any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	op, ok := m.ops[id]
	if !ok {
		return operations.ErrNotFound
	}
	op.Done = true
	op.Response = response
	return nil
}
func (m *memOps) MarkError(ctx context.Context, id string, errStatus *status.Status) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	op, ok := m.ops[id]
	if !ok {
		return operations.ErrNotFound
	}
	op.Done = true
	op.Error = errStatus
	return nil
}
func (m *memOps) Cancel(ctx context.Context, id string) error { return nil }

// awaitOpDone детерминированно дожидается завершения LRO-worker'а (poll, не sleep).
func awaitOpDone(t *testing.T, ops *memOps, id string) *operations.Operation {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		op, err := ops.Get(context.Background(), id)
		if err == nil && op.Done {
			return op
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("operation %s did not complete in time", id)
	return nil
}

// newUC собирает UseCase поверх mock-портов + in-memory ops (repo-registrar —
// no-op mock, чтобы существующие CRUD-тесты не заботились о нём).
func newUC(repo *mockRepo, zot *mockZot, iam *mockIAM, ops *memOps) *registry.UseCase {
	return newUCWithReg(repo, zot, iam, ops, &mockRepoReg{})
}

// newUCWithReg — вариант с явным RepoRegistrar (для проверки unregister-on-last-tag).
func newUCWithReg(repo *mockRepo, zot *mockZot, iam *mockIAM, ops *memOps, reg *mockRepoReg) *registry.UseCase {
	return registry.New(repo, repo, zot, iam, reg, ops, "registry.kacho.local")
}

// aliceCtx — ctx с аутентифицированным principal (owner-tuple → user:usr-alice).
func aliceCtx() context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr-alice", DisplayName: "alice"})
}
