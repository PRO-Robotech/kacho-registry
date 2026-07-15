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
	// namespaceEmptySeq — per-call ответы NamespaceEmpty (i-й вызов → seq[i]); за
	// пределами slice падаем на namespaceEmpty. Моделирует TOCTOU: sync-check пуст,
	// worker-recheck непуст (контент дозалился в окне).
	namespaceEmptySeq  []bool
	namespaceEmptyCall int

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

	// RG-1 config-overlay Repository projection/engine-порты.
	projByName   map[string]*domain.Repository
	projFn       func(registryID, repository string) (*domain.Repository, error)
	projErr      error
	empty        bool
	emptyErr     error
	renameErr    error
	renameCalls  [][3]string
	referrers    []*domain.Referrer
	referrersErr error
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
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.namespaceEmptyErr != nil {
		return false, z.namespaceEmptyErr
	}
	i := z.namespaceEmptyCall
	z.namespaceEmptyCall++
	if i < len(z.namespaceEmptySeq) {
		return z.namespaceEmptySeq[i], nil
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

// RepositoryProjection — управляемая проекция одного repo (GetRepository / merge). projFn
// даёт per-key ответ (durable-empty → nil); projErr — инъекция сбоя (fail-closed).
func (z *mockZot) RepositoryProjection(ctx context.Context, registryID, repository string) (*domain.Repository, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.projErr != nil {
		return nil, z.projErr
	}
	if z.projFn != nil {
		return z.projFn(registryID, repository)
	}
	if p, ok := z.projByName[repository]; ok {
		return p, nil
	}
	return nil, nil
}

// RepositoryEmpty — управляемая emptiness одного repo (DeleteRepository reject-if-tags).
func (z *mockZot) RepositoryEmpty(ctx context.Context, registryID, repository string) (bool, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.emptyErr != nil {
		return false, z.emptyErr
	}
	return z.empty, nil
}

// RenameRepository — записывает engine-remap вызов; renameErr — инъекция сбоя (A21).
func (z *mockZot) RenameRepository(ctx context.Context, registryID, oldName, newName string) error {
	z.mu.Lock()
	z.renameCalls = append(z.renameCalls, [3]string{registryID, oldName, newName})
	z.mu.Unlock()
	return z.renameErr
}

// ListReferrers — управляемый referrer-набор; referrersErr — инъекция сбоя.
func (z *mockZot) ListReferrers(ctx context.Context, registryID, repository, subjectDigest, artifactType string) ([]*domain.Referrer, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.referrersErr != nil {
		return nil, z.referrersErr
	}
	return z.referrers, nil
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
	// createErr — если задан, Create/CreateWithPrincipal возвращают его (симуляция
	// сбоя персиста pending-Operation; проверка LRO-ordering: ресурс не должен быть
	// записан, если Operation-envelope не удалось создать).
	createErr error
}

func newMemOps() *memOps { return &memOps{ops: map[string]*operations.Operation{}} }

func (m *memOps) put(op operations.Operation) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := op
	m.ops[op.ID] = &cp
}

func (m *memOps) Create(ctx context.Context, op operations.Operation) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.put(op)
	return nil
}
func (m *memOps) CreateWithPrincipal(ctx context.Context, op operations.Operation, p operations.Principal) error {
	if m.createErr != nil {
		return m.createErr
	}
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
	return registry.New(repo, repo, newMockCfg(), zot, iam, reg, ops, "registry.kacho.local")
}

// newUCWithCfg — вариант с явным config-overlay repo (RG-1 Repository RPC-тесты).
func newUCWithCfg(repo *mockRepo, cfg *mockRepoConfig, zot *mockZot, iam *mockIAM, ops *memOps) *registry.UseCase {
	return registry.New(repo, repo, cfg, zot, iam, &mockRepoReg{}, ops, "registry.kacho.local")
}

// ---- mock RepositoryConfigRepo (config-overlay CQRS-порт, RG-1) --------------

// cfgOutboxCall — записанный набор OutboxIntent, поданный writer'у (проверка эмиссии
// adopt-owner / public-grant governance в той же tx).
type cfgOutboxCall struct {
	op      string // insert/update/rekey/delete
	name    string
	newName string
	intents []registry.OutboxIntent
}

type mockRepoConfig struct {
	mu sync.Mutex

	byName map[string]*domain.RepositoryConfig

	getFn    func(registryID, name string) (*domain.RepositoryConfig, error)
	insertFn func(cfg *domain.RepositoryConfig) (*domain.RepositoryConfig, error)
	updateFn func(spec registry.RepositoryConfigUpdate) (*domain.RepositoryConfig, error)
	rekeyFn  func(registryID, oldName, newName string) (*domain.RepositoryConfig, error)
	deleteFn func(registryID, name string) error

	calls []cfgOutboxCall
}

func newMockCfg() *mockRepoConfig {
	return &mockRepoConfig{byName: map[string]*domain.RepositoryConfig{}}
}

func (m *mockRepoConfig) GetConfig(ctx context.Context, registryID, name string) (*domain.RepositoryConfig, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.getFn != nil {
		return m.getFn(registryID, name)
	}
	if c, ok := m.byName[name]; ok {
		return c, nil
	}
	return nil, regerrors.ErrNotFound
}

func (m *mockRepoConfig) ListConfigs(ctx context.Context, registryID string) ([]*domain.RepositoryConfig, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*domain.RepositoryConfig, 0, len(m.byName))
	for _, c := range m.byName {
		out = append(out, c)
	}
	return out, nil
}

func (m *mockRepoConfig) InsertConfig(ctx context.Context, cfg *domain.RepositoryConfig, intents ...registry.OutboxIntent) (*domain.RepositoryConfig, error) {
	m.mu.Lock()
	m.calls = append(m.calls, cfgOutboxCall{op: "insert", name: cfg.Name, intents: intents})
	m.mu.Unlock()
	if m.insertFn != nil {
		return m.insertFn(cfg)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byName[cfg.Name]; ok {
		return nil, regerrors.ErrAlreadyExists
	}
	cp := *cfg
	cp.CreatedAt = time.Now()
	m.byName[cfg.Name] = &cp
	return &cp, nil
}

func (m *mockRepoConfig) UpdateConfig(ctx context.Context, spec registry.RepositoryConfigUpdate, intents ...registry.OutboxIntent) (*domain.RepositoryConfig, error) {
	m.mu.Lock()
	m.calls = append(m.calls, cfgOutboxCall{op: "update", name: spec.Name, intents: intents})
	m.mu.Unlock()
	if m.updateFn != nil {
		return m.updateFn(spec)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.byName[spec.Name]
	if !ok {
		return nil, regerrors.ErrNotFound
	}
	if spec.ApplyDescription {
		c.Description = spec.Description
	}
	if spec.ApplyLabels {
		c.Labels = spec.Labels
	}
	if spec.ApplyVisibility {
		c.Visibility = spec.Visibility
	}
	return c, nil
}

func (m *mockRepoConfig) RekeyConfig(ctx context.Context, registryID, oldName, newName string, intents ...registry.OutboxIntent) (*domain.RepositoryConfig, error) {
	m.mu.Lock()
	m.calls = append(m.calls, cfgOutboxCall{op: "rekey", name: oldName, newName: newName, intents: intents})
	m.mu.Unlock()
	if m.rekeyFn != nil {
		return m.rekeyFn(registryID, oldName, newName)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.byName[oldName]
	if !ok {
		return nil, regerrors.ErrNotFound
	}
	if _, taken := m.byName[newName]; taken {
		return nil, regerrors.ErrAlreadyExists
	}
	cp := *c
	cp.Name = newName
	delete(m.byName, oldName)
	m.byName[newName] = &cp
	return &cp, nil
}

func (m *mockRepoConfig) DeleteConfig(ctx context.Context, registryID, name string, intents ...registry.OutboxIntent) error {
	m.mu.Lock()
	m.calls = append(m.calls, cfgOutboxCall{op: "delete", name: name, intents: intents})
	if m.deleteFn != nil {
		fn := m.deleteFn
		m.mu.Unlock()
		return fn(registryID, name)
	}
	defer m.mu.Unlock()
	if _, ok := m.byName[name]; !ok {
		return regerrors.ErrNotFound
	}
	delete(m.byName, name)
	return nil
}

// intentEvents собирает (event, subject, relation, object) всех эмитированных intent'ов
// по имени операции — для ассертов governance (public-grant / adopt-owner) в той же tx.
func (m *mockRepoConfig) allIntents() []registry.OutboxIntent {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []registry.OutboxIntent
	for _, c := range m.calls {
		out = append(out, c.intents...)
	}
	return out
}

// aliceCtx — ctx с аутентифицированным principal (owner-tuple → user:usr-alice).
func aliceCtx() context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr-alice", DisplayName: "alice"})
}
