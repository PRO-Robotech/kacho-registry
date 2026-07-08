// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package dataplane

import (
	"context"
	"net/http"
	"sync"

	"github.com/PRO-Robotech/kacho-registry/internal/domain"
)

// ---- fake TokenVerifier ---------------------------------------------------

type fakeVerifier struct {
	subject string
	err     error
	calls   int
}

func (v *fakeVerifier) Verify(ctx context.Context, raw string) (string, error) {
	v.calls++
	if v.err != nil {
		return "", v.err
	}
	return v.subject, nil
}

// ---- fake Authorizer (per-request Check) ----------------------------------

type checkCall struct{ subject, relation, object string }

type fakeAuthz struct {
	mu    sync.Mutex
	calls []checkCall
	// allow: ключ "relation object" → allow (отсутствие → deny). nil → allow-all.
	allow map[string]bool
	err   error
}

func (a *fakeAuthz) Check(ctx context.Context, subject, relation, object string) (bool, error) {
	a.mu.Lock()
	a.calls = append(a.calls, checkCall{subject, relation, object})
	a.mu.Unlock()
	if a.err != nil {
		return false, a.err
	}
	if a.allow == nil {
		return true, nil
	}
	return a.allow[relation+" "+object], nil
}

func (a *fakeAuthz) checkedObjects() []checkCall {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]checkCall, len(a.calls))
	copy(out, a.calls)
	return out
}

// ---- fake Backend (zot introspection) -------------------------------------

type fakeBackend struct {
	exists     map[string]bool // "reg/repo" → exists
	blobs      map[string]bool // "reg/repo|digest" → in-repo
	catalog    []string
	existsErr  error
	blobErr    error
	catalogErr error
}

func (b *fakeBackend) RepoExists(ctx context.Context, registryID, repo string) (bool, error) {
	if b.existsErr != nil {
		return false, b.existsErr
	}
	return b.exists[registryID+"/"+repo], nil
}

func (b *fakeBackend) BlobInRepo(ctx context.Context, registryID, repo, digest string) (bool, error) {
	if b.blobErr != nil {
		return false, b.blobErr
	}
	return b.blobs[registryID+"/"+repo+"|"+digest], nil
}

func (b *fakeBackend) CatalogRepoNames(ctx context.Context) ([]string, error) {
	if b.catalogErr != nil {
		return nil, b.catalogErr
	}
	return b.catalog, nil
}

// ---- fake Forwarder (reverse-proxy stub) ----------------------------------

type fakeForwarder struct {
	mu     sync.Mutex
	calls  []*http.Request
	status int
	body   string
}

func (f *fakeForwarder) Forward(w http.ResponseWriter, r *http.Request) int {
	f.mu.Lock()
	f.calls = append(f.calls, r)
	f.mu.Unlock()
	st := f.status
	if st == 0 {
		st = http.StatusOK
	}
	w.WriteHeader(st)
	if f.body != "" {
		_, _ = w.Write([]byte(f.body))
	}
	return st
}

func (f *fakeForwarder) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// ---- fake RepoRegistrar (register-on-first-push) --------------------------

type fakeRepoReg struct {
	mu      sync.Mutex
	intents []domain.RegisterIntent
	err     error
	ctxErr  error // ctx.Err() наблюдённый в момент вызова (detach-регресс REG-14e)
}

func (r *fakeRepoReg) RegisterRepository(ctx context.Context, intent domain.RegisterIntent) error {
	r.mu.Lock()
	r.intents = append(r.intents, intent)
	r.ctxErr = ctx.Err()
	r.mu.Unlock()
	return r.err
}

// observedCtxErr — состояние ctx.Err() в момент durable-emit. nil ⇒ контекст не был
// отменён (detached от отмены запроса), != nil ⇒ отмена запроса дотянулась до emit.
func (r *fakeRepoReg) observedCtxErr() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ctxErr
}

func (r *fakeRepoReg) registered() []domain.RegisterIntent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]domain.RegisterIntent, len(r.intents))
	copy(out, r.intents)
	return out
}

// ---- fake RegistryLookup (owning-project резолв) --------------------------

type fakeRegistryLookup struct {
	mu                sync.Mutex
	projectByRegistry map[string]string
	err               error
	calls             int
}

func (l *fakeRegistryLookup) RegistryProjectID(ctx context.Context, registryID string) (string, error) {
	l.mu.Lock()
	l.calls++
	l.mu.Unlock()
	if l.err != nil {
		return "", l.err
	}
	return l.projectByRegistry[registryID], nil
}

// newTestHandler собирает Handler поверх fake-портов с фиксированными realm/service.
// RegistryLookup — дефолтная пустая fake (тесты, не проверяющие ParentProjectID).
func newTestHandler(v TokenVerifier, az Authorizer, be Backend, fw Forwarder, rr RepoRegistrar) *Handler {
	return newTestHandlerLK(v, az, be, fw, rr, &fakeRegistryLookup{})
}

// newTestHandlerLK — вариант с явной RegistryLookup (проверка project-резолва
// register-on-first-push).
func newTestHandlerLK(v TokenVerifier, az Authorizer, be Backend, fw Forwarder, rr RepoRegistrar, lk RegistryLookup) *Handler {
	return New(v, az, be, fw, rr, lk, "https://api.kacho.local/iam/token", "registry.kacho.local", nil)
}
