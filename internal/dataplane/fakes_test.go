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

// vCreateErrAuthz — Authorizer, отвечающий на v_get детерминированным allow/deny (без
// ошибки), но на v_create возвращающий заданную ошибку. Нужен, чтобы изолированно
// проверить fail-closed ветку fallback именно на v_create-Check (fakeAuthz.err
// применился бы ко ВСЕМ Check, в т.ч. первому v_get, и до fallback не дошло бы).
type vCreateErrAuthz struct {
	allowGet   bool
	vCreateErr error
}

func (a *vCreateErrAuthz) Check(ctx context.Context, subject, relation, object string) (bool, error) {
	switch relation {
	case relVCreate:
		return false, a.vCreateErr
	case relVGet:
		return a.allowGet, nil
	default:
		return false, nil
	}
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

// ForwardCapture — буферизованный вариант (blob PUT-finalize): считается тем же
// count()'ом, что и Forward, и возвращает сконфигурированный статус/тело как
// CapturedResponse.
func (f *fakeForwarder) ForwardCapture(r *http.Request) CapturedResponse {
	f.mu.Lock()
	f.calls = append(f.calls, r)
	f.mu.Unlock()
	st := f.status
	if st == 0 {
		st = http.StatusOK
	}
	var body []byte
	if f.body != "" {
		body = []byte(f.body)
	}
	return CapturedResponse{Status: st, Header: http.Header{}, Body: body}
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

// ---- fake UploadRecorder (per-repo blob-upload tracking, REG-33 Defect A) --

// uploadKey — записанный (registryID, repo, digest) факт аплоада.
type uploadKey struct{ registryID, repo, digest string }

type fakeUploadRecorder struct {
	mu        sync.Mutex
	recorded  []uploadKey     // порядок вызовов RecordUploadedBlob
	uploaded  map[string]bool // "reg|repo|digest" → BlobUploaded возвращает true
	recErr    error           // RecordUploadedBlob возвращает эту ошибку
	getErr    error           // BlobUploaded возвращает эту ошибку
	recCtxErr error           // ctx.Err() в момент RecordUploadedBlob (detach-регресс)
}

func uploadCacheKey(registryID, repo, digest string) string {
	return registryID + "|" + repo + "|" + digest
}

func (u *fakeUploadRecorder) RecordUploadedBlob(ctx context.Context, registryID, repo, digest string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.recCtxErr = ctx.Err()
	if u.recErr != nil {
		return u.recErr
	}
	u.recorded = append(u.recorded, uploadKey{registryID, repo, digest})
	if u.uploaded == nil {
		u.uploaded = map[string]bool{}
	}
	u.uploaded[uploadCacheKey(registryID, repo, digest)] = true
	return nil
}

func (u *fakeUploadRecorder) BlobUploaded(ctx context.Context, registryID, repo, digest string) (bool, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.getErr != nil {
		return false, u.getErr
	}
	return u.uploaded[uploadCacheKey(registryID, repo, digest)], nil
}

func (u *fakeUploadRecorder) recordedKeys() []uploadKey {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([]uploadKey, len(u.recorded))
	copy(out, u.recorded)
	return out
}

// observedRecCtxErr — состояние ctx.Err() в момент durable-записи. nil ⇒ контекст не
// был отменён (detached от отмены запроса).
func (u *fakeUploadRecorder) observedRecCtxErr() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.recCtxErr
}

// newTestHandler собирает Handler поверх fake-портов с фиксированными realm/service.
// RegistryLookup — дефолтная пустая fake (тесты, не проверяющие ParentProjectID);
// UploadRecorder — дефолтная пустая fake (blob-scope reveal не проверяется).
func newTestHandler(v TokenVerifier, az Authorizer, be Backend, fw Forwarder, rr RepoRegistrar) *Handler {
	return newTestHandlerFull(v, az, be, fw, rr, &fakeRegistryLookup{}, &fakeUploadRecorder{})
}

// newTestHandlerLK — вариант с явной RegistryLookup (проверка project-резолва
// register-on-first-push).
func newTestHandlerLK(v TokenVerifier, az Authorizer, be Backend, fw Forwarder, rr RepoRegistrar, lk RegistryLookup) *Handler {
	return newTestHandlerFull(v, az, be, fw, rr, lk, &fakeUploadRecorder{})
}

// newTestHandlerU — вариант с явной UploadRecorder (REG-33: blob-finalize record +
// push-time blob-scope reveal).
func newTestHandlerU(v TokenVerifier, az Authorizer, be Backend, fw Forwarder, rr RepoRegistrar, up UploadRecorder) *Handler {
	return newTestHandlerFull(v, az, be, fw, rr, &fakeRegistryLookup{}, up)
}

// newTestHandlerFull — полный конструктор поверх всех fake-портов.
func newTestHandlerFull(v TokenVerifier, az Authorizer, be Backend, fw Forwarder, rr RepoRegistrar, lk RegistryLookup, up UploadRecorder) *Handler {
	return New(v, az, be, fw, rr, lk, up, "https://api.kacho.local/iam/token", "registry.kacho.local", nil)
}
