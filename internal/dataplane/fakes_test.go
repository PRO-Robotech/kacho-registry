// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package dataplane

import (
	"bytes"
	"context"
	"net/http"
	"sync"

	"github.com/PRO-Robotech/kacho-registry/internal/domain"
)

// syncBuffer — потокобезопасная обёртка bytes.Buffer для логов, читаемых тестом ПАРАЛЛЕЛЬНО
// с фоновой goroutine хендлера (delete-on-materialized логирует из детач-goroutine; plain
// bytes.Buffer не безопасен для конкурентного Write/String → -race флагует).
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

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
	err := a.err
	allow := a.allow
	a.mu.Unlock()
	if err != nil {
		return false, err
	}
	if allow == nil {
		return true, nil
	}
	return allow[relation+" "+object], nil
}

// setAllow атомарно подменяет allow-набор (симуляция revoke: allow → deny между двумя
// pull'ами). Замена ссылки под mutex + чтение ссылки под mutex в Check → race-free.
func (a *fakeAuthz) setAllow(m map[string]bool) {
	a.mu.Lock()
	a.allow = m
	a.mu.Unlock()
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

// ---- fake PushGrantRecorder (per-subject push-ownership, REG-33 immediate-pull) ----

// pushGrantKey — записанный (registryID, repo, subject) факт push-ownership.
type pushGrantKey struct{ registryID, repo, subject string }

type fakePushGrantRecorder struct {
	mu        sync.Mutex
	recorded  []pushGrantKey    // порядок вызовов RecordPushGrant
	granted   map[string]bool   // "reg|repo|subject" → PushGranted возвращает true
	deleted   []pushGrantKey    // порядок вызовов DeletePushGrant (delete-on-materialized)
	delCh     chan pushGrantKey // != nil → DeletePushGrant неблокирующе шлёт сюда ключ (детерм. синхронизация async-delete в тесте)
	recErr    error             // RecordPushGrant возвращает эту ошибку
	getErr    error             // PushGranted возвращает эту ошибку
	delErr    error             // DeletePushGrant возвращает эту ошибку
	recCtxErr error             // ctx.Err() в момент RecordPushGrant (detach-регресс)
	delCtxErr error             // ctx.Err() в момент DeletePushGrant (detach-регресс)
	getCalls  int               // число вызовов PushGranted (проверка «fallback не трогается»)
}

func pushGrantCacheKey(registryID, repo, subject string) string {
	return registryID + "|" + repo + "|" + subject
}

func (g *fakePushGrantRecorder) RecordPushGrant(ctx context.Context, registryID, repo, subject string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.recCtxErr = ctx.Err()
	if g.recErr != nil {
		return g.recErr
	}
	g.recorded = append(g.recorded, pushGrantKey{registryID, repo, subject})
	if g.granted == nil {
		g.granted = map[string]bool{}
	}
	g.granted[pushGrantCacheKey(registryID, repo, subject)] = true
	return nil
}

func (g *fakePushGrantRecorder) PushGranted(ctx context.Context, registryID, repo, subject string) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.getCalls++
	if g.getErr != nil {
		return false, g.getErr
	}
	return g.granted[pushGrantCacheKey(registryID, repo, subject)], nil
}

// DeletePushGrant фиксирует вызов, убирает ключ из granted (симулирует «мост снят» — так
// последующий PushGranted вернёт false, как после реального DELETE) и, если задан delCh,
// неблокирующе сигналит тесту (для детерминированного ожидания async-delete из goroutine
// хендлера). Ctx.Err() снимается для проверки detach (delete идёт на WithoutCancel-ctx).
func (g *fakePushGrantRecorder) DeletePushGrant(ctx context.Context, registryID, repo, subject string) error {
	g.mu.Lock()
	g.delCtxErr = ctx.Err()
	if g.delErr != nil {
		err := g.delErr
		g.mu.Unlock()
		return err
	}
	key := pushGrantKey{registryID, repo, subject}
	g.deleted = append(g.deleted, key)
	if g.granted != nil {
		delete(g.granted, pushGrantCacheKey(registryID, repo, subject))
	}
	ch := g.delCh
	g.mu.Unlock()
	if ch != nil {
		select {
		case ch <- key:
		default: // буфер полон — не блокируем prod-goroutine хендлера
		}
	}
	return nil
}

func (g *fakePushGrantRecorder) recordedKeys() []pushGrantKey {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]pushGrantKey, len(g.recorded))
	copy(out, g.recorded)
	return out
}

func (g *fakePushGrantRecorder) deletedKeys() []pushGrantKey {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]pushGrantKey, len(g.deleted))
	copy(out, g.deleted)
	return out
}

// observedDelCtxErr — состояние ctx.Err() в момент DeletePushGrant. nil ⇒ контекст не был
// отменён (delete идёт на detached-ctx, переживает разрыв соединения за pull-ответом).
func (g *fakePushGrantRecorder) observedDelCtxErr() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.delCtxErr
}

// observedRecCtxErr — состояние ctx.Err() в момент durable-записи push-grant. nil ⇒
// контекст не был отменён (detached от отмены запроса).
func (g *fakePushGrantRecorder) observedRecCtxErr() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.recCtxErr
}

// newTestHandler собирает Handler поверх fake-портов с фиксированными realm/service.
// RegistryLookup — дефолтная пустая fake (тесты, не проверяющие ParentProjectID);
// UploadRecorder / PushGrantRecorder — дефолтные пустые fake (reveal не проверяется).
func newTestHandler(v TokenVerifier, az Authorizer, be Backend, fw Forwarder, rr RepoRegistrar) *Handler {
	return newTestHandlerFull(v, az, be, fw, rr, &fakeRegistryLookup{}, &fakeUploadRecorder{}, &fakePushGrantRecorder{})
}

// newTestHandlerLK — вариант с явной RegistryLookup (проверка project-резолва
// register-on-first-push).
func newTestHandlerLK(v TokenVerifier, az Authorizer, be Backend, fw Forwarder, rr RepoRegistrar, lk RegistryLookup) *Handler {
	return newTestHandlerFull(v, az, be, fw, rr, lk, &fakeUploadRecorder{}, &fakePushGrantRecorder{})
}

// newTestHandlerU — вариант с явной UploadRecorder (REG-33: blob-finalize record +
// push-time blob-scope reveal).
func newTestHandlerU(v TokenVerifier, az Authorizer, be Backend, fw Forwarder, rr RepoRegistrar, up UploadRecorder) *Handler {
	return newTestHandlerFull(v, az, be, fw, rr, &fakeRegistryLookup{}, up, &fakePushGrantRecorder{})
}

// newTestHandlerPG — вариант с явными UploadRecorder И PushGrantRecorder (REG-33
// immediate-pull: push-ownership fallback + record-on-manifest-PUT).
func newTestHandlerPG(v TokenVerifier, az Authorizer, be Backend, fw Forwarder, rr RepoRegistrar, up UploadRecorder, pg PushGrantRecorder) *Handler {
	return newTestHandlerFull(v, az, be, fw, rr, &fakeRegistryLookup{}, up, pg)
}

// newTestHandlerFull — полный конструктор поверх всех fake-портов.
func newTestHandlerFull(v TokenVerifier, az Authorizer, be Backend, fw Forwarder, rr RepoRegistrar, lk RegistryLookup, up UploadRecorder, pg PushGrantRecorder) *Handler {
	return New(v, az, be, fw, rr, lk, up, pg, "https://api.kacho.local/iam/token", "registry.kacho.local", nil)
}
