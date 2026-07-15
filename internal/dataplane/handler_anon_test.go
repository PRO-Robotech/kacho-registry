// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package dataplane

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// handler_anon_test.go — RG-1 group B (anonymous public-read data-plane path,
// B03/B04/B05/B07/B14). A VALID iam-issued anon Bearer carries the configured
// anonymous principal id (its Hydra client id); the data-plane resolves it to the FGA
// wildcard `user:*` (D-7). PUBLIC repos carry a `user:* v_get` tuple (emitted by the
// overlay) → anon read allowed (200); PRIVATE/absent → the SAME uniform 404
// NAME_UNKNOWN (public-ness is NOT a probeable existence-oracle). Anon push is denied
// (user:* holds no write relation) → 403 DENIED; a request with no Bearer at all →
// 401 challenge (unchanged). The verb-per-route model is unchanged: manifest/blob use
// v_get (covered by the user:* wildcard), tags/list uses v_list (NO wildcard — anon
// cannot enumerate tags), which is why these tests exercise the docker-pull core
// (manifest + blob) rather than tag listing.

// anonClientID — the anon Hydra client id an anon Bearer's `sub` carries. The
// data-plane is configured (WithAnonymousSubject) to resolve this id to `user:*`.
const anonClientID = "cid-registry-anon"

// subjectAuthz — a subject-AWARE fake Authorizer keyed on the full (subject, relation,
// object) triple. Unlike fakeAuthz (which ignores the subject), it distinguishes
// `user:*` from any other principal — required to lock the anon→user:* mapping
// BEHAVIOURALLY: before the wiring the anon token resolves to
// service_account:<anonClientID> and is denied even on a PUBLIC repo (RED).
type subjectAuthz struct {
	mu    sync.Mutex
	calls []checkCall
	allow map[string]bool // "subject relation object" → allow
}

func (a *subjectAuthz) Check(ctx context.Context, subject, relation, object string) (bool, error) {
	a.mu.Lock()
	a.calls = append(a.calls, checkCall{subject, relation, object})
	allow := a.allow
	a.mu.Unlock()
	return allow[subject+" "+relation+" "+object], nil
}

func (a *subjectAuthz) checks() []checkCall {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]checkCall, len(a.calls))
	copy(out, a.calls)
	return out
}

// hasSubject reports whether any recorded Check carried the given subject.
func (a *subjectAuthz) hasSubject(subject string) bool {
	for _, c := range a.checks() {
		if c.subject == subject {
			return true
		}
	}
	return false
}

// newAnonHandler — a handler whose verifier resolves any Bearer to anonClientID (the
// anon principal) and which is configured to recognise anonClientID as anonymous
// (→ user:*). Mirrors the deployed wiring: iam issues the anon Bearer, the data-plane
// resolves it to the public wildcard.
func newAnonHandler(az Authorizer, be Backend, fw Forwarder) *Handler {
	return newTestHandler(&fakeVerifier{subject: anonClientID}, az, be, fw, &fakeRepoReg{}).
		WithAnonymousSubject(anonClientID)
}

const publicRepoObject = "registry_repository:reg-A/public"

// TestDataplane_RG1_B03_AnonPullPublic_200 — a VALID anon Bearer pulling a PUBLIC repo
// (manifest GET/HEAD + blob GET) → 200. The per-request Check MUST carry the FGA
// wildcard subject `user:*` (proves the anon-recognition wiring); the PUBLIC repo's
// `user:* v_get` tuple grants the read. RED before wiring: the anon token resolves to
// service_account:<anonClientID>, the subject-aware authz denies, and the pull 404s.
func TestDataplane_RG1_B03_AnonPullPublic_200(t *testing.T) {
	az := &subjectAuthz{allow: map[string]bool{
		"user:* v_get " + publicRepoObject: true, // PUBLIC repo carries the user:* v_get tuple
	}}
	fw := &fakeForwarder{status: 200}
	be := &fakeBackend{
		exists: map[string]bool{"reg-A/public": true},
		blobs:  map[string]bool{"reg-A/public|sha256:x": true},
	}
	h := newAnonHandler(az, be, fw)

	// manifest GET + HEAD (v_get, covered by the user:* wildcard).
	for _, m := range []string{http.MethodGet, http.MethodHead} {
		rec := doReq(h, m, "/v2/reg-A/public/manifests/v1", true)
		require.Equal(t, http.StatusOK, rec.Code, "anon manifest %s of PUBLIC repo → 200", m)
	}
	// blob GET (v_get + REG-37 member-scope).
	rec := doReq(h, http.MethodGet, "/v2/reg-A/public/blobs/sha256:x", true)
	require.Equal(t, http.StatusOK, rec.Code, "anon member-blob pull of PUBLIC repo → 200")

	require.True(t, az.hasSubject("user:*"),
		"anon Bearer MUST resolve to the FGA wildcard user:* (D-7); before wiring it would be service_account:%s", anonClientID)
	require.False(t, az.hasSubject("service_account:"+anonClientID),
		"anon Bearer MUST NOT reach FGA as an ordinary service_account principal")
}

// TestDataplane_RG1_B04B05_AnonPullPrivateOrAbsent_Uniform404 — a VALID anon Bearer
// pulling a PRIVATE repo (exists, no user:* v_get tuple, B04) OR an ABSENT repo (B05)
// → the SAME uniform 404 NAME_UNKNOWN, byte-for-byte identical to a missing repo.
// public-ness is NOT a probeable existence-oracle: private-exists is indistinguishable
// from absent. The Check still carries user:* (mapping applied) but denies.
func TestDataplane_RG1_B04B05_AnonPullPrivateOrAbsent_Uniform404(t *testing.T) {
	az := &subjectAuthz{allow: map[string]bool{}} // no user:* v_get anywhere → all anon reads deny
	fw := &fakeForwarder{}
	be := &fakeBackend{exists: map[string]bool{"reg-A/private": true}} // private exists; ghost absent
	h := newAnonHandler(az, be, fw)

	// B04 — PRIVATE (exists) → 404 NAME_UNKNOWN.
	privateRec := doReq(h, http.MethodGet, "/v2/reg-A/private/manifests/v1", true)
	require.Equal(t, http.StatusNotFound, privateRec.Code, "anon pull of PRIVATE repo → 404")

	// B05 — ABSENT → 404 NAME_UNKNOWN.
	absentRec := doReq(h, http.MethodGet, "/v2/reg-A/ghost/manifests/v1", true)
	require.Equal(t, http.StatusNotFound, absentRec.Code, "anon pull of ABSENT repo → 404")

	// Existence-oracle safety: PRIVATE-exists and ABSENT are byte-for-byte identical.
	require.Equal(t, absentRec.Body.String(), privateRec.Body.String(),
		"PRIVATE-exists and ABSENT anon-404 bodies MUST be byte-identical (no public-ness oracle)")
	require.Equal(t, `{"errors":[{"code":"NAME_UNKNOWN","message":"not found"}]}`+"\n", privateRec.Body.String())

	require.Equal(t, 0, fw.count(), "denied anon reads never reach zot")
	require.True(t, az.hasSubject("user:*"), "anon read still resolves to user:* before it is denied")
}

// TestDataplane_RG1_B04_HeadAndBlob_Uniform404 — the uniform-404 existence-hiding
// holds across the docker-pull surface (HEAD manifest + blob GET), not only manifest
// GET: a probe on any read verb of a PRIVATE/absent repo is indistinguishable.
func TestDataplane_RG1_B04_HeadAndBlob_Uniform404(t *testing.T) {
	az := &subjectAuthz{allow: map[string]bool{}}
	fw := &fakeForwarder{}
	be := &fakeBackend{blobs: map[string]bool{"reg-A/private|sha256:x": true}} // member blob, but repo not readable by anon
	h := newAnonHandler(az, be, fw)

	for _, tc := range []struct {
		method, target string
	}{
		{http.MethodHead, "/v2/reg-A/private/manifests/v1"},
		{http.MethodGet, "/v2/reg-A/private/blobs/sha256:x"},
		{http.MethodHead, "/v2/reg-A/private/blobs/sha256:x"},
	} {
		rec := doReq(h, tc.method, tc.target, true)
		require.Equal(t, http.StatusNotFound, rec.Code, "anon %s %s (PRIVATE) → 404", tc.method, tc.target)
	}
	require.Equal(t, 0, fw.count(), "denied anon reads never reach zot")
}

// TestDataplane_RG1_B07_AnonPushNoToken_401 — B07(a): a push with NO Bearer at all →
// 401 + WWW-Authenticate challenge (unchanged; push requires identity, PUBLIC grants
// only a read wildcard). The challenge is repo-independent → not an oracle.
func TestDataplane_RG1_B07_AnonPushNoToken_401(t *testing.T) {
	az := &subjectAuthz{allow: map[string]bool{}}
	fw := &fakeForwarder{}
	be := &fakeBackend{exists: map[string]bool{"reg-A/public": true}}
	h := newAnonHandler(az, be, fw)

	rec := doReq(h, http.MethodPost, "/v2/reg-A/public/blobs/uploads/", false) // no Bearer
	require.Equal(t, http.StatusUnauthorized, rec.Code, "no-token push → 401 challenge")
	require.Contains(t, rec.Header().Get("WWW-Authenticate"), `realm=`)
	require.Equal(t, 0, fw.count(), "unauthenticated push never reaches zot")
}

// TestDataplane_RG1_B14_AnonTokenPushPublic_403Denied — B07(b)/B14: an anon Bearer
// (user:*, read-only) attempting `docker push` into a PULL-ABLE PUBLIC repo → 403
// DENIED. user:* carries the v_get wildcard (the repo IS anon-readable) but NO write
// relation, so the push-verb Check (v_update on the existing repo) denies → uniform
// push-deny 403. Public-ness of a repo does NOT open anonymous writes. The Check MUST
// carry user:* (proves the mapping applies on the write path too).
func TestDataplane_RG1_B14_AnonTokenPushPublic_403Denied(t *testing.T) {
	az := &subjectAuthz{allow: map[string]bool{
		"user:* v_get " + publicRepoObject: true, // repo is anon-pull-able...
		// ...but NO "user:* v_update" — user:* holds no write relation (read-only floor).
	}}
	fw := &fakeForwarder{}
	be := &fakeBackend{exists: map[string]bool{"reg-A/public": true}} // existing repo → push verb = v_update@repo
	h := newAnonHandler(az, be, fw)

	// manifest PUT (push) into the existing PUBLIC repo → v_update Check denies → 403.
	rec := doReq(h, http.MethodPut, "/v2/reg-A/public/manifests/v2", true)
	require.Equal(t, http.StatusForbidden, rec.Code, "anon push into pull-able PUBLIC repo → 403 DENIED")
	require.Equal(t, "DENIED", pushDenyCode(t, rec))
	require.Equal(t, 0, fw.count(), "denied anon push never writes to zot")

	// The write-path Check was made as user:* (mapping applied), and denied.
	require.Contains(t, az.checks(), checkCall{"user:*", "v_update", publicRepoObject},
		"anon push resolves to user:* and is checked for the write verb v_update (denied — no wildcard write)")
}

// TestDataplane_RG1_B14_AnonTokenPushNewRepo_403Denied — an anon Bearer initiating a
// blob-upload into a NEW repo (push-new verb = v_create@registry_registry) → 403
// DENIED: user:* holds no v_create on the namespace either. No register-on-first-push
// intent is emitted (push was denied).
func TestDataplane_RG1_B14_AnonTokenPushNewRepo_403Denied(t *testing.T) {
	az := &subjectAuthz{allow: map[string]bool{}} // user:* has no v_create on the registry
	fw := &fakeForwarder{}
	be := &fakeBackend{exists: map[string]bool{}} // repo does not exist → push-new
	rr := &fakeRepoReg{}
	h := newTestHandler(&fakeVerifier{subject: anonClientID}, az, be, fw, rr).WithAnonymousSubject(anonClientID)

	rec := doReq(h, http.MethodPost, "/v2/reg-A/fresh/blobs/uploads/", true)
	require.Equal(t, http.StatusForbidden, rec.Code, "anon push into a NEW repo → 403 DENIED")
	require.Equal(t, "DENIED", pushDenyCode(t, rec))
	require.Equal(t, 0, fw.count())
	require.Empty(t, rr.registered(), "denied anon push emits no register-intent")
	require.Contains(t, az.checks(), checkCall{"user:*", "v_create", "registry_registry:reg-A"},
		"anon push-new resolves to user:* and is checked for v_create (denied)")
}

// TestDataplane_RG1_AnonDisabled_TokenResolvesAsOrdinaryPrincipal — secure-by-default:
// with anonymous pull DISABLED (WithAnonymousSubject NOT called / empty), a token whose
// sub equals the anon client id resolves as an ordinary principal (service_account),
// NOT the wildcard — it never silently gains public-read. A PUBLIC repo (whose grant is
// user:* only) then denies it → 404.
func TestDataplane_RG1_AnonDisabled_TokenResolvesAsOrdinaryPrincipal(t *testing.T) {
	az := &subjectAuthz{allow: map[string]bool{
		"user:* v_get " + publicRepoObject: true, // only the wildcard is granted
	}}
	fw := &fakeForwarder{}
	be := &fakeBackend{exists: map[string]bool{"reg-A/public": true}}
	// anonymous NOT configured (WithAnonymousSubject not called) → disabled.
	h := newTestHandler(&fakeVerifier{subject: anonClientID}, az, be, fw, &fakeRepoReg{})

	rec := doReq(h, http.MethodGet, "/v2/reg-A/public/manifests/v1", true)
	require.Equal(t, http.StatusNotFound, rec.Code,
		"anon disabled → anon-shaped token resolves as ordinary principal, not user:* → PUBLIC repo denies → 404")
	require.True(t, az.hasSubject("service_account:"+anonClientID),
		"anon disabled → token resolves by id-prefix (service_account), not the wildcard")
	require.False(t, az.hasSubject("user:*"), "anon disabled → the wildcard is never used")
	require.Equal(t, 0, fw.count())
}
