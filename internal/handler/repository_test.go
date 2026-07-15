// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// repository_test.go — unit-тесты handler-слоя config-overlay Repository RPC (RG-1):
// any-path-to-PUBLIC admin-gate (B02/B08/B10/B11/B12), existence-hiding deny→NOT_FOUND
// "repository not found" (A08/C02/A15), namespace call-gate X04, malformed-first A06.
// Authz-гейты живут В ХЕНДЛЕРЕ (ScopeFiltered) — здесь через relation-aware fake.
package handler

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	registryv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/registry/v1"
)

// relAuthz — Authorizer, ключуемый по паре (relation, object) — в отличие от
// recordingAuthorizer (object-only), нужен для admin-gate (v_create/v_update разрешён,
// admin — нет, на ТОМ ЖЕ объекте registry_registry).
type relAuthz struct {
	allow map[string]bool
	err   error
}

func (a relAuthz) Check(_ context.Context, _, relation, object string) (bool, error) {
	if a.err != nil {
		return false, a.err
	}
	return a.allow[relation+" "+object], nil
}

func regRef() string          { return registryObjectRef(validReg) }
func repoRef(r string) string { return repositoryObjectRef(validReg, r) }

// statusMsg — gRPC message ошибки (behaviour-level assert контракт-текста).
func statusMsg(err error) string {
	return status.Convert(err).Message()
}

// RG-1-B08 — CreateRepository с явным visibility=PUBLIC не-admin'ом (v_create есть,
// admin нет) → PERMISSION_DENIED "creating a public repository requires registry admin".
func TestRepositoryHandler_RG1B08_CreatePublicNonAdmin(t *testing.T) {
	az := relAuthz{allow: map[string]bool{"v_create " + regRef(): true}} // admin НЕ разрешён
	h := newTestHandler(&fakeZotH{}, az)
	_, err := h.CreateRepository(carolCtx(), &registryv1.CreateRepositoryRequest{
		RegistryId: validReg, Repository: "open/x", Visibility: registryv1.Visibility_PUBLIC,
	})
	require.Equal(t, codes.PermissionDenied, codeOf(t, err))
	require.Equal(t, "creating a public repository requires registry admin", statusMsg(err))
}

// RG-1-B12-boundary — тот же не-admin создаёт repo БЕЗ visibility (UNSPECIFIED) →
// admin-gate НЕ срабатывает (наследование дефолта — gate-at-default), проходит.
func TestRepositoryHandler_RG1B12_CreateInheritNonAdmin_NoGate(t *testing.T) {
	az := relAuthz{allow: map[string]bool{"v_create " + regRef(): true}}
	h := newTestHandler(&fakeZotH{}, az)
	_, err := h.CreateRepository(carolCtx(), &registryv1.CreateRepositoryRequest{
		RegistryId: validReg, Repository: "open/inherited", // visibility UNSPECIFIED
	})
	require.NotEqual(t, codes.PermissionDenied, codeOf(t, err)) // gate не сработал (use-case reader stub → NotFound, но НЕ 403)
}

// RG-1-X04 — CreateRepository в невидимом реестре (нет v_create) → NOT_FOUND
// (namespace call-gate, existence-hiding — не PERMISSION_DENIED).
func TestRepositoryHandler_RG1X04_CreateNamespaceHiding(t *testing.T) {
	az := relAuthz{allow: map[string]bool{}} // v_create НЕ разрешён
	h := newTestHandler(&fakeZotH{}, az)
	_, err := h.CreateRepository(carolCtx(), &registryv1.CreateRepositoryRequest{RegistryId: validReg, Repository: "x/y"})
	require.Equal(t, codes.NotFound, codeOf(t, err))
}

// RG-1-A06 — malformed registry_id → INVALID_ARGUMENT ПЕРВЫМ (до authz), все RPC.
func TestRepositoryHandler_RG1A06_MalformedRegistryID(t *testing.T) {
	h := newTestHandler(&fakeZotH{}, relAuthz{allow: map[string]bool{}})
	_, err := h.GetRepository(carolCtx(), &registryv1.GetRepositoryRequest{RegistryId: "not-a-reg", Repository: "a/b"})
	require.Equal(t, codes.InvalidArgument, codeOf(t, err))
	require.Contains(t, statusMsg(err), "invalid registry id 'not-a-reg'")
}

// RG-1-A08 — GetRepository unauthorized → NOT_FOUND "repository not found"
// (existence-hiding, байт-в-байт с absent).
func TestRepositoryHandler_RG1A08_GetExistenceHiding(t *testing.T) {
	az := relAuthz{allow: map[string]bool{}} // нет v_get
	h := newTestHandler(&fakeZotH{}, az)
	_, err := h.GetRepository(carolCtx(), &registryv1.GetRepositoryRequest{RegistryId: validReg, Repository: "secret/svc"})
	require.Equal(t, codes.NotFound, codeOf(t, err))
	require.Equal(t, "repository not found", statusMsg(err), "existence-hiding text (A08)")
}

// RG-1-C02 — ListReferrers unauthorized → NOT_FOUND "repository not found".
func TestRepositoryHandler_RG1C02_ReferrersExistenceHiding(t *testing.T) {
	az := relAuthz{allow: map[string]bool{}}
	h := newTestHandler(&fakeZotH{}, az)
	_, err := h.ListReferrers(carolCtx(), &registryv1.ListReferrersRequest{RegistryId: validReg, Repository: "secret/app", SubjectDigest: "sha256:x"})
	require.Equal(t, codes.NotFound, codeOf(t, err))
	require.Equal(t, "repository not found", statusMsg(err))
}

// RG-1-A15 — DeleteRepository unauthorized → sync NOT_FOUND, Operation НЕ создаётся.
func TestRepositoryHandler_RG1A15_DeleteExistenceHiding(t *testing.T) {
	ops := newMemOpsH()
	h := newTestHandlerOps(ops, relAuthz{allow: map[string]bool{}}) // нет v_delete
	_, err := h.DeleteRepository(carolCtx(), &registryv1.DeleteRepositoryRequest{RegistryId: validReg, Repository: "secret/svc"})
	require.Equal(t, codes.NotFound, codeOf(t, err))
	require.Equal(t, "repository not found", statusMsg(err))
	require.Equal(t, 0, ops.count(), "Operation НЕ создана на deny (A15)")
}

// RG-1-B02 — UpdateRepository visibility→PUBLIC не-admin (v_update есть, admin нет) →
// PERMISSION_DENIED "changing repository visibility requires registry admin".
func TestRepositoryHandler_RG1B02_FlipVisibilityNonAdmin(t *testing.T) {
	az := relAuthz{allow: map[string]bool{"v_update " + repoRef("public/img"): true}}
	h := newTestHandler(&fakeZotH{}, az)
	_, err := h.UpdateRepository(carolCtx(), &registryv1.UpdateRepositoryRequest{
		RegistryId: validReg, Repository: "public/img",
		Visibility: registryv1.Visibility_PUBLIC,
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"visibility"}},
	})
	require.Equal(t, codes.PermissionDenied, codeOf(t, err))
	require.Equal(t, "changing repository visibility requires registry admin", statusMsg(err))
}

// RG-1-B10/B11 — UpdateRegistry default_visibility→PUBLIC: не-admin → PERMISSION_DENIED;
// admin → gate пройден (не 403).
func TestRepositoryHandler_RG1B10B11_RegistryDefaultVisibilityAdminGate(t *testing.T) {
	mask := &fieldmaskpb.FieldMask{Paths: []string{"default_visibility"}}
	req := &registryv1.UpdateRegistryRequest{RegistryId: validReg, DefaultVisibility: registryv1.Visibility_PUBLIC, UpdateMask: mask}

	// B10 не-admin → PERMISSION_DENIED.
	hDeny := newTestHandler(&fakeZotH{}, relAuthz{allow: map[string]bool{}})
	_, err := hDeny.Update(carolCtx(), req)
	require.Equal(t, codes.PermissionDenied, codeOf(t, err))
	require.Equal(t, "changing default visibility to public requires registry admin", statusMsg(err))

	// B11 admin → gate пройден (Update возвращает Operation, не 403).
	hAllow := newTestHandler(&fakeZotH{}, relAuthz{allow: map[string]bool{"admin " + regRef(): true}})
	op, aerr := hAllow.Update(carolCtx(), req)
	require.NoError(t, aerr, "admin проходит gate (B11)")
	require.NotNil(t, op)
}
