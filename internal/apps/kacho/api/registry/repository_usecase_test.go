// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// repository_usecase_test.go — unit-тесты config-overlay Repository use-case (RG-1)
// через mock-порты (RepositoryConfigRepo/ZotClient/RegistryReader). LRO дожидаются
// детерминированно (awaitOpDone). Имена трассируются к acceptance-сценариям RG-1-<G><NN>.
package registry_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	registryv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/registry/v1"

	registry "github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/api/registry"
	"github.com/PRO-Robotech/kacho-registry/internal/domain"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

const regID = "regTEST00000000000000"

// ucWithRegistry — UseCase, где reader.Get отдаёт ACTIVE-реестр с заданным
// default_visibility (inheritance-путь Create/Update/Rename).
func ucWithRegistry(cfg *mockRepoConfig, zot *mockZot, ops *memOps, defVis domain.Visibility) *registry.UseCase {
	repo := &mockRepo{getFn: func(_ context.Context, id string) (*domain.Registry, error) {
		return &domain.Registry{ID: id, ProjectID: "prj-P", Status: domain.RegistryStatusActive, DefaultVisibility: defVis}, nil
	}}
	return newUCWithCfg(repo, cfg, zot, &mockIAM{}, ops)
}

// statusText возвращает message + все field-violation тексты (corelib validate кладёт
// конкретный текст в BadRequest FieldViolation.description, top-message = "invalid
// argument"; parity с Registry). Позволяет assert'ить контракт-текст behaviour-level.
func statusText(err error) string {
	st := status.Convert(err)
	parts := []string{st.Message()}
	for _, d := range st.Proto().GetDetails() {
		parts = append(parts, d.String())
	}
	return strings.Join(parts, " | ")
}

// opResponseRepository декодирует Operation.response в registryv1.Repository.
func opResponseRepository(t *testing.T, resp *anypb.Any) *registryv1.Repository {
	t.Helper()
	require.NotNil(t, resp, "Operation.response не пуст")
	var out registryv1.Repository
	require.NoError(t, resp.UnmarshalTo(&out))
	return &out
}

// RG-1-A01 — CreateRepository пустого durable-repo → Operation → durable, PRIVATE
// (inherited default), tagCount=0, createdAt заполнен; adopt-owner intent эмитирован.
func TestRepository_RG1A01_CreateEmptyDurable(t *testing.T) {
	cfg, zot, ops := newMockCfg(), &mockZot{}, newMemOps()
	uc := ucWithRegistry(cfg, zot, ops, domain.VisibilityPrivate)

	op, err := uc.CreateRepository(aliceCtx(), registry.CreateRepositorySpec{
		RegistryID: regID, Repository: "backend/api",
		Description: "api service images", Labels: map[string]string{"team": "core"},
	})
	require.NoError(t, err)
	done := awaitOpDone(t, ops, op.ID)
	require.Nil(t, done.Error, "happy create — без error")
	repo := opResponseRepository(t, done.Response)
	require.Equal(t, "backend/api", repo.GetName())
	require.Equal(t, registryv1.Visibility_PRIVATE, repo.GetVisibility(), "унаследован PRIVATE default")
	require.Equal(t, "api service images", repo.GetDescription())
	require.Equal(t, int32(0), repo.GetTagCount(), "durable пережил пустоту")
	require.NotNil(t, repo.GetCreatedAt(), "createdAt заполнен")

	// adopt-owner intent эмитирован в той же tx (register RepoPush parent+owner).
	var hasOwner bool
	for _, oi := range cfg.allIntents() {
		if oi.Event == domain.FGAEventRegister && oi.Intent.Kind == "Repository" {
			hasOwner = true
		}
	}
	require.True(t, hasOwner, "adopt-owner register-intent эмитирован (A01)")
}

// RG-1-A02 — дубликат overlay → sync ALREADY_EXISTS "repository already exists".
func TestRepository_RG1A02_CreateDuplicate(t *testing.T) {
	cfg, zot, ops := newMockCfg(), &mockZot{}, newMemOps()
	cfg.byName["backend/api"] = &domain.RepositoryConfig{RegistryID: regID, Name: "backend/api", Visibility: domain.VisibilityPrivate}
	uc := ucWithRegistry(cfg, zot, ops, domain.VisibilityPrivate)

	_, err := uc.CreateRepository(aliceCtx(), registry.CreateRepositorySpec{RegistryID: regID, Repository: "backend/api"})
	st := status.Convert(err)
	require.Equal(t, codes.AlreadyExists, st.Code())
	require.Equal(t, "repository already exists", st.Message())
}

// RG-1-A03 — adopt пред-существующей проекции (pushed content) → durable tagCount=3.
func TestRepository_RG1A03_CreateAdoptProjection(t *testing.T) {
	cfg, ops := newMockCfg(), newMemOps()
	zot := &mockZot{projByName: map[string]*domain.Repository{
		"legacy/app": {RegistryID: regID, Name: "legacy/app", TagCount: 3},
	}}
	uc := ucWithRegistry(cfg, zot, ops, domain.VisibilityPrivate)

	op, err := uc.CreateRepository(aliceCtx(), registry.CreateRepositorySpec{
		RegistryID: regID, Repository: "legacy/app", Labels: map[string]string{"owner": "billing"},
	})
	require.NoError(t, err)
	done := awaitOpDone(t, ops, op.ID)
	require.Nil(t, done.Error)
	repo := opResponseRepository(t, done.Response)
	require.Equal(t, int32(3), repo.GetTagCount(), "adopt существующего контента (A03)")
}

// RG-1-A05 — malformed/пустое имя → INVALID_ARGUMENT (первым стейтментом).
func TestRepository_RG1A05_CreateBadName(t *testing.T) {
	cfg, zot, ops := newMockCfg(), &mockZot{}, newMemOps()
	uc := ucWithRegistry(cfg, zot, ops, domain.VisibilityPrivate)

	_, err := uc.CreateRepository(aliceCtx(), registry.CreateRepositorySpec{RegistryID: regID, Repository: ""})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Contains(t, status.Convert(err).Message(), "repository is required")

	_, err = uc.CreateRepository(aliceCtx(), registry.CreateRepositorySpec{RegistryID: regID, Repository: "Bad Name!"})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Contains(t, status.Convert(err).Message(), "invalid repository name 'Bad Name!'")
}

// RG-1-A06 — malformed registry_id → INVALID_ARGUMENT (первым стейтментом, все RPC).
func TestRepository_RG1A06_BadRegistryID(t *testing.T) {
	cfg, zot, ops := newMockCfg(), &mockZot{}, newMemOps()
	uc := ucWithRegistry(cfg, zot, ops, domain.VisibilityPrivate)
	_, err := uc.CreateRepository(aliceCtx(), registry.CreateRepositorySpec{RegistryID: "not-a-reg-id", Repository: "a/b"})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Contains(t, status.Convert(err).Message(), "invalid registry id 'not-a-reg-id'")
}

// RG-1-A22 — payload-границы: labels 65 / key-64 / value-64, description 257-rune,
// control-char → INVALID_ARGUMENT; multibyte-unicode ≤256 rune → OK round-trip.
func TestRepository_RG1A22_PayloadBounds(t *testing.T) {
	cfg, zot, ops := newMockCfg(), &mockZot{}, newMemOps()
	uc := ucWithRegistry(cfg, zot, ops, domain.VisibilityPrivate)

	tooMany := map[string]string{}
	for i := 0; i < 65; i++ {
		tooMany["k"+string(rune('a'+i%26))+strings.Repeat("x", i)] = "v"
	}
	_, err := uc.CreateRepository(aliceCtx(), registry.CreateRepositorySpec{RegistryID: regID, Repository: "a/b", Labels: tooMany})
	require.Equal(t, codes.InvalidArgument, status.Code(err), "65 labels → InvalidArgument")

	_, err = uc.CreateRepository(aliceCtx(), registry.CreateRepositorySpec{RegistryID: regID, Repository: "a/b", Description: strings.Repeat("x", 257)})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Contains(t, statusText(err), "description length exceeds 256 chars", "corelib parity (field-violation detail)")

	_, err = uc.CreateRepository(aliceCtx(), registry.CreateRepositorySpec{RegistryID: regID, Repository: "a/b", Description: "bad\x00ctl"})
	require.Equal(t, codes.InvalidArgument, status.Code(err), "control-char → InvalidArgument")

	// Валидный multibyte-unicode ≤256 rune → OK, round-trip байт-в-байт.
	unicode := "службы платформы 平台 🚀"
	op, err := uc.CreateRepository(aliceCtx(), registry.CreateRepositorySpec{RegistryID: regID, Repository: "u/svc", Description: unicode})
	require.NoError(t, err)
	done := awaitOpDone(t, ops, op.ID)
	require.Nil(t, done.Error)
	require.Equal(t, unicode, opResponseRepository(t, done.Response).GetDescription(), "unicode round-trip")
}

// RG-1-B12 — inherited PUBLIC на create (default_visibility=PUBLIC) → visibility=PUBLIC
// + public-grant "user:* v_get" intent эмитирован (gate-at-default).
func TestRepository_RG1B12_InheritPublicOnCreate(t *testing.T) {
	cfg, zot, ops := newMockCfg(), &mockZot{}, newMemOps()
	uc := ucWithRegistry(cfg, zot, ops, domain.VisibilityPublic)

	op, err := uc.CreateRepository(aliceCtx(), registry.CreateRepositorySpec{RegistryID: regID, Repository: "open/inherited"})
	require.NoError(t, err)
	done := awaitOpDone(t, ops, op.ID)
	require.Nil(t, done.Error)
	require.Equal(t, registryv1.Visibility_PUBLIC, opResponseRepository(t, done.Response).GetVisibility())
	require.True(t, hasPublicGrant(cfg, domain.FGAEventRegister), "user:* v_get register-intent эмитирован (B12)")
}

// hasPublicGrant — есть ли public-grant (user:* v_get) intent заданного event-type.
func hasPublicGrant(cfg *mockRepoConfig, event string) bool {
	for _, oi := range cfg.allIntents() {
		if oi.Event != event {
			continue
		}
		for _, tp := range oi.Intent.Tuples {
			if tp.SubjectID == domain.FGASubjectPublicWildcard && tp.Relation == domain.FGARelationVGet {
				return true
			}
		}
	}
	return false
}

// RG-1-A07/A08 — GetRepository durable-empty → Repository; absent → NOT_FOUND
// "repository not found" (existence-hiding).
func TestRepository_RG1A07A08_GetRepository(t *testing.T) {
	cfg, zot, ops := newMockCfg(), &mockZot{}, newMemOps()
	cfg.byName["backend/api"] = &domain.RepositoryConfig{RegistryID: regID, Name: "backend/api", Visibility: domain.VisibilityPrivate}
	uc := ucWithRegistry(cfg, zot, ops, domain.VisibilityPrivate)

	repo, err := uc.GetRepository(aliceCtx(), regID, "backend/api")
	require.NoError(t, err)
	require.Equal(t, int32(0), repo.TagCount, "durable-empty")
	require.Equal(t, domain.VisibilityPrivate, repo.Visibility)

	_, err = uc.GetRepository(aliceCtx(), regID, "ghost/svc")
	require.Equal(t, codes.NotFound, status.Code(err))
	require.Equal(t, "repository not found", status.Convert(err).Message(), "existence-hiding (A08)")
}

// RG-1-A10/A11 — UpdateRepository unknown mask → InvalidArgument; immutable "name" в mask
// → каноничный immutable-текст.
func TestRepository_RG1A10A11_UpdateMaskDiscipline(t *testing.T) {
	cfg, zot, ops := newMockCfg(), &mockZot{}, newMemOps()
	cfg.byName["backend/api"] = &domain.RepositoryConfig{RegistryID: regID, Name: "backend/api", Visibility: domain.VisibilityPrivate}
	uc := ucWithRegistry(cfg, zot, ops, domain.VisibilityPrivate)

	_, err := uc.UpdateRepository(aliceCtx(), registry.UpdateRepositorySpec{RegistryID: regID, Repository: "backend/api", Mask: []string{"descriptionx"}})
	require.Equal(t, codes.InvalidArgument, status.Code(err), "unknown mask-field (A10)")

	_, err = uc.UpdateRepository(aliceCtx(), registry.UpdateRepositorySpec{RegistryID: regID, Repository: "backend/api", Mask: []string{"name"}})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Equal(t, "name is immutable after Repository.Create", status.Convert(err).Message(), "A11")
}

// RG-1-A12 — UpdateRepository ephemeral (нет overlay) → auto-promote INSERT (durable).
func TestRepository_RG1A12_UpdatePromoteEphemeral(t *testing.T) {
	cfg, ops := newMockCfg(), newMemOps()
	zot := &mockZot{projByName: map[string]*domain.Repository{"legacy/tool": {RegistryID: regID, Name: "legacy/tool", TagCount: 2}}}
	uc := ucWithRegistry(cfg, zot, ops, domain.VisibilityPrivate)

	op, err := uc.UpdateRepository(aliceCtx(), registry.UpdateRepositorySpec{
		RegistryID: regID, Repository: "legacy/tool", Labels: map[string]string{"archived": "true"}, Mask: []string{"labels"},
	})
	require.NoError(t, err)
	done := awaitOpDone(t, ops, op.ID)
	require.Nil(t, done.Error)
	require.Contains(t, cfg.byName, "legacy/tool", "overlay-строка создана (promote → durable, A12)")
	require.Equal(t, int32(2), opResponseRepository(t, done.Response).GetTagCount())
}

// RG-1-B01/B06 — visibility flip PUBLIC → public-grant register; PRIVATE → unregister.
func TestRepository_RG1B01B06_VisibilityFlipGovernance(t *testing.T) {
	cfg, zot, ops := newMockCfg(), &mockZot{}, newMemOps()
	cfg.byName["public/img"] = &domain.RepositoryConfig{RegistryID: regID, Name: "public/img", Visibility: domain.VisibilityPrivate}
	uc := ucWithRegistry(cfg, zot, ops, domain.VisibilityPrivate)

	op, err := uc.UpdateRepository(aliceCtx(), registry.UpdateRepositorySpec{
		RegistryID: regID, Repository: "public/img", Visibility: domain.VisibilityPublic, Mask: []string{"visibility"},
	})
	require.NoError(t, err)
	require.Nil(t, awaitOpDone(t, ops, op.ID).Error)
	require.True(t, hasPublicGrant(cfg, domain.FGAEventRegister), "flip→PUBLIC эмитит user:* register (B01)")

	cfg2 := newMockCfg()
	cfg2.byName["public/img"] = &domain.RepositoryConfig{RegistryID: regID, Name: "public/img", Visibility: domain.VisibilityPublic}
	ops2 := newMemOps()
	uc2 := ucWithRegistry(cfg2, zot, ops2, domain.VisibilityPrivate)
	op2, err := uc2.UpdateRepository(aliceCtx(), registry.UpdateRepositorySpec{
		RegistryID: regID, Repository: "public/img", Visibility: domain.VisibilityPrivate, Mask: []string{"visibility"},
	})
	require.NoError(t, err)
	require.Nil(t, awaitOpDone(t, ops2, op2.ID).Error)
	require.True(t, hasPublicGrant(cfg2, domain.FGAEventUnregister), "flip→PRIVATE эмитит user:* unregister (B06)")
}

// RG-1-A13/A14 — DeleteRepository пустого → OK; непустого → FAILED_PRECONDITION
// "repository is not empty"; engine-down → UNAVAILABLE (fail-closed).
func TestRepository_RG1A13A14_Delete(t *testing.T) {
	// A13 пустой durable → OK.
	cfg, ops := newMockCfg(), newMemOps()
	cfg.byName["backend/api"] = &domain.RepositoryConfig{RegistryID: regID, Name: "backend/api", Visibility: domain.VisibilityPrivate}
	zot := &mockZot{empty: true}
	uc := ucWithRegistry(cfg, zot, ops, domain.VisibilityPrivate)
	op, err := uc.DeleteRepository(aliceCtx(), regID, "backend/api")
	require.NoError(t, err)
	require.Nil(t, awaitOpDone(t, ops, op.ID).Error)
	require.NotContains(t, cfg.byName, "backend/api", "overlay снят (A13)")

	// A14 непустой → FAILED_PRECONDITION.
	cfg2, ops2 := newMockCfg(), newMemOps()
	cfg2.byName["busy/svc"] = &domain.RepositoryConfig{RegistryID: regID, Name: "busy/svc", Visibility: domain.VisibilityPrivate}
	uc2 := ucWithRegistry(cfg2, &mockZot{empty: false}, ops2, domain.VisibilityPrivate)
	op2, err := uc2.DeleteRepository(aliceCtx(), regID, "busy/svc")
	require.NoError(t, err)
	d2 := awaitOpDone(t, ops2, op2.ID)
	require.NotNil(t, d2.Error)
	require.Equal(t, int32(codes.FailedPrecondition), d2.Error.Code)
	require.Equal(t, "repository is not empty", d2.Error.Message)
	require.Contains(t, cfg2.byName, "busy/svc", "overlay сохранён")

	// A14-note engine-down → UNAVAILABLE fail-closed.
	cfg3, ops3 := newMockCfg(), newMemOps()
	cfg3.byName["down/svc"] = &domain.RepositoryConfig{RegistryID: regID, Name: "down/svc", Visibility: domain.VisibilityPrivate}
	uc3 := ucWithRegistry(cfg3, &mockZot{emptyErr: regerrors.ErrUnavailable}, ops3, domain.VisibilityPrivate)
	op3, err := uc3.DeleteRepository(aliceCtx(), regID, "down/svc")
	require.NoError(t, err)
	require.Equal(t, int32(codes.Unavailable), awaitOpDone(t, ops3, op3.ID).Error.Code, "engine-down → UNAVAILABLE")
	require.Contains(t, cfg3.byName, "down/svc", "overlay не сносим (fail-closed)")
}

// RG-1-A16 — RenameRepository durable → rekey; Get(new) OK, Get(old) NOT_FOUND.
func TestRepository_RG1A16_RenameDurable(t *testing.T) {
	cfg, ops := newMockCfg(), newMemOps()
	cfg.byName["old/name"] = &domain.RepositoryConfig{RegistryID: regID, Name: "old/name", Visibility: domain.VisibilityPrivate, Labels: map[string]string{"k": "v"}}
	zot := &mockZot{}
	uc := ucWithRegistry(cfg, zot, ops, domain.VisibilityPrivate)

	op, err := uc.RenameRepository(aliceCtx(), regID, "old/name", "new/name")
	require.NoError(t, err)
	require.Nil(t, awaitOpDone(t, ops, op.ID).Error)
	require.Contains(t, cfg.byName, "new/name")
	require.NotContains(t, cfg.byName, "old/name")
	require.Len(t, zot.renameCalls, 1, "engine remap вызван old→new")
	require.Equal(t, [3]string{regID, "old/name", "new/name"}, zot.renameCalls[0])
}

// RG-1-A23 — RenameRepository ephemeral (нет overlay) → auto-promote INSERT под new_name.
func TestRepository_RG1A23_RenameEphemeralPromote(t *testing.T) {
	cfg, ops := newMockCfg(), newMemOps()
	zot := &mockZot{projByName: map[string]*domain.Repository{"push/old": {RegistryID: regID, Name: "push/old", TagCount: 2}}}
	uc := ucWithRegistry(cfg, zot, ops, domain.VisibilityPrivate)

	op, err := uc.RenameRepository(aliceCtx(), regID, "push/old", "push/new")
	require.NoError(t, err)
	done := awaitOpDone(t, ops, op.ID)
	require.Nil(t, done.Error)
	require.Contains(t, cfg.byName, "push/new", "auto-promote INSERT под new_name (A23)")
}

// RG-1-A21 — RenameRepository движок недоступен в середине remap → UNAVAILABLE
// fail-closed; overlay-имя НЕ меняется (old резолвится).
func TestRepository_RG1A21_RenameEngineUnavailable(t *testing.T) {
	cfg, ops := newMockCfg(), newMemOps()
	cfg.byName["move/src"] = &domain.RepositoryConfig{RegistryID: regID, Name: "move/src", Visibility: domain.VisibilityPrivate}
	zot := &mockZot{renameErr: regerrors.ErrUnavailable}
	uc := ucWithRegistry(cfg, zot, ops, domain.VisibilityPrivate)

	op, err := uc.RenameRepository(aliceCtx(), regID, "move/src", "move/dst")
	require.NoError(t, err)
	require.Equal(t, int32(codes.Unavailable), awaitOpDone(t, ops, op.ID).Error.Code)
	require.Contains(t, cfg.byName, "move/src", "overlay-имя не изменено (A21)")
	require.NotContains(t, cfg.byName, "move/dst")
}

// RG-1-A17 — RenameRepository целевое имя занято (overlay) → ALREADY_EXISTS.
func TestRepository_RG1A17_RenameCollision(t *testing.T) {
	cfg, ops := newMockCfg(), newMemOps()
	cfg.byName["src/a"] = &domain.RepositoryConfig{RegistryID: regID, Name: "src/a", Visibility: domain.VisibilityPrivate}
	cfg.byName["dst/b"] = &domain.RepositoryConfig{RegistryID: regID, Name: "dst/b", Visibility: domain.VisibilityPrivate}
	uc := ucWithRegistry(cfg, &mockZot{}, ops, domain.VisibilityPrivate)

	op, err := uc.RenameRepository(aliceCtx(), regID, "src/a", "dst/b")
	require.NoError(t, err)
	d := awaitOpDone(t, ops, op.ID)
	require.NotNil(t, d.Error)
	require.Equal(t, int32(codes.AlreadyExists), d.Error.Code)
	require.Equal(t, "repository already exists", d.Error.Message)
}

// RG-1-A19 — RenameRepository malformed newName / no-op → INVALID_ARGUMENT sync-first.
func TestRepository_RG1A19_RenameBadNewName(t *testing.T) {
	cfg, ops := newMockCfg(), newMemOps()
	cfg.byName["app/x"] = &domain.RepositoryConfig{RegistryID: regID, Name: "app/x", Visibility: domain.VisibilityPrivate}
	uc := ucWithRegistry(cfg, &mockZot{}, ops, domain.VisibilityPrivate)

	_, err := uc.RenameRepository(aliceCtx(), regID, "app/x", "Bad Name!")
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Contains(t, status.Convert(err).Message(), "invalid repository name 'Bad Name!'")

	_, err = uc.RenameRepository(aliceCtx(), regID, "app/x", "app/x")
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Equal(t, "new name must differ from current name", status.Convert(err).Message())
}

// RG-1-C01/C03/C04 — ListReferrers: набор → проекции; пусто → []; malformed digest → InvalidArgument.
func TestRepository_RG1C_ListReferrers(t *testing.T) {
	cfg, ops := newMockCfg(), newMemOps()
	zot := &mockZot{referrers: []*domain.Referrer{
		{RegistryID: regID, Repository: "img/app", SubjectDigest: "sha256:" + strings.Repeat("d", 64), Digest: "sha256:" + strings.Repeat("a", 64), ArtifactType: "application/vnd.dev.cosign.simplesigning.v1+json"},
	}}
	uc := ucWithRegistry(cfg, zot, ops, domain.VisibilityPrivate)

	refs, err := uc.ListReferrers(aliceCtx(), registry.ReferrersQuery{RegistryID: regID, Repository: "img/app", SubjectDigest: "sha256:" + strings.Repeat("d", 64)})
	require.NoError(t, err)
	require.Len(t, refs, 1, "C01 referrer-проекция")

	// C03 пусто → [].
	uc2 := ucWithRegistry(newMockCfg(), &mockZot{referrers: []*domain.Referrer{}}, newMemOps(), domain.VisibilityPrivate)
	empty, err := uc2.ListReferrers(aliceCtx(), registry.ReferrersQuery{RegistryID: regID, Repository: "img/app", SubjectDigest: "sha256:" + strings.Repeat("e", 64)})
	require.NoError(t, err)
	require.Empty(t, empty, "C03 нет referrer'ов → [] (не 404)")

	// C04 malformed digest → InvalidArgument.
	_, err = uc.ListReferrers(aliceCtx(), registry.ReferrersQuery{RegistryID: regID, Repository: "img/app", SubjectDigest: "not-a-digest"})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Contains(t, status.Convert(err).Message(), "invalid subject digest 'not-a-digest'")
}

// RG-1-X02 — non-sentineled DB-сбой на overlay-мутации → INTERNAL "internal database
// error"; сырой pgx/driver-текст НЕ течёт (behaviour-level, no-leak).
func TestRepository_RG1X02_InternalNoLeak(t *testing.T) {
	cfg, zot, ops := newMockCfg(), &mockZot{}, newMemOps()
	// Adapter стрипает сырой pgx в ErrInternal ДО use-case; здесь проверяем, что
	// use-case/serviceerr не эхает сырой текст и отдаёт фикс. INTERNAL-сообщение.
	cfg.insertFn = func(_ *domain.RepositoryConfig) (*domain.RepositoryConfig, error) {
		return nil, regerrors.ErrInternal
	}
	uc := ucWithRegistry(cfg, zot, ops, domain.VisibilityPrivate)

	_, err := uc.CreateRepository(aliceCtx(), registry.CreateRepositorySpec{RegistryID: regID, Repository: "x/y"})
	st := status.Convert(err)
	require.Equal(t, codes.Internal, st.Code())
	require.Equal(t, "internal database error", st.Message(), "фикс. INTERNAL-текст")
	require.NotContains(t, st.Message(), "host=")
	require.NotContains(t, st.Message(), "pq:")
}

// guard — sanity, что sentinel-детект в тестах работает (не ошибка компиляции errors).
func TestRepository_sentinelSanity(t *testing.T) {
	require.True(t, errors.Is(regerrors.ErrInternal, regerrors.ErrInternal))
}
