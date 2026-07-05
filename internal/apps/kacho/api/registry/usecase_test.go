// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package registry_test — unit-тесты use-case Registry через mock-порты (CQRS repo
// + zot + iam) и in-memory LRO. Имена тестов трассируются к acceptance-сценариям
// (REG-NN). LRO дожидаются детерминированно (awaitOpDone), не time.Sleep.
package registry_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	registryv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/registry/v1"

	registry "github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/api/registry"
	"github.com/PRO-Robotech/kacho-registry/internal/domain"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// validRegID — well-formed registry id (prefix "reg"); corevalidate.ResourceID
// family-agnostic (проверяет только известный prefix).
const validRegID = "regTEST00000000000000"

func codeOf(t *testing.T, err error) codes.Code {
	t.Helper()
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok, "expected gRPC status, got %v", err)
	return st.Code()
}

// REG-01 — Create happy: Operation(done=false) → poll до done → Registry с prefix
// reg, projectId, status ACTIVE, endpoint "registry.kacho.local/<id>".
func TestRegistry_REG01_Create_HappyPath(t *testing.T) {
	repo := &mockRepo{}
	iam := &mockIAM{}
	ops := newMemOps()
	uc := newUC(repo, &mockZot{}, iam, ops)

	op, err := uc.Create(aliceCtx(), registry.CreateSpec{
		ProjectID: "prj-P", Name: "team-images", Description: "CI images",
		Labels: map[string]string{"env": "prod"},
	})
	require.NoError(t, err)
	require.NotNil(t, op)
	require.False(t, op.Done, "Operation returned done=false")
	require.True(t, iam.called, "ProjectService.Get validated on request-path")

	var meta registryv1.CreateRegistryMetadata
	require.NoError(t, op.Metadata.UnmarshalTo(&meta))
	require.True(t, strings.HasPrefix(meta.GetRegistryId(), "reg"))

	done := awaitOpDone(t, ops, op.ID)
	require.Nil(t, done.Error)
	require.NotNil(t, done.Response)

	var reg registryv1.Registry
	require.NoError(t, done.Response.UnmarshalTo(&reg))
	require.True(t, strings.HasPrefix(reg.GetId(), "reg"))
	require.Equal(t, "prj-P", reg.GetProjectId())
	require.Equal(t, "team-images", reg.GetName())
	require.Equal(t, registryv1.RegistryStatus_REGISTRY_STATUS_ACTIVE, reg.GetStatus())
	require.Equal(t, "registry.kacho.local/"+reg.GetId(), reg.GetEndpoint())
	require.Equal(t, map[string]string{"env": "prod"}, reg.GetLabels())
}

// REG-01/REG-28 — owner-tuple intent: project-tuple ПЕРВЫМ, затем owner-tuple
// (registry_registry object; owner subject из principal).
func TestRegistry_REG28_Create_OwnerTupleIntentOrder(t *testing.T) {
	repo := &mockRepo{}
	ops := newMemOps()
	uc := newUC(repo, &mockZot{}, &mockIAM{}, ops)

	op, err := uc.Create(aliceCtx(), registry.CreateSpec{ProjectID: "prj-P", Name: "team-images"})
	require.NoError(t, err)
	awaitOpDone(t, ops, op.ID)

	require.Len(t, repo.insertIntent.Tuples, 2, "project + owner tuple")
	// project-tuple ПЕРВЫМ (grabli listener-visibility).
	require.Equal(t, domain.FGARelationProject, repo.insertIntent.Tuples[0].Relation)
	require.Equal(t, "project:prj-P", repo.insertIntent.Tuples[0].SubjectID)
	require.True(t, strings.HasPrefix(repo.insertIntent.Tuples[0].Object, "registry_registry:reg"))
	// owner-tuple вторым, subject из principal.
	require.Equal(t, domain.FGARelationOwner, repo.insertIntent.Tuples[1].Relation)
	require.Equal(t, "user:usr-alice", repo.insertIntent.Tuples[1].SubjectID)
	require.Equal(t, "prj-P", repo.insertIntent.ParentProjectID)
}

// REG-02 — invalid input → синхронный INVALID_ARGUMENT; Insert НЕ вызывается.
func TestRegistry_REG02_Create_InvalidName(t *testing.T) {
	cases := map[string]string{
		"empty":           "",
		"uppercase_score": "Team_Images",
		"too_long":        strings.Repeat("a", 256),
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			repo := &mockRepo{}
			iam := &mockIAM{}
			uc := newUC(repo, &mockZot{}, iam, newMemOps())
			_, err := uc.Create(aliceCtx(), registry.CreateSpec{ProjectID: "prj-P", Name: value})
			require.Equal(t, codes.InvalidArgument, codeOf(t, err))
			require.Nil(t, repo.insertReg, "no row inserted")
			require.False(t, iam.called, "project not checked before validation")
		})
	}
}

// REG-03 — project не существует → cross-domain reject INVALID_ARGUMENT; edge iam
// недоступен → UNAVAILABLE (fail-closed). Insert НЕ вызывается.
func TestRegistry_REG03_Create_CrossDomainProject(t *testing.T) {
	t.Run("not_found", func(t *testing.T) {
		repo := &mockRepo{}
		iam := &mockIAM{projectFn: func(context.Context, string) error { return regerrors.ErrInvalidArg }}
		uc := newUC(repo, &mockZot{}, iam, newMemOps())
		_, err := uc.Create(aliceCtx(), registry.CreateSpec{ProjectID: "prj-NOPE", Name: "x"})
		require.Equal(t, codes.InvalidArgument, codeOf(t, err))
		require.Contains(t, status.Convert(err).Message(), "prj-NOPE")
		require.Nil(t, repo.insertReg)
	})
	t.Run("iam_unavailable_fail_closed", func(t *testing.T) {
		repo := &mockRepo{}
		iam := &mockIAM{projectFn: func(context.Context, string) error { return regerrors.ErrUnavailable }}
		uc := newUC(repo, &mockZot{}, iam, newMemOps())
		_, err := uc.Create(aliceCtx(), registry.CreateSpec{ProjectID: "prj-P", Name: "x"})
		require.Equal(t, codes.Unavailable, codeOf(t, err))
		require.Nil(t, repo.insertReg)
	})
}

// REG-04 — дубликат имени → синхронный ALREADY_EXISTS с именем (partial UNIQUE
// backstop транслируется репозиторием в ErrAlreadyExists).
func TestRegistry_REG04_Create_DuplicateName(t *testing.T) {
	repo := &mockRepo{insertFn: func(context.Context, *domain.Registry, domain.RegisterIntent) (*domain.Registry, error) {
		return nil, regerrors.ErrAlreadyExists
	}}
	uc := newUC(repo, &mockZot{}, &mockIAM{}, newMemOps())
	_, err := uc.Create(aliceCtx(), registry.CreateSpec{ProjectID: "prj-P", Name: "team-images"})
	require.Equal(t, codes.AlreadyExists, codeOf(t, err))
	require.Contains(t, status.Convert(err).Message(), "team-images")
}

// REG-01 ordering (CWE-662) — pending-Operation персистится ДО durable INSERT
// ресурса. Если создание Operation-envelope падает, реестр НЕ должен оказаться
// закоммиченным без сопутствующей Operation (cross-transaction partial write):
// writer.Insert не вызывается вовсе, Create возвращает ошибку. Инвертированный
// порядок (Insert раньше Operation) оставил бы осиротевший ресурс без envelope.
func TestRegistry_REG01_Create_OperationBeforeInsert(t *testing.T) {
	repo := &mockRepo{}
	ops := newMemOps()
	ops.createErr = regerrors.ErrUnavailable // персист pending-Operation падает
	uc := newUC(repo, &mockZot{}, &mockIAM{}, ops)

	_, err := uc.Create(aliceCtx(), registry.CreateSpec{ProjectID: "prj-P", Name: "team-images"})
	require.Error(t, err)
	require.Nil(t, repo.insertReg, "resource must NOT be inserted when Operation-envelope create fails")
}

// REG-05 — Get: malformed id → INVALID_ARGUMENT первым стейтментом; well-formed-но-нет
// → NOT_FOUND.
func TestRegistry_REG05_Get(t *testing.T) {
	t.Run("malformed_id", func(t *testing.T) {
		uc := newUC(&mockRepo{}, &mockZot{}, &mockIAM{}, newMemOps())
		_, err := uc.Get(context.Background(), "not-an-id")
		require.Equal(t, codes.InvalidArgument, codeOf(t, err))
		require.Contains(t, status.Convert(err).Message(), "invalid registry id")
	})
	t.Run("not_found", func(t *testing.T) {
		repo := &mockRepo{getFn: func(context.Context, string) (*domain.Registry, error) {
			return nil, regerrors.ErrNotFound
		}}
		uc := newUC(repo, &mockZot{}, &mockIAM{}, newMemOps())
		_, err := uc.Get(context.Background(), validRegID)
		require.Equal(t, codes.NotFound, codeOf(t, err))
	})
}

// REG-06 — List: garbage page_size → INVALID_ARGUMENT (не silent fallback).
func TestRegistry_REG06_List_PageSizeValidation(t *testing.T) {
	uc := newUC(&mockRepo{}, &mockZot{}, &mockIAM{}, newMemOps())
	_, _, err := uc.List(context.Background(), registry.ListQuery{ProjectID: "prj-P", PageSize: 5000})
	require.Equal(t, codes.InvalidArgument, codeOf(t, err))
}

// REG-36 — update_mask discipline: immutable project → INVALID_ARGUMENT с
// каноничным текстом (без Operation); unknown → INVALID_ARGUMENT. name — mutable
// (см. TestRegistry_REG36_Update_MutableFields).
func TestRegistry_REG36_Update_MaskDiscipline(t *testing.T) {
	cases := []struct {
		name string
		mask []string
		msg  string
	}{
		{"immutable_project", []string{"project_id"}, "projectId is immutable after Registry.Create"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := &mockRepo{}
			uc := newUC(repo, &mockZot{}, &mockIAM{}, newMemOps())
			_, err := uc.Update(aliceCtx(), registry.UpdateSpec{RegistryID: validRegID, Mask: tc.mask})
			require.Equal(t, codes.InvalidArgument, codeOf(t, err))
			require.Equal(t, tc.msg, status.Convert(err).Message())
		})
	}
	t.Run("unknown_field", func(t *testing.T) {
		uc := newUC(&mockRepo{}, &mockZot{}, &mockIAM{}, newMemOps())
		_, err := uc.Update(aliceCtx(), registry.UpdateSpec{RegistryID: validRegID, Mask: []string{"bogus"}})
		require.Equal(t, codes.InvalidArgument, codeOf(t, err))
	})
	t.Run("malformed_id", func(t *testing.T) {
		uc := newUC(&mockRepo{}, &mockZot{}, &mockIAM{}, newMemOps())
		_, err := uc.Update(aliceCtx(), registry.UpdateSpec{RegistryID: "bad-id", Mask: []string{"labels"}})
		require.Equal(t, codes.InvalidArgument, codeOf(t, err))
	})
}

// REG-36 — mutable Update: mask {labels,description} → Apply-флаги; mirror-intent
// несёт обновлённые labels (label-clear реально отзывает scope). empty-mask →
// full-object PATCH (оба поля применяются).
func TestRegistry_REG36_Update_MutableFields(t *testing.T) {
	t.Run("explicit_mask", func(t *testing.T) {
		repo := &mockRepo{updateFn: func(_ context.Context, spec registry.UpdateSpec, mirror func(*domain.Registry) domain.RegisterIntent) (*domain.Registry, error) {
			updated := &domain.Registry{ID: spec.RegistryID, ProjectID: "prj-P", Name: "team-images",
				Description: spec.Description, Labels: spec.Labels, Status: domain.RegistryStatusActive}
			// mirror-intent строится из обновлённой строки → новые labels.
			mi := mirror(updated)
			require.Equal(t, spec.Labels, mi.Labels)
			return updated, nil
		}}
		ops := newMemOps()
		uc := newUC(repo, &mockZot{}, &mockIAM{}, ops)
		op, err := uc.Update(aliceCtx(), registry.UpdateSpec{
			RegistryID: validRegID, Mask: []string{"labels", "description"},
			Labels: map[string]string{"env": "staging"}, Description: "staging CI",
		})
		require.NoError(t, err)
		awaitOpDone(t, ops, op.ID)
		require.True(t, repo.updateSpec.ApplyLabels)
		require.True(t, repo.updateSpec.ApplyDescription)
	})
	t.Run("empty_mask_full_patch", func(t *testing.T) {
		repo := &mockRepo{}
		ops := newMemOps()
		uc := newUC(repo, &mockZot{}, &mockIAM{}, ops)
		op, err := uc.Update(aliceCtx(), registry.UpdateSpec{RegistryID: validRegID, Mask: nil})
		require.NoError(t, err)
		awaitOpDone(t, ops, op.ID)
		require.True(t, repo.updateSpec.ApplyLabels, "empty mask → full PATCH")
		require.True(t, repo.updateSpec.ApplyDescription, "empty mask → full PATCH")
	})
	t.Run("label_clear", func(t *testing.T) {
		// mask=[labels], пустая карта → метки очищаются (ApplyLabels=true, Labels empty).
		repo := &mockRepo{}
		ops := newMemOps()
		uc := newUC(repo, &mockZot{}, &mockIAM{}, ops)
		op, err := uc.Update(aliceCtx(), registry.UpdateSpec{
			RegistryID: validRegID, Mask: []string{"labels"}, Labels: map[string]string{},
		})
		require.NoError(t, err)
		awaitOpDone(t, ops, op.ID)
		require.True(t, repo.updateSpec.ApplyLabels)
		require.Empty(t, repo.updateSpec.Labels)
	})
	t.Run("name_mutable", func(t *testing.T) {
		// mask=[name] с валидным DNS-safe именем → ApplyName, репозиторий SET name.
		repo := &mockRepo{}
		ops := newMemOps()
		uc := newUC(repo, &mockZot{}, &mockIAM{}, ops)
		op, err := uc.Update(aliceCtx(), registry.UpdateSpec{
			RegistryID: validRegID, Mask: []string{"name"}, Name: "renamed-registry",
		})
		require.NoError(t, err)
		awaitOpDone(t, ops, op.ID)
		require.True(t, repo.updateSpec.ApplyName)
		require.Equal(t, "renamed-registry", repo.updateSpec.Name)
		require.False(t, repo.updateSpec.ApplyDescription, "mask=[name] не трогает description")
	})
	t.Run("name_invalid_dns", func(t *testing.T) {
		// невалидное имя (uppercase/underscore) → InvalidArgument (те же правила, что Create).
		uc := newUC(&mockRepo{}, &mockZot{}, &mockIAM{}, newMemOps())
		_, err := uc.Update(aliceCtx(), registry.UpdateSpec{
			RegistryID: validRegID, Mask: []string{"name"}, Name: "Bad_Name",
		})
		require.Equal(t, codes.InvalidArgument, codeOf(t, err))
	})
	t.Run("empty_mask_applies_name_when_provided", func(t *testing.T) {
		// full-object PATCH с непустым именем → ApplyName; без имени — не трогает name.
		repo := &mockRepo{}
		ops := newMemOps()
		uc := newUC(repo, &mockZot{}, &mockIAM{}, ops)
		op, err := uc.Update(aliceCtx(), registry.UpdateSpec{RegistryID: validRegID, Name: "patched-name"})
		require.NoError(t, err)
		awaitOpDone(t, ops, op.ID)
		require.True(t, repo.updateSpec.ApplyName)
		require.Equal(t, "patched-name", repo.updateSpec.Name)
	})
}

// REG-27 — worker-principal propagation: async Update-worker обязан пробросить
// principal в worker-ctx (baggage.Extract режет его), иначе downstream/peer-вызовы
// уходят анонимно (authz_no_principal). writer.Update должен получить ctx с
// principal вызывающего (usr-alice), а не system/bootstrap-fallback.
func TestRegistry_REG27_Update_WorkerPrincipalPropagated(t *testing.T) {
	repo := &mockRepo{}
	ops := newMemOps()
	uc := newUC(repo, &mockZot{}, &mockIAM{}, ops)

	op, err := uc.Update(aliceCtx(), registry.UpdateSpec{
		RegistryID: validRegID, Mask: []string{"description"}, Description: "x",
	})
	require.NoError(t, err)
	awaitOpDone(t, ops, op.ID)

	require.Equal(t, "user", repo.updatePrincipal.Type, "worker-ctx несёт principal вызывающего, не system")
	require.Equal(t, "usr-alice", repo.updatePrincipal.ID)
}

// REG-07 — Delete happy: Operation → poll до done без error; zot-namespace снят;
// unregister-intent (project-tuple) эмитится.
func TestRegistry_REG07_Delete_HappyPath(t *testing.T) {
	zot := &mockZot{namespaceEmpty: true} // пустой namespace → Delete проходит precondition
	repo := &mockRepo{
		markFn: func(_ context.Context, id string) (*domain.Registry, error) {
			return &domain.Registry{ID: id, ProjectID: "prj-P", Status: domain.RegistryStatusDeleting}, nil
		},
	}
	ops := newMemOps()
	uc := newUC(repo, zot, &mockIAM{}, ops)

	op, err := uc.Delete(aliceCtx(), validRegID)
	require.NoError(t, err)
	done := awaitOpDone(t, ops, op.ID)
	require.Nil(t, done.Error)

	require.Contains(t, zot.removedNS, validRegID, "zot namespace removal attempted")
	require.Len(t, repo.deleteIntent.Tuples, 1)
	require.Equal(t, domain.FGARelationProject, repo.deleteIntent.Tuples[0].Relation)
}

// REG-09 — Delete idempotent: строка уже удалена (MarkDeleting → ErrNotFound) →
// Operation завершается идемпотентным done без второго destructive Delete.
func TestRegistry_REG09_Delete_Idempotent(t *testing.T) {
	deleted := false
	repo := &mockRepo{
		markFn:   func(context.Context, string) (*domain.Registry, error) { return nil, regerrors.ErrNotFound },
		deleteFn: func(context.Context, string, domain.RegisterIntent) error { deleted = true; return nil },
	}
	ops := newMemOps()
	uc := newUC(repo, &mockZot{namespaceEmpty: true}, &mockIAM{}, ops)

	op, err := uc.Delete(aliceCtx(), validRegID)
	require.NoError(t, err)
	done := awaitOpDone(t, ops, op.ID)
	require.Nil(t, done.Error, "idempotent done, not error")
	require.False(t, deleted, "no second destructive Delete on already-deleted resource")
}

// REG-08-TOCTOU — контент дозалился в окне между sync empty-check и async worker'ом:
// worker re-check'ает NamespaceEmpty ПОСЛЕ CAS→DELETING и аборт'ит удаление, если
// namespace снова непуст. Строка НЕ удаляется, unregister-intent НЕ эмитится →
// authz-tuple'ы контента сохранены (не осиротили zot-контент).
func TestRegistry_REG08_Delete_RechecksEmptinessInWorker(t *testing.T) {
	deleted := false
	repo := &mockRepo{
		markFn: func(_ context.Context, id string) (*domain.Registry, error) {
			return &domain.Registry{ID: id, ProjectID: "prj-P", Status: domain.RegistryStatusDeleting}, nil
		},
		deleteFn: func(context.Context, string, domain.RegisterIntent) error { deleted = true; return nil },
	}
	// sync-check: пусто (Delete принят) → worker-recheck: НЕпусто (контент дозалился).
	zot := &mockZot{namespaceEmptySeq: []bool{true, false}}
	ops := newMemOps()
	uc := newUC(repo, zot, &mockIAM{}, ops)

	op, err := uc.Delete(aliceCtx(), validRegID)
	require.NoError(t, err, "sync empty-check passes → op accepted")
	done := awaitOpDone(t, ops, op.ID)

	require.NotNil(t, done.Error, "worker aborts delete: content reappeared")
	require.Equal(t, int32(codes.FailedPrecondition), done.Error.Code)
	require.False(t, deleted, "row NOT physically deleted when content reappeared")
	require.Empty(t, repo.deleteIntent.Tuples, "no unregister-intent emitted")
}

// REG-05/07 — malformed id на мутациях → синхронный INVALID_ARGUMENT (без Operation).
func TestRegistry_Delete_MalformedID(t *testing.T) {
	uc := newUC(&mockRepo{}, &mockZot{}, &mockIAM{}, newMemOps())
	_, err := uc.Delete(context.Background(), "not-an-id")
	require.Equal(t, codes.InvalidArgument, codeOf(t, err))
}
