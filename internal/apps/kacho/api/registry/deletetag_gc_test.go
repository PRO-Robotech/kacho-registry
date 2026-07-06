// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package registry_test — unit-тесты async-мутаций проекции zot (DeleteTag, GC) и
// sync-precondition непустого Delete. Authz этих RPC (existence-hiding, per-repo
// row-filter) живёт в handler-слое; здесь проверяется use-case-механика LRO,
// проброс principal в worker и fail-closed на недоступность zot. REG-08/25/27/38.
package registry_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-registry/internal/domain"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// REG-25/REG-27 — DeleteTag happy: async Operation → worker (с проброшенным
// principal) зовёт zot.DeleteTag(registryID, repository, tag); полл до done без error.
func TestRegistry_REG25_DeleteTag_HappyPath(t *testing.T) {
	zot := &mockZot{}
	ops := newMemOps()
	uc := newUC(&mockRepo{}, zot, &mockIAM{}, ops)

	op, err := uc.DeleteTag(aliceCtx(), validRegID, "app", "v1")
	require.NoError(t, err)
	require.NotNil(t, op)
	require.False(t, op.Done, "async: Operation returned done=false")

	done := awaitOpDone(t, ops, op.ID)
	require.Nil(t, done.Error)

	require.Len(t, zot.deleteTagCall, 1)
	call := zot.deleteTagCall[0]
	require.Equal(t, validRegID, call.registryID)
	require.Equal(t, "app", call.repository)
	require.Equal(t, "v1", call.tag)
	// REG-27: worker не уходит анонимно — principal проброшен в worker-ctx.
	require.Equal(t, "usr-alice", call.principal.ID)
	require.Equal(t, "user", call.principal.Type)
}

// REG-25 (imp-4) — DeleteTag последнего тега repo: после удаления repo пуст
// (ListTags == []) → worker эмитит UnregisterResource-intent на
// registry_repository:<reg>/<repo> (не оставлять висячий authz-объект).
func TestRegistry_REG25_DeleteTag_UnregisterOnLastTag(t *testing.T) {
	zot := &mockZot{listTagsResult: nil} // после удаления тегов не осталось
	ops := newMemOps()
	reg := &mockRepoReg{}
	uc := newUCWithReg(&mockRepo{}, zot, &mockIAM{}, ops, reg)

	op, err := uc.DeleteTag(aliceCtx(), validRegID, "app", "v1")
	require.NoError(t, err)
	done := awaitOpDone(t, ops, op.ID)
	require.Nil(t, done.Error)

	reg.mu.Lock()
	defer reg.mu.Unlock()
	require.Len(t, reg.unregisterIntent, 1, "last-tag removal emits repo unregister-intent")
	intent := reg.unregisterIntent[0]
	require.Equal(t, "Repository", intent.Kind)
	require.Equal(t, validRegID+"/app", intent.ResourceID)
	require.NotEmpty(t, intent.Tuples)
	// parent-tuple снимается: registry_repository:<reg>/app #parent @registry_registry:<reg>.
	require.Equal(t, "registry_repository:"+validRegID+"/app", intent.Tuples[0].Object)
	require.Equal(t, "parent", intent.Tuples[0].Relation)
}

// REG-25 (imp-4) — DeleteTag НЕ последнего тега: repo ещё содержит теги
// (ListTags != []) → unregister-intent НЕ эмитится (authz-объект жив).
func TestRegistry_REG25_DeleteTag_TagsRemain_NoUnregister(t *testing.T) {
	zot := &mockZot{listTagsResult: []*domain.Tag{{Tag: "v2"}}} // остаётся v2
	ops := newMemOps()
	reg := &mockRepoReg{}
	uc := newUCWithReg(&mockRepo{}, zot, &mockIAM{}, ops, reg)

	op, err := uc.DeleteTag(aliceCtx(), validRegID, "app", "v1")
	require.NoError(t, err)
	done := awaitOpDone(t, ops, op.ID)
	require.Nil(t, done.Error)

	reg.mu.Lock()
	defer reg.mu.Unlock()
	require.Empty(t, reg.unregisterIntent, "repo still has tags → no unregister")
}

// REG-25 (imp-4) — DeleteTag worker: zot.DeleteTag прошёл, но чтение остатка тегов
// (ListTags) упало (zot недоступен) → unregisterRepoIfEmpty пробрасывает ошибку,
// Operation завершается С error, и unregister-intent НЕ эмитится (нельзя снимать
// authz-объект при НЕИЗВЕСТНОМ числе тегов — иначе dangling authz на живом repo).
// Пинит ветку deletetag.go:79 (ранее listTagsErr был объявлен в mock, но не покрыт).
func TestRegistry_REG25_DeleteTag_ListTagsError_NoUnregister(t *testing.T) {
	zot := &mockZot{listTagsErr: regerrors.ErrUnavailable} // DeleteTag ok, ListTags fail-closed
	ops := newMemOps()
	reg := &mockRepoReg{}
	uc := newUCWithReg(&mockRepo{}, zot, &mockIAM{}, ops, reg)

	op, err := uc.DeleteTag(aliceCtx(), validRegID, "app", "v1")
	require.NoError(t, err)
	done := awaitOpDone(t, ops, op.ID)
	require.NotNil(t, done.Error, "ListTags read failure must surface in Operation.error")
	require.Equal(t, int32(codes.Unavailable), done.Error.GetCode(),
		"mapped gRPC code preserved (mapRepoErr, not swallowed/mismapped)")

	reg.mu.Lock()
	defer reg.mu.Unlock()
	require.Empty(t, reg.unregisterIntent,
		"unknown tag count must not strip the repo authz-object (no unregister on ListTags error)")
}

// REG-25 — DeleteTag: malformed registry id / пустые repo|tag → синхронный
// INVALID_ARGUMENT (Operation НЕ создаётся, zot не трогается).
func TestRegistry_REG25_DeleteTag_SyncValidation(t *testing.T) {
	cases := []struct {
		name       string
		registryID string
		repo       string
		tag        string
	}{
		{"malformed_id", "not-an-id", "app", "v1"},
		{"empty_repo", validRegID, "", "v1"},
		{"empty_tag", validRegID, "app", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			zot := &mockZot{}
			uc := newUC(&mockRepo{}, zot, &mockIAM{}, newMemOps())
			_, err := uc.DeleteTag(aliceCtx(), tc.registryID, tc.repo, tc.tag)
			require.Equal(t, codes.InvalidArgument, codeOf(t, err))
			require.Empty(t, zot.deleteTagCall, "zot not touched on sync-reject")
		})
	}
}

// REG-25 — DeleteTag worker: zot вернул ошибку → Operation завершается с error
// (worker-ошибка не глушится, клиент видит причину через polling).
func TestRegistry_REG25_DeleteTag_WorkerZotError(t *testing.T) {
	zot := &mockZot{deleteTagErr: regerrors.ErrUnavailable}
	ops := newMemOps()
	uc := newUC(&mockRepo{}, zot, &mockIAM{}, ops)

	op, err := uc.DeleteTag(aliceCtx(), validRegID, "app", "v1")
	require.NoError(t, err)
	done := awaitOpDone(t, ops, op.ID)
	require.NotNil(t, done.Error, "worker zot-failure surfaced in Operation.error")
}

// REG-38 — TriggerGC happy: async Operation → worker (с principal) зовёт
// zot.TriggerGC(registryID); полл до done. Идемпотентен (повторный вызов безопасен).
func TestRegistry_REG38_TriggerGC_HappyPath(t *testing.T) {
	zot := &mockZot{}
	ops := newMemOps()
	uc := newUC(&mockRepo{}, zot, &mockIAM{}, ops)

	op, err := uc.TriggerGC(aliceCtx(), validRegID)
	require.NoError(t, err)
	require.False(t, op.Done)

	done := awaitOpDone(t, ops, op.ID)
	require.Nil(t, done.Error)
	require.Contains(t, zot.triggerGCCalls, validRegID)
}

// REG-38 — TriggerGC malformed id → синхронный INVALID_ARGUMENT.
func TestRegistry_REG38_TriggerGC_MalformedID(t *testing.T) {
	uc := newUC(&mockRepo{}, &mockZot{}, &mockIAM{}, newMemOps())
	_, err := uc.TriggerGC(context.Background(), "bad-id")
	require.Equal(t, codes.InvalidArgument, codeOf(t, err))
}

// REG-38 — TriggerGC worker zot-failure: async worker'а zot.TriggerGC вернул ошибку →
// Operation завершается done=true С НЕПУСТЫМ error (не «тихий success»), код проброшен
// через mapRepoErr без mismap/leak. Mirror REG-25 DeleteTag_WorkerZotError — раньше
// GC-worker error-ветка не покрывалась (регрессия «emptyAny() вместо mapped error»
// прошла бы незамеченной).
func TestRegistry_REG38_TriggerGC_WorkerZotError(t *testing.T) {
	zot := &mockZot{triggerGCErr: regerrors.ErrUnavailable}
	ops := newMemOps()
	uc := newUC(&mockRepo{}, zot, &mockIAM{}, ops)

	op, err := uc.TriggerGC(aliceCtx(), validRegID)
	require.NoError(t, err)
	done := awaitOpDone(t, ops, op.ID)
	require.NotNil(t, done.Error, "worker GC zot-failure must surface in Operation.error, not silent success")
	require.Equal(t, int32(codes.Unavailable), done.Error.GetCode(),
		"mapped gRPC code preserved (mapRepoErr, not swallowed/mismapped)")
	require.Contains(t, zot.triggerGCCalls, validRegID)
}

// REG-08 — Delete непустого namespace: sync-precondition читает zot.NamespaceEmpty;
// НЕ пусто → FAILED_PRECONDITION "registry is not empty"; Operation НЕ создаётся,
// namespace/строка не трогаются (status остаётся ACTIVE, worker не запускается).
func TestRegistry_REG08_Delete_NonEmpty_FailedPrecondition(t *testing.T) {
	zot := &mockZot{namespaceEmpty: false} // namespace НЕ пуст
	repo := &mockRepo{}
	uc := newUC(repo, zot, &mockIAM{}, newMemOps())

	_, err := uc.Delete(aliceCtx(), validRegID)
	require.Equal(t, codes.FailedPrecondition, codeOf(t, err))
	require.Equal(t, "registry is not empty", status.Convert(err).Message())
	require.Empty(t, zot.removedNS, "namespace not touched")
}

// REG-08 edge — zot недоступен при проверке непустоты → sync UNAVAILABLE
// (fail-closed: НЕ «считаем пустым и удаляем»).
func TestRegistry_REG08_Delete_ZotUnavailable_FailClosed(t *testing.T) {
	zot := &mockZot{namespaceEmptyErr: regerrors.ErrUnavailable}
	uc := newUC(&mockRepo{}, zot, &mockIAM{}, newMemOps())

	_, err := uc.Delete(aliceCtx(), validRegID)
	require.Equal(t, codes.Unavailable, codeOf(t, err))
	require.Empty(t, zot.removedNS, "namespace not touched when precondition fails closed")
}
