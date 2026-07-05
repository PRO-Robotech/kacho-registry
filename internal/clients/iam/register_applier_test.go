// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-corelib/outbox/drainer"
	iamv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-registry/internal/domain"
)

// scriptedRegisterClient — fake RegisterResourceClient, записывающий каждый вызов
// и скриптующий per-call gRPC-ответ (errs[i] для i-го вызова, nil если i вне slice).
type scriptedRegisterClient struct {
	registerReqs []*iamv1.RegisterResourceRequest
	registerErrs []error

	unregisterReqs []*iamv1.UnregisterResourceRequest
	unregisterErrs []error
}

func (f *scriptedRegisterClient) RegisterResource(
	_ context.Context, in *iamv1.RegisterResourceRequest, _ ...grpc.CallOption,
) (*iamv1.RegisterResourceResponse, error) {
	idx := len(f.registerReqs)
	f.registerReqs = append(f.registerReqs, in)
	if idx < len(f.registerErrs) {
		return nil, f.registerErrs[idx]
	}
	return &iamv1.RegisterResourceResponse{}, nil
}

func (f *scriptedRegisterClient) UnregisterResource(
	_ context.Context, in *iamv1.UnregisterResourceRequest, _ ...grpc.CallOption,
) (*iamv1.UnregisterResourceResponse, error) {
	idx := len(f.unregisterReqs)
	f.unregisterReqs = append(f.unregisterReqs, in)
	if idx < len(f.unregisterErrs) {
		return nil, f.unregisterErrs[idx]
	}
	return &iamv1.UnregisterResourceResponse{}, nil
}

// objects extracts the object strings of every recorded RegisterResource call in
// call order — the assertion surface for "which tuples were actually attempted".
func (f *scriptedRegisterClient) registerObjects() []string {
	out := make([]string, 0, len(f.registerReqs))
	for _, r := range f.registerReqs {
		out = append(out, r.GetObject())
	}
	return out
}

// TestRegisterApplier_PartialApplyRetry_OwnerTupleNotDropped — regression для
// HIGH-находки: ErrAlreadyApplied на РАННЕМ tuple мульти-tuple intent'а не должен
// short-circuit'ить остаток набора при retry-after-partial-apply.
//
// Сценарий: RegisterIntentForCreate даёт [project-tuple, owner-tuple]. На повторе
// (attempt 2) project-tuple уже применён → iam отвечает AlreadyExists; owner-tuple
// ещё НЕ применён и должен быть отправлен. Багованный applier возвращал
// ErrAlreadyApplied сразу после project-tuple → owner-tuple терялся навсегда.
func TestRegisterApplier_PartialApplyRetry_OwnerTupleNotDropped(t *testing.T) {
	intent := domain.RegisterIntentForCreate(
		&domain.Registry{ID: "reg-1", ProjectID: "prj-1"}, "user", "usr-abc")
	require.Len(t, intent.Tuples, 2, "intent must carry project-tuple + owner-tuple")

	fake := &scriptedRegisterClient{
		// attempt-2 повтор: 1-й вызов (project-tuple) уже применён → AlreadyExists;
		// 2-й вызов (owner-tuple) — nil (реальная работа).
		registerErrs: []error{status.Error(codes.AlreadyExists, "duplicate tuple")},
	}
	applier := NewRegisterApplier(fake)

	err := applier(context.Background(), domain.FGAEventRegister, intent)
	require.NoError(t, err, "at least one tuple did real work → non-terminal-error success")

	require.Len(t, fake.registerReqs, 2,
		"BOTH tuples must be attempted on retry; owner-tuple must not be dropped")
	ownerObj := domain.FGAObjectRef(domain.FGAObjectTypeRegistry, "reg-1")
	assert.Contains(t, fake.registerObjects(), ownerObj,
		"owner-tuple object must have been sent to iam")
	// Оба tuple на один и тот же object (registry_registry:reg-1); проверяем, что
	// среди отправленных есть owner-relation (не только project-relation).
	var sawOwner bool
	for _, r := range fake.registerReqs {
		if r.GetRelation() == domain.FGARelationOwner {
			sawOwner = true
		}
	}
	assert.True(t, sawOwner, "owner-relation tuple must have been sent on retry")
}

// TestUnregisterApplier_PartialApplyRetry_AllTuplesAttempted — та же регрессия на
// unregister-ветке (line 116): ErrAlreadyApplied (AlreadyExists) на первом tuple
// не должен обрывать остаток.
func TestUnregisterApplier_PartialApplyRetry_AllTuplesAttempted(t *testing.T) {
	intent := domain.RegisterIntent{
		Kind:       "Registry",
		ResourceID: "reg-9",
		Tuples: []domain.FGATuple{
			domain.FGAProjectTuple("reg-9", "prj-9"),
			domain.FGAOwnerTuple("user:usr-z", "reg-9"),
		},
	}
	fake := &scriptedRegisterClient{
		unregisterErrs: []error{status.Error(codes.AlreadyExists, "already gone")},
	}
	applier := NewRegisterApplier(fake)

	err := applier(context.Background(), domain.FGAEventUnregister, intent)
	require.NoError(t, err)
	require.Len(t, fake.unregisterReqs, 2, "both tuples must be attempted on unregister retry")
}

// TestRegisterApplier_AllTuplesAlreadyApplied_ReturnsAlreadyApplied — когда КАЖДЫЙ
// tuple уже применён (нулевая реальная работа), applier обязан вернуть терминальный
// ErrAlreadyApplied (drainer → sent_at), а не nil, чтобы classify-метрика оставалась
// точной. Все tuple при этом всё равно должны быть опрошены.
func TestRegisterApplier_AllTuplesAlreadyApplied_ReturnsAlreadyApplied(t *testing.T) {
	intent := domain.RegisterIntentForCreate(
		&domain.Registry{ID: "reg-2", ProjectID: "prj-2"}, "user", "usr-x")
	require.Len(t, intent.Tuples, 2)

	fake := &scriptedRegisterClient{
		registerErrs: []error{
			status.Error(codes.AlreadyExists, "dup"),
			status.Error(codes.AlreadyExists, "dup"),
		},
	}
	applier := NewRegisterApplier(fake)

	err := applier(context.Background(), domain.FGAEventRegister, intent)
	require.Error(t, err)
	assert.True(t, errors.Is(err, drainer.ErrAlreadyApplied),
		"all-already-applied must surface terminal ErrAlreadyApplied, got %v", err)
	require.Len(t, fake.registerReqs, 2, "all tuples opined even when all already applied")
}

// TestRegisterApplier_PermanentOnLaterTuple_StopsAndPoisons — ErrPermanent
// (InvalidArgument) на любом tuple немедленно прекращает обработку и всплывает как
// permanent (poison), даже если предыдущие tuple прошли.
func TestRegisterApplier_PermanentOnLaterTuple_StopsAndPoisons(t *testing.T) {
	intent := domain.RegisterIntentForCreate(
		&domain.Registry{ID: "reg-3", ProjectID: "prj-3"}, "user", "usr-y")
	require.Len(t, intent.Tuples, 2)

	fake := &scriptedRegisterClient{
		registerErrs: []error{
			nil, // project-tuple applied
			status.Error(codes.InvalidArgument, "malformed owner tuple"),
		},
	}
	applier := NewRegisterApplier(fake)

	err := applier(context.Background(), domain.FGAEventRegister, intent)
	require.Error(t, err)
	assert.True(t, errors.Is(err, drainer.ErrPermanent), "InvalidArgument → permanent, got %v", err)
	require.Len(t, fake.registerReqs, 2, "processing stops AT the poison tuple (both attempted)")
}

// TestRegisterApplier_TransientOnLaterTuple_Retries — transient (Unavailable) на
// tuple всплывает сырым (drainer → transient retry) после предыдущих OK.
func TestRegisterApplier_TransientOnLaterTuple_Retries(t *testing.T) {
	intent := domain.RegisterIntentForCreate(
		&domain.Registry{ID: "reg-4", ProjectID: "prj-4"}, "user", "usr-w")
	require.Len(t, intent.Tuples, 2)

	fake := &scriptedRegisterClient{
		registerErrs: []error{
			nil,
			status.Error(codes.Unavailable, "iam down"),
		},
	}
	applier := NewRegisterApplier(fake)

	err := applier(context.Background(), domain.FGAEventRegister, intent)
	require.Error(t, err)
	assert.Equal(t, drainer.ClassTransient, drainer.Classify(err),
		"Unavailable must classify transient (never poison), got %v", err)
}

// TestRegisterApplier_HappyPath_AllApplied — все tuple применяются, возвращается nil.
func TestRegisterApplier_HappyPath_AllApplied(t *testing.T) {
	intent := domain.RegisterIntentForCreate(
		&domain.Registry{ID: "reg-5", ProjectID: "prj-5"}, "user", "usr-v")
	fake := &scriptedRegisterClient{}
	applier := NewRegisterApplier(fake)

	err := applier(context.Background(), domain.FGAEventRegister, intent)
	require.NoError(t, err)
	require.Len(t, fake.registerReqs, len(intent.Tuples))
}

// TestRegisterApplier_NilClient_Transient — peer не сконфигурирован → transient
// (intent durable до wiring'а).
func TestRegisterApplier_NilClient_Transient(t *testing.T) {
	applier := NewRegisterApplier(nil)
	err := applier(context.Background(), domain.FGAEventRegister,
		domain.RegisterIntent{Tuples: []domain.FGATuple{domain.FGAProjectTuple("r", "p")}})
	require.Error(t, err)
	assert.Equal(t, drainer.ClassTransient, drainer.Classify(err))
}

// TestRegisterApplier_UnknownEventType_Permanent — неизвестный event_type → poison.
func TestRegisterApplier_UnknownEventType_Permanent(t *testing.T) {
	fake := &scriptedRegisterClient{}
	applier := NewRegisterApplier(fake)
	err := applier(context.Background(), "fga.bogus",
		domain.RegisterIntent{Tuples: []domain.FGATuple{domain.FGAProjectTuple("r", "p")}})
	require.Error(t, err)
	assert.True(t, errors.Is(err, drainer.ErrPermanent))
	assert.Empty(t, fake.registerReqs, "unknown event must not touch iam")
}

// TestClassifyRegisterErr — table-driven классификация gRPC-ответа (medium TEST
// finding: applier ранее без покрытия).
func TestClassifyRegisterErr(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantNil bool
		wantIs  error
	}{
		{name: "nil", err: nil, wantNil: true},
		{name: "already_exists", err: status.Error(codes.AlreadyExists, "dup"), wantIs: drainer.ErrAlreadyApplied},
		{name: "invalid_argument", err: status.Error(codes.InvalidArgument, "bad"), wantIs: drainer.ErrPermanent},
		{name: "unavailable_raw_transient", err: status.Error(codes.Unavailable, "down")},
		{name: "internal_raw_transient", err: status.Error(codes.Internal, "boom")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyRegisterErr(tc.err)
			if tc.wantNil {
				assert.NoError(t, got)
				return
			}
			require.Error(t, got)
			if tc.wantIs != nil {
				assert.True(t, errors.Is(got, tc.wantIs), "want Is(%v), got %v", tc.wantIs, got)
			} else {
				// raw transient: not AlreadyApplied, not Permanent.
				assert.False(t, errors.Is(got, drainer.ErrAlreadyApplied))
				assert.False(t, errors.Is(got, drainer.ErrPermanent))
				assert.Equal(t, drainer.ClassTransient, drainer.Classify(got))
			}
		})
	}
}

// TestDecodeRegisterIntent — malformed/empty/incomplete → poison; valid → intent.
func TestDecodeRegisterIntent(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		in := domain.RegisterIntentForCreate(
			&domain.Registry{ID: "reg-d", ProjectID: "prj-d"}, "user", "usr-d")
		b, err := in.Marshal()
		require.NoError(t, err)
		got, err := DecodeRegisterIntent(b)
		require.NoError(t, err)
		assert.Len(t, got.Tuples, 2)
	})
	t.Run("malformed_json", func(t *testing.T) {
		_, err := DecodeRegisterIntent([]byte("{not json"))
		require.Error(t, err)
		assert.True(t, errors.Is(err, drainer.ErrPermanent))
	})
	t.Run("empty_tuple_set", func(t *testing.T) {
		b, _ := domain.RegisterIntent{Kind: "Registry", ResourceID: "x"}.Marshal()
		_, err := DecodeRegisterIntent(b)
		require.Error(t, err)
		assert.True(t, errors.Is(err, drainer.ErrPermanent))
	})
	t.Run("incomplete_tuple", func(t *testing.T) {
		b, _ := domain.RegisterIntent{
			Kind:       "Registry",
			ResourceID: "x",
			Tuples:     []domain.FGATuple{{SubjectID: "user:u", Relation: "", Object: "o"}},
		}.Marshal()
		_, err := DecodeRegisterIntent(b)
		require.Error(t, err)
		assert.True(t, errors.Is(err, drainer.ErrPermanent))
	})
}
