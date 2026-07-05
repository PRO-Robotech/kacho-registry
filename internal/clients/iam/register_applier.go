// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// register_applier.go — register-drainer applier поверх kacho-iam
// InternalIAMService.RegisterResource / UnregisterResource (fga-proxy). Это
// consumer-half transactional-outbox owner-tuple реле: writer-tx Create/Delete/
// Update пишет domain.RegisterIntent в registry_outbox, а drainer (corelib
// outbox/drainer) читает каждую строку и применяет её tuple-набор через kacho-iam
// по mTLS, мапя gRPC-ответ на three-way классификацию drainer'а:
//
//	nil                       → sent_at (happy path / идемпотентный повтор)
//	drainer.ErrAlreadyApplied → sent_at (target «уже есть»)
//	drainer.ErrPermanent      → poison (attempt_count = Max)
//	прочее                    → transient (retry с exp backoff)
package iam

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-corelib/auth"
	"github.com/PRO-Robotech/kacho-corelib/outbox/drainer"
	iamv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-registry/internal/domain"
)

// errRegisterClientNotConfigured — iam-peer не сконфигурирован. Для drainer'а это
// transient (intent остаётся durable, ретраится после wiring'а peer'а).
var errRegisterClientNotConfigured = errors.New("iam register client not configured")

// RegisterResourceClient — узкий порт fga-proxy, нужный applier'у. Реализуется
// сгенерированным InternalIAMServiceClient; fake в тестах пишет вызовы и скриптует
// ответы. Определён здесь (consumer-side), чтобы drainer-код зависел от порта, а не
// от grpc-stub (architecture.md dependency rule).
type RegisterResourceClient interface {
	RegisterResource(ctx context.Context, in *iamv1.RegisterResourceRequest, opts ...grpc.CallOption) (*iamv1.RegisterResourceResponse, error)
	UnregisterResource(ctx context.Context, in *iamv1.UnregisterResourceRequest, opts ...grpc.CallOption) (*iamv1.UnregisterResourceResponse, error)
}

// NewRegisterResourceClient оборачивает grpc-conn к kacho-iam internal-листенеру
// (:9091 — RegisterResource/UnregisterResource Internal-only) в порт. nil → nil.
func NewRegisterResourceClient(conn grpc.ClientConnInterface) RegisterResourceClient {
	if conn == nil {
		return nil
	}
	return iamv1.NewInternalIAMServiceClient(conn)
}

// DecodeRegisterIntent — drainer.Decoder[domain.RegisterIntent] для
// registry_outbox.payload. Malformed JSON / пустой tuple-набор / неполный tuple →
// drainer.ErrPermanent (poison, не бесконечный retry).
func DecodeRegisterIntent(payload []byte) (domain.RegisterIntent, error) {
	i, err := domain.UnmarshalRegisterIntent(payload)
	if err != nil {
		return domain.RegisterIntent{}, fmt.Errorf("%w: registry_outbox: invalid json: %s", drainer.ErrPermanent, err)
	}
	if len(i.Tuples) == 0 {
		return domain.RegisterIntent{}, fmt.Errorf("%w: registry_outbox: empty tuple set", drainer.ErrPermanent)
	}
	for idx, t := range i.Tuples {
		if !t.Valid() {
			return domain.RegisterIntent{}, fmt.Errorf(
				"%w: registry_outbox: incomplete tuple[%d] (subject=%q relation=%q object=%q)",
				drainer.ErrPermanent, idx, t.SubjectID, t.Relation, t.Object)
		}
	}
	return i, nil
}

// NewRegisterApplier — drainer.Applier[domain.RegisterIntent] поверх fga-proxy.
// На каждый tuple вызывает RegisterResource (fga.register) либо UnregisterResource
// (fga.unregister).
//
// КАЖДЫЙ tuple обрабатывается идемпотентно ВСЕГДА, до конца набора: ErrAlreadyApplied
// на отдельном tuple — это per-tuple success (target «уже есть»), НЕ повод обрывать
// остаток набора. Это критично для at-least-once retry-after-partial-apply: если
// attempt-1 применил project-tuple, но упал на owner-tuple (transient) → drainer
// ретраит строку; на attempt-2 iam отвечает AlreadyExists на уже-применённый
// project-tuple, и applier обязан пойти ДАЛЬШЕ и всё-таки применить owner-tuple.
// Ранний return на первом AlreadyExists ронял owner-tuple навсегда (drainer помечал
// строку sent, не дойдя до второго tuple) — нарушение «owner-tuple не теряется».
//
// Только ErrPermanent (poison) и transient short-circuit'ят набор — drainer
// ретраит/травит всю строку, и оставшиеся tuple будут повторно опрошены. Терминальный
// ErrAlreadyApplied всплывает наверх лишь когда КАЖДЫЙ tuple ответил already-applied
// (нулевая реальная работа) — тогда classify-метрика видит already_applied, а не
// success; если хоть один tuple сделал реальную работу — возвращается nil (оба
// класса → sent_at, но метрика точнее).
func NewRegisterApplier(cli RegisterResourceClient) drainer.Applier[domain.RegisterIntent] {
	return func(ctx context.Context, eventType string, intent domain.RegisterIntent) error {
		if cli == nil {
			// iam-peer не сконфигурирован — transient (intent durable до wiring'а).
			return errRegisterClientNotConfigured
		}
		// PropagateOutgoing — iam-side principal-extractor видит контекст; identity
		// least-priv fga_writer приходит из mTLS client-cert.
		ctx = auth.PropagateOutgoing(ctx)

		var apply func(t domain.FGATuple) error
		switch eventType {
		case domain.FGAEventRegister:
			apply = func(t domain.FGATuple) error {
				_, err := cli.RegisterResource(ctx, &iamv1.RegisterResourceRequest{
					SubjectId:       t.SubjectID,
					Relation:        t.Relation,
					Object:          t.Object,
					TraceId:         intent.ResourceID,
					Labels:          intent.Labels,
					ParentProjectId: intent.ParentProjectID,
				})
				return err
			}
		case domain.FGAEventUnregister:
			apply = func(t domain.FGATuple) error {
				_, err := cli.UnregisterResource(ctx, &iamv1.UnregisterResourceRequest{
					SubjectId:       t.SubjectID,
					Relation:        t.Relation,
					Object:          t.Object,
					TraceId:         intent.ResourceID,
					Labels:          intent.Labels,
					ParentProjectId: intent.ParentProjectID,
				})
				return err
			}
		default:
			return fmt.Errorf("%w: registry_outbox: unknown event_type %q", drainer.ErrPermanent, eventType)
		}

		// allAlreadyApplied — становится false, как только хоть один tuple сделал
		// реальную работу (nil-ответ). Стартовое true покрывает пустой набор (decoder
		// такой уже отсеял как poison, но keep-honest на случай прямого вызова).
		allAlreadyApplied := true
		for _, t := range intent.Tuples {
			switch cerr := classifyRegisterErr(apply(t)); {
			case cerr == nil:
				allAlreadyApplied = false
			case errors.Is(cerr, drainer.ErrAlreadyApplied):
				// per-tuple идемпотентный success — идём к следующему tuple, НЕ обрываем.
			default:
				// ErrPermanent или transient — обрываем; drainer ретраит/травит строку,
				// оставшиеся tuple будут опрошены заново на следующем attempt'е.
				return cerr
			}
		}
		if allAlreadyApplied && len(intent.Tuples) > 0 {
			return fmt.Errorf("%w: all tuples already applied", drainer.ErrAlreadyApplied)
		}
		return nil
	}
}

// classifyRegisterErr мапит gRPC-ответ RegisterResource/UnregisterResource на
// three-way классификацию drainer'а:
//
//	nil                    → nil (применено / идемпотентный OK)
//	AlreadyExists          → ErrAlreadyApplied (target «уже есть» — success)
//	InvalidArgument        → ErrPermanent (malformed tuple — retry бессмыслен)
//	прочее                 → raw (transient — drainer ретраит; intent durable)
func classifyRegisterErr(err error) error {
	if err == nil {
		return nil
	}
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	switch st.Code() {
	case codes.AlreadyExists:
		return fmt.Errorf("%w: iam register reports duplicate: %s", drainer.ErrAlreadyApplied, st.Message())
	case codes.InvalidArgument:
		return fmt.Errorf("%w: iam register rejected (no retry): %s", drainer.ErrPermanent, st.Message())
	default:
		return err
	}
}

// Compile-time guards — возвращаемые Applier/Decoder совпадают с generic-сигнатурами
// drainer'а (рассинхрон сигнатур падает здесь, а не на месте wiring'а в main).
var _ drainer.Applier[domain.RegisterIntent] = NewRegisterApplier(nil)
var _ drainer.Decoder[domain.RegisterIntent] = DecodeRegisterIntent
