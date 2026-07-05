// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho-corelib/ids"
	"github.com/PRO-Robotech/kacho-corelib/operations"
	corevalidate "github.com/PRO-Robotech/kacho-corelib/validate"
	registryv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/registry/v1"

	"github.com/PRO-Robotech/kacho-registry/internal/domain"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// Create — async создание реестра. Sync-часть: domain-валидация, cross-domain
// project-existence через iam (fail-closed → Unavailable), id-gen (prefix "reg"),
// атомарный INSERT registries + owner-tuple register-intent в registry_outbox
// ОДНОЙ writer-tx. Async worker (с проброшенным principal): lazy zot-namespace
// (репо появляется на push, создавать нечего) + финализация Operation ресурсом.
//
// Порядок negatives (строка/tuple/namespace НЕ появляются): authz-Check (interceptor)
// → domain-валидация → project-existence → INSERT. Всё до INSERT — sync-reject.
func (u *UseCase) Create(ctx context.Context, spec CreateSpec) (*operations.Operation, error) {
	if err := u.assertWired(); err != nil {
		return nil, err
	}

	if spec.ProjectID == "" {
		return nil, failInvalidArg("projectId is required")
	}
	if err := corevalidate.Labels("labels", spec.Labels); err != nil {
		return nil, err
	}

	reg := &domain.Registry{
		ID:          ids.NewID(ids.PrefixRegistry),
		ProjectID:   spec.ProjectID,
		Name:        spec.Name,
		Description: spec.Description,
		Labels:      spec.Labels,
		Status:      domain.RegistryStatusActive,
	}
	// Self-validating domain: name DNS-safe (OCI-namespace segment), status,
	// project_id. Ошибка → InvalidArgument (каноничный "Illegal argument"-класс).
	if err := reg.Validate(); err != nil {
		return nil, failInvalidArg("Illegal argument: %s", err.Error())
	}

	// Cross-domain existence project'а на request-path (data-integrity.md §cross-domain):
	// not-found → InvalidArgument; iam недоступен → Unavailable (мутация fail-closed).
	if err := u.iam.ProjectExists(ctx, spec.ProjectID); err != nil {
		return nil, projectExistsErr(spec.ProjectID, err)
	}

	// Principal захватывается в sync-ctx (реальный вызывающий от interceptor'а) —
	// нужен и для owner-tuple, и для worker'а (иначе authz_no_principal).
	principal := operations.PrincipalFromContext(ctx)
	intent := domain.RegisterIntentForCreate(reg, principal.Type, principal.ID)

	// LRO-ordering (project-rule #9 / CWE-662): pending-Operation персистится ПЕРВЫМ,
	// затем — durable INSERT. Иначе Insert-commit с последующим сбоем Operation-create
	// (две разные транзакции) оставил бы закоммиченный ресурс + owner-tuple без
	// сопутствующего Operation-envelope (осиротевший ресурс). reg.ID/reg.Name уже
	// известны (id сгенерирован выше) — метадату можно построить до INSERT.
	op, err := operations.NewFromContext(ctx,
		ids.PrefixOperationReg,
		fmt.Sprintf("Create Registry %s", reg.Name),
		&registryv1.CreateRegistryMetadata{RegistryId: reg.ID},
	)
	if err != nil {
		return nil, mapRepoErr(err)
	}
	if err := u.ops.CreateWithPrincipal(ctx, op, principal); err != nil {
		return nil, mapRepoErr(err)
	}

	// Атомарно: строка registry + register-intent (project-tuple ПЕРВЫМ, затем
	// owner-tuple) в одной writer-tx. partial UNIQUE(project_id,name)WHERE
	// status<>'DELETING' → 23505 → ALREADY_EXISTS с именем. INSERT — синхронно
	// (сохраняет sync-reject семантику REG-04): дубликат → немедленный gRPC
	// AlreadyExists клиенту, а не async-Operation с error. При ошибке INSERT
	// уже созданный pending-Operation финализируется как failed (не оставляем
	// подвисший done=false envelope, который клиент поллил бы вечно).
	created, err := u.writer.Insert(ctx, reg, intent)
	if err != nil {
		syncErr := mapRepoErr(err)
		if errors.Is(err, regerrors.ErrAlreadyExists) {
			syncErr = failAlreadyExists("registry %s already exists", reg.Name)
		}
		// Финализируем осиротевший pending-Operation тем же статусом (worker переведёт
		// его в done=true+error). Клиент всё равно получает sync-ошибку ниже.
		finalErr := syncErr
		operations.Run(ctx, u.ops, op.ID, func(_ context.Context) (*anypb.Any, error) {
			return nil, finalErr
		})
		return nil, syncErr
	}

	operations.Run(ctx, u.ops, op.ID, func(_ context.Context) (*anypb.Any, error) {
		// Строка реестра + owner-tuple intent уже записаны СИНХРОННО (writer.Insert
		// с request-ctx, несущим principal). zot-namespace lazy — материализуется на
		// первом docker push, отдельного provisioning-шага нет. Worker лишь финализирует
		// Operation созданным ресурсом: downstream/peer-вызовов нет, principal в
		// worker-ctx не требуется (в отличие от update/delete/deletetag/gc, где он
		// принудительно пробрасывается перед downstream-вызовом).
		return u.registryAny(created)
	})

	return &op, nil
}

// registryAny упаковывает Registry в Operation.response (google.protobuf.Any).
func (u *UseCase) registryAny(r *domain.Registry) (*anypb.Any, error) {
	out, err := anypb.New(u.ProtoRegistry(r))
	if err != nil {
		return nil, mapRepoErr(err)
	}
	return out, nil
}

// projectExistsErr — маппинг cross-domain project-precheck в gRPC-status:
//
//	not-found / invalid → InvalidArgument ("project <id> not found")
//	iam недоступен      → Unavailable (fail-closed для мутации)
func projectExistsErr(projectID string, err error) error {
	switch {
	case errors.Is(err, regerrors.ErrInvalidArg), errors.Is(err, regerrors.ErrNotFound):
		return failInvalidArg("project %s not found", projectID)
	case errors.Is(err, regerrors.ErrUnavailable):
		return failUnavailable("project existence check unavailable")
	}
	return mapRepoErr(err)
}
