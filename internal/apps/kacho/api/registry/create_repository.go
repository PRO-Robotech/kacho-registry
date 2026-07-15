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

// CreateRepositorySpec — вход CreateRepository (тело CreateRepositoryRequest, распарсенное
// тонким handler'ом). Visibility — запрошенная (UNSPECIFIED → наследует default).
type CreateRepositorySpec struct {
	RegistryID  string
	Repository  string
	Description string
	Labels      map[string]string
	Visibility  domain.Visibility
}

// CreateRepository — async вставка config-overlay (durable, survives-empty, D-3).
// Sync-часть: format-валидация (malformed-first A05/A06), payload-границы (A22),
// resolve visibility (UNSPECIFIED → registry.default_visibility, B12), и СИНХРОННЫЙ
// InsertConfig (tx: ACTIVE-guard A24 + INSERT + adopt-owner/public-grant intents в
// ТОЙ ЖЕ writer-tx). Дубликат overlay → sync ALREADY_EXISTS (DB PRIMARY KEY, ban #10,
// A02/A04); реестр DELETING → sync FAILED_PRECONDITION (A24). Async worker лишь
// финализирует Operation: projection-merge (adopt существующего контента, tagCount, A03).
//
// admin-gate на EXPLICIT visibility=PUBLIC (B08) и namespace call-gate (X04) — в
// handler'е ДО вызова (существование реестра / any-path-to-PUBLIC — authz-концерн).
func (u *UseCase) CreateRepository(ctx context.Context, spec CreateRepositorySpec) (*operations.Operation, error) {
	if err := u.assertRepoWired(); err != nil {
		return nil, err
	}
	if err := ValidateRegistryID(spec.RegistryID); err != nil {
		return nil, err
	}
	if err := domain.ValidateRepositoryName("repository", spec.Repository); err != nil {
		return nil, failInvalidArg("%s", err.Error())
	}
	if err := validateRepoDescription(spec.Description); err != nil {
		return nil, err
	}
	if err := corevalidate.Labels("labels", spec.Labels); err != nil {
		return nil, err
	}

	// Read registry для default_visibility (inheritance, B12) — same-DB read. Absent/
	// invisible реестр отсекается handler namespace call-gate (X04) ДО вызова; здесь
	// well-formed-но-нет → NOT_FOUND (не течёт факт).
	reg, err := u.reader.Get(ctx, spec.RegistryID)
	if err != nil {
		return nil, mapRepoErr(err)
	}
	visibility := resolveVisibility(spec.Visibility, reg.DefaultVisibility)

	cfg := &domain.RepositoryConfig{
		RegistryID:  spec.RegistryID,
		Name:        spec.Repository,
		Description: spec.Description,
		Labels:      spec.Labels,
		Visibility:  visibility,
	}

	principal := operations.PrincipalFromContext(ctx)
	op, err := operations.NewFromContext(ctx,
		ids.PrefixOperationReg,
		fmt.Sprintf("Create Repository %s/%s", spec.RegistryID, spec.Repository),
		&registryv1.CreateRepositoryMetadata{RegistryId: spec.RegistryID, Repository: spec.Repository},
	)
	if err != nil {
		return nil, mapRepoErr(err)
	}
	if err := u.ops.CreateWithPrincipal(ctx, op, principal); err != nil {
		return nil, mapRepoErr(err)
	}

	// Синхронный InsertConfig (tx: ACTIVE-guard + INSERT overlay + adopt-owner intent +
	// [public-grant intent если PUBLIC] в ОДНОЙ writer-tx). Дубликат/DELETING → sync
	// reject (sync-семантика REG-04 parity). Осиротевший pending-Operation финализируется
	// как failed. Intents эмитятся ТОЛЬКО при успешном INSERT (та же tx).
	intents := createRepoIntents(spec.RegistryID, spec.Repository, reg.ProjectID, principal, visibility)
	created, ierr := u.cfg.InsertConfig(ctx, cfg, intents...)
	if ierr != nil {
		syncErr := mapRepoErr(ierr)
		if errors.Is(ierr, regerrors.ErrAlreadyExists) {
			syncErr = failAlreadyExists("repository already exists")
		}
		operations.Run(ctx, u.ops, op.ID, func(_ context.Context) (*anypb.Any, error) {
			return nil, syncErr
		})
		return nil, syncErr
	}

	operations.Run(ctx, u.ops, op.ID, func(workerCtx context.Context) (*anypb.Any, error) {
		wctx := operations.WithPrincipal(workerCtx, principal)
		// Overlay уже вставлен (created несёт DB-assigned created_at) + intents эмитированы
		// синхронно; worker читает projection (adopt существующего контента → tagCount, A03)
		// и мёржит в публичный Repository.
		proj, perr := u.zot.RepositoryProjection(wctx, spec.RegistryID, spec.Repository)
		if perr != nil {
			return nil, mapRepoErr(perr)
		}
		repo := mergeRepository(spec.RegistryID, spec.Repository, created, proj)
		return u.repositoryAny(repo)
	})

	return &op, nil
}

// createRepoIntents — набор FGA outbox-intent'ов для CreateRepository, эмитируемых в
// ТОЙ ЖЕ writer-tx, что INSERT overlay:
//   - adopt-owner (register RepoPush): parent-tuple + owner-tuple создателя → repo
//     становится push/pull-able его создателем; АДДИТИВЕН (не снимает owner-tuple
//     исходного пушера при adopt пред-существующей проекции, A03 — iam дедуплицирует);
//   - public-grant (register RepoPublicGrant): при итоговом visibility=PUBLIC
//     (включая inherited-default B12) — "user:* v_get" для анонимного pull (D-7).
func createRepoIntents(registryID, repository, projectID string, principal operations.Principal, visibility domain.Visibility) []OutboxIntent {
	subject := domain.FGASubjectFromPrincipal(principal.Type, principal.ID)
	intents := []OutboxIntent{
		{Event: domain.FGAEventRegister, Intent: domain.RegisterIntentForRepoPush(registryID, repository, projectID, subject)},
	}
	if visibility == domain.VisibilityPublic {
		intents = append(intents, OutboxIntent{Event: domain.FGAEventRegister, Intent: domain.RegisterIntentForRepoPublicGrant(registryID, repository)})
	}
	return intents
}

// repositoryAny упаковывает публичный Repository в Operation.response (google.protobuf.Any).
func (u *UseCase) repositoryAny(r *domain.Repository) (*anypb.Any, error) {
	out, err := anypb.New(u.ProtoRepository(r))
	if err != nil {
		return nil, mapRepoErr(err)
	}
	return out, nil
}
