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
	registryv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/registry/v1"

	"github.com/PRO-Robotech/kacho-registry/internal/domain"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// RenameRepository — async переименование в пределах ОДНОГО реестра (new_name — голое
// repo-имя; cross-registry rename структурно невыразим, D-5). Sync-часть: format-
// валидация registry_id/repository + new_name (malformed → INVALID_ARGUMENT, no-op
// new_name==repository → "new name must differ from current name", A19, ДО Operation).
// per-repo v_update@old + v_create@registry Check (deny|absent → NOT_FOUND) — в handler'е.
//
// Async worker: (1) класс источника (GetConfig old — durable vs ephemeral); (2) pre-check
// коллизии целевого имени (overlay ИЛИ проекция занята → ALREADY_EXISTS, A17);
// (3) engine re-home тегов/манифестов/referrers old→new — движок недоступен в середине
// → UNAVAILABLE fail-closed (без частичного rename, старое имя резолвится, A21);
// (4) durable → RekeyConfig (re-key UPDATE, A16) | ephemeral → InsertConfig под new_name
// (auto-promote → durable, A23) — одностейтментная запись под PK-backstop (A18); FGA
// re-register new / unregister old + public-grant governance в той же tx.
func (u *UseCase) RenameRepository(ctx context.Context, registryID, repository, newName string) (*operations.Operation, error) {
	if err := u.assertRepoWired(); err != nil {
		return nil, err
	}
	if err := ValidateRegistryID(registryID); err != nil {
		return nil, err
	}
	if err := domain.ValidateRepositoryName("repository", repository); err != nil {
		return nil, failInvalidArg("%s", err.Error())
	}
	if err := domain.ValidateRepositoryName("new_name", newName); err != nil {
		return nil, failInvalidArg("%s", err.Error())
	}
	if newName == repository {
		return nil, failInvalidArg("new name must differ from current name")
	}

	principal := operations.PrincipalFromContext(ctx)
	op, err := operations.NewFromContext(ctx,
		ids.PrefixOperationReg,
		fmt.Sprintf("Rename Repository %s/%s → %s", registryID, repository, newName),
		&registryv1.RenameRepositoryMetadata{RegistryId: registryID, Repository: repository, NewName: newName},
	)
	if err != nil {
		return nil, mapRepoErr(err)
	}
	if err := u.ops.CreateWithPrincipal(ctx, op, principal); err != nil {
		return nil, mapRepoErr(err)
	}

	operations.Run(ctx, u.ops, op.ID, func(workerCtx context.Context) (*anypb.Any, error) {
		wctx := operations.WithPrincipal(workerCtx, principal)
		renamed, rerr := u.doRename(wctx, registryID, repository, newName, principal)
		if rerr != nil {
			return nil, rerr
		}
		return u.repositoryAny(renamed)
	})

	return &op, nil
}

// doRename исполняет rename в worker'е: класс источника, collision-precheck, engine
// re-home (fail-closed A21), overlay re-key/promote под PK-backstop, projection-merge.
func (u *UseCase) doRename(ctx context.Context, registryID, repository, newName string, principal operations.Principal) (*domain.Repository, error) {
	overlay, oerr := u.cfg.GetConfig(ctx, registryID, repository)
	durable := true
	if oerr != nil {
		if !errors.Is(oerr, regerrors.ErrNotFound) {
			return nil, mapRepoErr(oerr)
		}
		durable = false // ephemeral (проекция без overlay) → auto-promote (A23)
	}

	if cerr := u.assertTargetFree(ctx, registryID, newName); cerr != nil {
		return nil, cerr
	}

	// Engine re-home old→new (многошаговая НЕ-атомарная OCI-операция). Движок недоступен
	// → UNAVAILABLE fail-closed: overlay-имя НЕ меняем, старое имя резолвится (A21).
	if merr := u.zot.RenameRepository(ctx, registryID, repository, newName); merr != nil {
		return nil, mapRepoErr(merr)
	}

	reg, gerr := u.reader.Get(ctx, registryID)
	if gerr != nil {
		return nil, mapRepoErr(gerr)
	}

	visibility := reg.DefaultVisibility
	if durable {
		visibility = overlay.Visibility
	}
	visibility = resolveVisibility(visibility, reg.DefaultVisibility)
	intents := renameIntents(registryID, repository, newName, reg.ProjectID, principal, visibility)

	var (
		written *domain.RepositoryConfig
		werr    error
	)
	if durable {
		written, werr = u.cfg.RekeyConfig(ctx, registryID, repository, newName, intents...)
	} else {
		promoted := &domain.RepositoryConfig{
			RegistryID: registryID,
			Name:       newName,
			Visibility: visibility,
		}
		written, werr = u.cfg.InsertConfig(ctx, promoted, intents...)
	}
	if werr != nil {
		if errors.Is(werr, regerrors.ErrAlreadyExists) {
			return nil, failAlreadyExists("repository already exists")
		}
		return nil, mapRepoErr(werr)
	}

	proj, perr := u.zot.RepositoryProjection(ctx, registryID, newName)
	if perr != nil {
		return nil, mapRepoErr(perr)
	}
	return mergeRepository(registryID, newName, written, proj), nil
}

// assertTargetFree — целевое имя свободно (ни overlay-строки, ни проекции с тегами),
// иначе ALREADY_EXISTS (A17). Двойная проверка (overlay + projection) — целевое имя
// занято либо durable-overlay, либо pushed-контентом. DB PK-backstop (RekeyConfig/
// InsertConfig) — авторитетный арбитр под concurrency (A18); эта проверка — ранний
// reject до engine-remap (не re-home'им в занятое имя).
func (u *UseCase) assertTargetFree(ctx context.Context, registryID, newName string) error {
	if _, err := u.cfg.GetConfig(ctx, registryID, newName); err == nil {
		return failAlreadyExists("repository already exists")
	} else if !errors.Is(err, regerrors.ErrNotFound) {
		return mapRepoErr(err)
	}
	proj, perr := u.zot.RepositoryProjection(ctx, registryID, newName)
	if perr != nil {
		return mapRepoErr(perr)
	}
	if proj != nil && proj.TagCount > 0 {
		return failAlreadyExists("repository already exists")
	}
	return nil
}

// renameIntents — FGA outbox-intent'ы rename в той же writer-tx: re-register new repo
// (parent+owner создателя), unregister old repo, + public-grant governance по итоговому
// visibility (PUBLIC → register(new)/unregister(old); PRIVATE → unregister(old) на всякий
// случай, no-op в iam если tuple отсутствовал).
func renameIntents(registryID, oldName, newName, projectID string, principal operations.Principal, visibility domain.Visibility) []OutboxIntent {
	subject := domain.FGASubjectFromPrincipal(principal.Type, principal.ID)
	intents := []OutboxIntent{
		{Event: domain.FGAEventRegister, Intent: domain.RegisterIntentForRepoPush(registryID, newName, projectID, subject)},
		{Event: domain.FGAEventUnregister, Intent: domain.UnregisterIntentForRepo(registryID, oldName)},
		{Event: domain.FGAEventUnregister, Intent: domain.UnregisterIntentForRepoPublicGrant(registryID, oldName)},
	}
	if visibility == domain.VisibilityPublic {
		intents = append(intents,
			OutboxIntent{Event: domain.FGAEventRegister, Intent: domain.RegisterIntentForRepoPublicGrant(registryID, newName)})
	}
	return intents
}
