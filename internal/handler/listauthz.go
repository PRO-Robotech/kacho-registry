// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// listauthz.go — handler-level authz для ScopeFiltered registry-RPC
// (ListRepositories/ListTags/DeleteTag). Interceptor эти RPC пропускает
// (ScopeFiltered), потому что per-RPC single-object Check не покрывает две
// потребности: (1) per-repo row-filter каталога (namespace-viewer НЕ видит все repos
// автоматически) и (2) existence-hiding deny→NOT_FOUND (interceptor вернул бы
// PermissionDenied, раскрыв факт существования чужого repo). Обе — здесь.
//
// Authz читает caller-principal из ctx (populated principal-extract интерсептором на
// public-листенере) и Check'ает через InternalIAMService.Check по mTLS. Fail-closed:
// iam недоступен → Unavailable (не нефильтрованный список, не «deny»). breakglass
// (nil Authorizer) → bypass, как и у interceptor'а.
package handler

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-corelib/authz"
	"github.com/PRO-Robotech/kacho-corelib/ids"
	"github.com/PRO-Robotech/kacho-corelib/operations"
	corevalidate "github.com/PRO-Robotech/kacho-corelib/validate"

	"github.com/PRO-Robotech/kacho-registry/internal/domain"
)

// Authorizer — узкий порт per-repo authz-Check (InternalIAMService.Check →
// OpenFGA/ReBAC). subject — FGA subject-строка ("user:usr_…" / "service_account:…"),
// relation — verb-relation (v_list/v_delete), object — FGA object-строка. Реализуется
// check.IAMCheckClient. nil → breakglass (authz bypass).
type Authorizer interface {
	Check(ctx context.Context, subject, relation, object string) (bool, error)
}

// verb-relations per-repo authz (зеркалят check.PermissionMap; для ScopeFiltered
// registry-RPC authz энфорсится ЗДЕСЬ, не в interceptor'е — anti-#241: repo-verb НЕ
// наследуется от namespace-tier).
const (
	relationVList   = "v_list"
	relationVDelete = "v_delete"
)

// registryObjectRef — FGA object namespace-реестра "registry_registry:<id>".
func registryObjectRef(registryID string) string {
	return domain.FGAObjectTypeRegistry + ":" + registryID
}

// repositoryObjectRef — FGA object репозитория "registry_repository:<id>/<repo>".
func repositoryObjectRef(registryID, repository string) string {
	return domain.FGAObjectTypeRepository + ":" + registryID + "/" + repository
}

// validateRegistryID отсекает malformed registry-id первым стейтментом RPC (prefix
// `reg` → InvalidArgument "invalid registry id '<X>'").
func validateRegistryID(id string) error {
	return corevalidate.ResourceID("registry", ids.PrefixRegistry, id)
}

// repoAuthz — handler-level per-repo authz. Пустой az (breakglass) → bypass.
type repoAuthz struct{ az Authorizer }

func newRepoAuthz(az Authorizer) repoAuthz { return repoAuthz{az: az} }

// subjectFromContext — FGA subject-строка аутентифицированного principal из ctx.
func subjectFromContext(ctx context.Context) string {
	p := operations.PrincipalFromContext(ctx)
	return authz.FormatSubject(p.Type, p.ID)
}

// check — единичный Check против объекта. breakglass (nil az) → allow. Ошибка az —
// проброс наружу (caller маппит в Unavailable, fail-closed).
func (a repoAuthz) check(ctx context.Context, relation, object string) (bool, error) {
	if a.az == nil {
		return true, nil
	}
	return a.az.Check(ctx, subjectFromContext(ctx), relation, object)
}

// namespaceGate — call-gate: subject обязан иметь v_list на registry_registry:<reg>.
// deny → NOT_FOUND (existence-hiding); az-error → UNAVAILABLE (fail-closed).
func (a repoAuthz) namespaceGate(ctx context.Context, registryID string) error {
	allowed, err := a.check(ctx, relationVList, registryObjectRef(registryID))
	if err != nil {
		return errAuthzUnavailable()
	}
	if !allowed {
		return errHideExistence()
	}
	return nil
}

// checkRepo — per-repo verb-Check (ListTags v_list / DeleteTag v_delete). deny →
// NOT_FOUND (existence-hiding — не раскрывать существование чужого repo); az-error →
// UNAVAILABLE.
func (a repoAuthz) checkRepo(ctx context.Context, registryID, repository, relation string) error {
	allowed, err := a.check(ctx, relation, repositoryObjectRef(registryID, repository))
	if err != nil {
		return errAuthzUnavailable()
	}
	if !allowed {
		return errHideExistence()
	}
	return nil
}

// filterRepos — per-repo row-filter каталога: оставляет только repos, на
// registry_repository:<reg>/<repo> которых subject имеет v_list (REG-22/23). breakglass
// → все; az-error → UNAVAILABLE (не отдаём нефильтрованный список — no-leak).
func (a repoAuthz) filterRepos(ctx context.Context, registryID string, repos []*domain.Repository) ([]*domain.Repository, error) {
	if a.az == nil {
		return repos, nil
	}
	subject := subjectFromContext(ctx)
	out := make([]*domain.Repository, 0, len(repos))
	for _, r := range repos {
		allowed, err := a.az.Check(ctx, subject, relationVList, repositoryObjectRef(registryID, r.Name))
		if err != nil {
			return nil, errAuthzUnavailable()
		}
		if allowed {
			out = append(out, r)
		}
	}
	return out, nil
}

// errHideExistence — deny на объект, который caller не вправе видеть: NOT_FOUND
// (existence-hiding — «есть-но-не-твой» неотличимо от «нет»).
func errHideExistence() error { return status.Error(codes.NotFound, "not found") }

// errAuthzUnavailable — iam.Check недоступен: fail-closed UNAVAILABLE.
func errAuthzUnavailable() error {
	return status.Error(codes.Unavailable, "authorization service unavailable")
}
