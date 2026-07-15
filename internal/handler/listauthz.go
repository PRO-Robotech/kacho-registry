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

	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/PRO-Robotech/kacho-corelib/authz"
	"github.com/PRO-Robotech/kacho-corelib/operations"

	"github.com/PRO-Robotech/kacho-registry/internal/domain"
)

// repoAuthzConcurrency — верхняя граница параллельных per-repo authz-Check при
// row-фильтрации ОДНОЙ страницы каталога. Паритет с data-plane serveCatalog
// (catalogAuthzConcurrency): fan-out в iam ограничен, а не «по одному синхронно».
// Само число Check ограничивается окном page_size ДО фильтра (см. ListRepositories),
// поэтому здесь только concurrency-bound.
const repoAuthzConcurrency = 8

// Authorizer — узкий порт per-repo authz-Check (InternalIAMService.Check →
// OpenFGA/ReBAC). subject — FGA subject-строка ("user:usr_…" / "service_account:…"),
// relation — verb-relation (v_list/v_delete), object — FGA object-строка. Реализуется
// check.IAMCheckClient. nil → breakglass (authz bypass).
type Authorizer interface {
	Check(ctx context.Context, subject, relation, object string) (bool, error)
}

// verb-relations per-repo authz — локальные alias'ы единого источника internal/domain
// (для ScopeFiltered registry-RPC authz энфорсится ЗДЕСЬ, не в interceptor'е —
// repo-verb НЕ наследуется от namespace-tier). check.PermissionMap /
// dataplane/authz ссылаются на те же domain-константы: drift между planes исключён.
const (
	relationVList   = domain.FGARelationVList
	relationVGet    = domain.FGARelationVGet
	relationVCreate = domain.FGARelationVCreate
	relationVUpdate = domain.FGARelationVUpdate
	relationVDelete = domain.FGARelationVDelete
	relationAdmin   = domain.FGARelationAdmin
)

// registryObjectRef — FGA object namespace-реестра "registry_registry:<id>".
func registryObjectRef(registryID string) string {
	return domain.FGAObjectRef(domain.FGAObjectTypeRegistry, registryID)
}

// repositoryObjectRef — FGA object репозитория "registry_repository:<id>/<repo>".
func repositoryObjectRef(registryID, repository string) string {
	return domain.FGAObjectRef(domain.FGAObjectTypeRepository, registryID+"/"+repository)
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

// checkRepository — per-repo verb-Check config-overlay Repository RPC (GetRepository
// v_get / UpdateRepository v_update / DeleteRepository v_delete / RenameRepository
// v_update / ListReferrers v_get). deny|az-absent → NOT_FOUND "repository not found"
// (existence-hiding, БАЙТ-В-БАЙТ с use-case failNotFound — unauthorized неотличимо от
// absent, A08/C02/A15); az-error → UNAVAILABLE (fail-closed).
func (a repoAuthz) checkRepository(ctx context.Context, registryID, repository, relation string) error {
	allowed, err := a.check(ctx, relation, repositoryObjectRef(registryID, repository))
	if err != nil {
		return errAuthzUnavailable()
	}
	if !allowed {
		return errRepoHideExistence()
	}
	return nil
}

// registryGate — namespace call-gate по заданному verb-relation на registry_registry:
// <reg> (CreateRepository v_create — невидимый реестр existence-hidden, X04). deny →
// NOT_FOUND (existence-hiding); az-error → UNAVAILABLE (fail-closed).
func (a repoAuthz) registryGate(ctx context.Context, registryID, relation string) error {
	allowed, err := a.check(ctx, relation, registryObjectRef(registryID))
	if err != nil {
		return errAuthzUnavailable()
	}
	if !allowed {
		return errHideExistence()
	}
	return nil
}

// requireRegistryAdmin — admin-gate any-path-to-PUBLIC (D-6): subject обязан держать
// admin на registry_registry:<reg>. НЕ existence-hiding: caller уже доказал доступ к
// видимому ресурсу (v_create/v_update прошёл ДО этого гейта), поэтому deny честен коду —
// PERMISSION_DENIED с contract-текстом msg (B02/B08/B10); az-error → UNAVAILABLE.
// breakglass (nil az) → allow.
func (a repoAuthz) requireRegistryAdmin(ctx context.Context, registryID, msg string) error {
	allowed, err := a.check(ctx, relationAdmin, registryObjectRef(registryID))
	if err != nil {
		return errAuthzUnavailable()
	}
	if !allowed {
		return status.Error(codes.PermissionDenied, msg)
	}
	return nil
}

// filterRegistries — row-filter коллекции реестров: оставляет только реестры, на
// registry_registry:<id> которых subject имеет v_list. non-member → пустой список
// (200+empty, НЕ 403 — List не гейтится per-object Check). breakglass → все;
// az-error → UNAVAILABLE (не отдаём нефильтрованный список — no-leak).
//
// Fan-out ограничен: сами Check выполняются bounded-concurrency (repoAuthzConcurrency)
// — паритет с filterRepos/filterOperations (List latency не масштабируется линейно по
// числу реестров страницы). Результат детерминирован (indexed slice сохраняет входной
// порядок).
func (a repoAuthz) filterRegistries(ctx context.Context, regs []*domain.Registry) ([]*domain.Registry, error) {
	if a.az == nil {
		return regs, nil
	}
	subject := subjectFromContext(ctx)
	allowed := make([]bool, len(regs))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(repoAuthzConcurrency)
	for i, r := range regs {
		i, r := i, r
		g.Go(func() error {
			ok, err := a.az.Check(gctx, subject, relationVList, registryObjectRef(r.ID))
			if err != nil {
				return err
			}
			allowed[i] = ok
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, errAuthzUnavailable()
	}
	out := make([]*domain.Registry, 0, len(regs))
	for i, r := range regs {
		if allowed[i] {
			out = append(out, r)
		}
	}
	return out, nil
}

// filterRepos — per-repo row-filter каталога: оставляет только repos, на
// registry_repository:<reg>/<repo> которых subject имеет v_list (REG-22/23). breakglass
// → все; az-error → UNAVAILABLE (не отдаём нефильтрованный список — no-leak).
//
// Fan-out ограничен: (1) вызывающий (ListRepositories) передаёт УЖЕ окно page_size
// (bounded число Check per RPC — anti-DoS, CWE-770), (2) сами Check выполняются
// bounded-concurrency (repoAuthzConcurrency) — паритет с data-plane serveCatalog.
// Результат детерминирован (indexed slice сохраняет входной порядок имён ASC).
func (a repoAuthz) filterRepos(ctx context.Context, registryID string, repos []*domain.Repository) ([]*domain.Repository, error) {
	if a.az == nil {
		return repos, nil
	}
	subject := subjectFromContext(ctx)
	allowed := make([]bool, len(repos))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(repoAuthzConcurrency)
	for i, r := range repos {
		i, r := i, r
		g.Go(func() error {
			ok, err := a.az.Check(gctx, subject, relationVList, repositoryObjectRef(registryID, r.Name))
			if err != nil {
				return err
			}
			allowed[i] = ok
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, errAuthzUnavailable()
	}
	out := make([]*domain.Repository, 0, len(repos))
	for i, r := range repos {
		if allowed[i] {
			out = append(out, r)
		}
	}
	return out, nil
}

// filterOperations — per-repo row-filter истории операций реестра (ListOperations).
// Interceptor гейтит RPC ТОЛЬКО namespace v_list на registry_registry:<reg>; но
// операция, scoped к конкретному sub-repo (DeleteTag → metadata.repository +
// Description "Delete tag … of <reg>/<repo>"), раскрыла бы namespace-viewer'у, НЕ
// имеющему v_list на этот repo, само его существование (имя/тег) — existence-oracle,
// обходящий per-repo isolation, которую держат ListTags/checkRepo. Поэтому repo-scoped
// операция видна ТОЛЬКО при per-repo v_list на registry_repository:<reg>/<repo> (тот
// же Check, что checkRepo/ListTags); иначе тихо выпадает (existence-hiding: без ошибки).
// Registry-level операции (no repository в metadata) остаются видны — namespace v_list
// (interceptor) достаточно.
//
// registryID берётся из ЗАПРОСА (не из metadata) — операции уже отфильтрованы
// use-case'ом по resource_id=registryID, а доверять registry_id из metadata для
// построения authz-объекта незачем. breakglass → все; az-error → UNAVAILABLE
// (fail-closed, не отдаём частичный список — паритет с filterRepos/filterRegistries).
// Fan-out bounded-concurrency (repoAuthzConcurrency), детерминированный порядок.
func (a repoAuthz) filterOperations(ctx context.Context, registryID string, ops []operations.Operation) ([]operations.Operation, error) {
	if a.az == nil {
		return ops, nil
	}
	subject := subjectFromContext(ctx)
	keep := make([]bool, len(ops))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(repoAuthzConcurrency)
	for i := range ops {
		repository, scoped := repositoryOfOperation(&ops[i])
		if !scoped {
			keep[i] = true // registry-level op — namespace v_list (interceptor) достаточно
			continue
		}
		i := i
		g.Go(func() error {
			ok, err := a.az.Check(gctx, subject, relationVList, repositoryObjectRef(registryID, repository))
			if err != nil {
				return err
			}
			keep[i] = ok
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, errAuthzUnavailable()
	}
	out := make([]operations.Operation, 0, len(ops))
	for i := range ops {
		if keep[i] {
			out = append(out, ops[i])
		}
	}
	return out, nil
}

// repositoryOfOperation — sub-repository, к которому scoped операция (из её metadata),
// и true если op — repo-scoped. Registry-level op (metadata без непустого поля
// "repository", напр. Create/Update/Delete/GC) → ("", false). Metadata Any
// интроспектится generic'ом (protoreflect-поле "repository") — любой новый
// repo-scoped op-тип покрывается автоматически, без перечисления конкретных
// *Metadata-типов. Неразбираемая metadata (не должно случаться: registry-op-типы
// зарегистрированы в глобальном proto-registry) → registry-level (нет repository для
// leak'а).
func repositoryOfOperation(op *operations.Operation) (string, bool) {
	if op == nil || op.Metadata == nil {
		return "", false
	}
	msg, err := op.Metadata.UnmarshalNew()
	if err != nil {
		return "", false
	}
	fd := msg.ProtoReflect().Descriptor().Fields().ByName("repository")
	if fd == nil || fd.Kind() != protoreflect.StringKind {
		return "", false
	}
	repository := msg.ProtoReflect().Get(fd).String()
	if repository == "" {
		return "", false
	}
	return repository, true
}

// errHideExistence — deny на объект, который caller не вправе видеть: NOT_FOUND
// (existence-hiding — «есть-но-не-твой» неотличимо от «нет»).
func errHideExistence() error { return status.Error(codes.NotFound, "not found") }

// errRepoHideExistence — existence-hiding config-overlay Repository RPC: NOT_FOUND
// "repository not found" — БАЙТ-В-БАЙТ с use-case failNotFound (unauthorized неотличимо
// от absent; A08/C02/A15). Отдельный текст от errHideExistence (namespace-level "not
// found"), т.к. Repository-контракт несёт "repository not found".
func errRepoHideExistence() error { return status.Error(codes.NotFound, "repository not found") }

// errAuthzUnavailable — iam.Check недоступен: fail-closed UNAVAILABLE.
func errAuthzUnavailable() error {
	return status.Error(codes.Unavailable, "authorization service unavailable")
}
