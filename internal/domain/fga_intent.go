// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

import (
	"encoding/json"
	"fmt"
	"strings"
)

// FGA-register-intent — чистые domain-value-типы transactional-outbox owner-tuple
// реле через IAM. Вместо прямой записи tuple в OpenFGA после commit'а
// (dual-write) writer-tx Create/Delete/Update пишет RegisterIntent строкой в
// registry_outbox В ТОЙ ЖЕ tx (один commit). Отдельный register-drainer применяет
// каждый intent через kacho-iam InternalIAMService.RegisterResource /
// UnregisterResource по mTLS — идемпотентно, at-least-once, owner-tuple не теряется.
//
// Файл — leaf (только stdlib): импортируется и writer-side (emit), и client-side
// (decode) без import-цикла и без pgx/grpc в контракте.

// FGAObjectTypeRegistry — FGA object-type namespace-реестра. object-prefix
// `registry_` РАВЕН имени сервиса kacho-registry → iam-side ValidateProxyTuple
// domain-binding без moduleObjectDomain-mapping (в отличие от граблей nlb→lb).
const FGAObjectTypeRegistry = "registry_registry"

// FGAObjectTypeRepository — FGA object-type конкретного репозитория (parent =
// registry_registry). object-id — "<registryID>/<repo>". Per-repo verb-relations
// развязаны от namespace-tier: доступ к repo требует отдельного
// verb-tuple, namespace-viewer НЕ видит все repos автоматически.
const FGAObjectTypeRepository = "registry_repository"

// FGAObjectTypeProject — FGA object-type parent-проекта (владелец в модели kacho-iam
// — тип `project`). Единый источник для обоих planes: project-hierarchy tuple
// (FGAProjectTuple) и create-child interceptor-Check (check.PermissionMap). Раньше
// check держал независимый литерал `iam_project` — тип, которого НЕТ в FGA-модели →
// Create.Check всегда denied. Константа исключает этот drift.
const FGAObjectTypeProject = "project"

// FGA relation-строки owner-hierarchy tuple'ов registry_registry. `project`
// линкует ресурс к project-у (cascade tier'ов); `owner` — creator-tuple
// (обязателен: модель несёт relation owner, иначе creator-intent застрял бы unsent
// в outbox). Обе входят в allowedProxyRelations iam (fga-proxy privilege-guard).
const (
	FGARelationProject = "project"
	FGARelationOwner   = "owner"
	// FGARelationParent — hierarchy-relation репозитория к его namespace-реестру
	// (registry_repository #parent @registry_registry). Входит в allowedProxyRelations
	// iam (fga-proxy privilege-guard): модуль вправе проксировать только
	// {project,account,parent,owner}.
	FGARelationParent = "parent"
)

// FGA register-intent event-types (parity с CHECK-constraint registry_outbox и с
// kacho-iam RegisterResource/UnregisterResource).
const (
	FGAEventRegister   = "fga.register"
	FGAEventUnregister = "fga.unregister"
)

// FGA verb-relation-строки (verb-bearing модель Kachō: repo-verb НЕ
// наследуется от namespace-tier). ЕДИНЫЙ источник истины для обоих planes —
// check.PermissionMap (control-plane interceptor-gate), handler/listauthz
// (ScopeFiltered row-filter) и dataplane/authz (OCI push/pull) ссылаются сюда,
// не переобъявляя литералы (иначе rename одной строки рассинхронит планы).
const (
	FGARelationVGet    = "v_get"
	FGARelationVList   = "v_list"
	FGARelationVCreate = "v_create"
	FGARelationVUpdate = "v_update"
	FGARelationVDelete = "v_delete"
)

// FGARelationAdmin — admin-tier relation на registry_registry. Любой путь, где
// принципал САМ приводит ресурс к PUBLIC (per-repo flip B02, create-with-PUBLIC B08,
// default_visibility→PUBLIC B10) требует этого relation (D-6 any-path-to-PUBLIC gate).
const FGARelationAdmin = "admin"

// FGASubjectPublicWildcard — FGA subject-строка анонимного/публичного принципала
// ("user:*"). visibility=PUBLIC ⟺ существует tuple "user:* v_get registry_repository:
// <reg>/<repo>" (D-7): анонимный pull резолвится в этот wildcard subject. Governance —
// register/unregister по ИТОГОВОМУ visibility overlay-строки (B01/B06/B12).
const FGASubjectPublicWildcard = FGASubjectTypeUser + ":*"

// FGA subject-type namespaces аутентифицированного principal (parity с kacho-iam
// FGA-моделью). Разделяемы обоими encoders (FGASubjectFromPrincipal — control-plane
// по Principal.Type; FGASubjectFromID — data-plane по id-prefix), чтобы тип-строка
// жила в одном месте.
const (
	FGASubjectTypeUser           = "user"
	FGASubjectTypeServiceAccount = "service_account"
)

// Kachō principal id-prefix'ы (parity с kacho-iam domain PrefixUser/PrefixServiceAccount).
// Data-plane имеет только id из верифицированного JWT (без Principal.Type), поэтому
// выводит subject-тип по этим префиксам — единственный доступный ему дискриминатор.
const (
	principalIDPrefixUser           = "usr"
	principalIDPrefixServiceAccount = "sva"
)

// FGATuple — один owner-hierarchy tuple intent "<subject> #<relation> @<object>".
// Имена полей совпадают с kacho-proto RegisterResourceRequest (subject_id /
// relation / object) — applier мапит 1:1 без трансляции.
type FGATuple struct {
	SubjectID string `json:"subject_id"`
	Relation  string `json:"relation"`
	Object    string `json:"object"`
}

// Valid — все три компонента непусты. Неполный tuple — caller-side баг (drainer
// трактует декодированный неполный tuple как poison, не transient-retry).
func (t FGATuple) Valid() bool {
	return t.SubjectID != "" && t.Relation != "" && t.Object != ""
}

// RegisterIntent — полный набор owner-hierarchy tuple'ов одного реестра
// (project-hierarchy + creator). Весь набор — одна outbox-строка = одна логическая
// единица apply. Несёт labels + parent-project для output-only resource_mirror в
// iam (питает label-selectable authz-scope; source of truth = kacho-registry).
type RegisterIntent struct {
	// Kind — вид ресурса для observability ("Registry"). Не участвует в apply.
	Kind string `json:"kind"`
	// ResourceID — id ресурса для observability/tracing. Не участвует в apply.
	ResourceID string `json:"resource_id"`
	// Tuples — набор tuple-намерений (project-tuple ПЕРВЫМ — grabli listener-
	// visibility: project-tuple применяется раньше creator-tuple).
	Tuples []FGATuple `json:"tuples"`
	// Labels — копия labels реестра (label-selectable authz-scope в iam-mirror).
	// На Update несёт НОВЫЕ labels → снятая метка реально отзывает label-scope.
	Labels map[string]string `json:"labels,omitempty"`
	// ParentProjectID — owning-project (containment scope в iam-mirror).
	ParentProjectID string `json:"parent_project_id,omitempty"`
}

// Marshal сериализует intent в JSONB-payload registry_outbox.payload.
func (i RegisterIntent) Marshal() ([]byte, error) {
	b, err := json.Marshal(i)
	if err != nil {
		return nil, fmt.Errorf("marshal fga register intent: %w", err)
	}
	return b, nil
}

// UnmarshalRegisterIntent разбирает JSONB-payload registry_outbox обратно в intent.
func UnmarshalRegisterIntent(payload []byte) (RegisterIntent, error) {
	var i RegisterIntent
	if err := json.Unmarshal(payload, &i); err != nil {
		return RegisterIntent{}, fmt.Errorf("unmarshal fga register intent: %w", err)
	}
	return i, nil
}

// FGAObjectRef строит "<objectType>:<objectID>" FGA object-строку.
func FGAObjectRef(objectType, objectID string) string {
	return objectType + ":" + objectID
}

// FGAProjectTuple — project-hierarchy tuple
// "project:<projectID> #project @registry_registry:<registryID>".
func FGAProjectTuple(registryID, projectID string) FGATuple {
	return FGATuple{
		SubjectID: FGAObjectRef(FGAObjectTypeProject, projectID),
		Relation:  FGARelationProject,
		Object:    FGAObjectRef(FGAObjectTypeRegistry, registryID),
	}
}

// FGAOwnerTuple — creator owner-tuple
// "<subject> #owner @registry_registry:<registryID>". subject — FGA subject-строка
// (напр. "user:usr…") аутентифицированного principal. Пустой subject → неполный
// tuple; caller пропускает его (system-инициированный ресурс без human-owner).
func FGAOwnerTuple(subject, registryID string) FGATuple {
	return FGATuple{
		SubjectID: subject,
		Relation:  FGARelationOwner,
		Object:    FGAObjectRef(FGAObjectTypeRegistry, registryID),
	}
}

// FGASubjectFromPrincipal — FGA subject-строка "<type>:<id>" аутентифицированного
// principal, либо "" для system/unauthenticated (creator-tuple тогда пропускается).
// "system" трактуется как unauthenticated.
func FGASubjectFromPrincipal(principalType, principalID string) string {
	if principalType == "" || principalID == "" || principalType == "system" {
		return ""
	}
	return principalType + ":" + principalID
}

// FGASubjectFromID — FGA subject-строка из одного Kachō principal id (data-plane
// имеет только `sub` из верифицированного JWT, без Principal.Type). Тип выводится по
// id-prefix — единственному дискриминатору, доступному без обращения к iam: usr_ →
// user, sva_ → service_account. В схеме ids Kachō id-prefix и Principal.Type
// согласованы (usr_ всегда type=user), поэтому результат совпадает с
// control-plane FGASubjectFromPrincipal для тех же principal'ов. Пустой id → ""
// (невалидный caller — AuthN не должен был его пропустить). Неизвестный prefix
// трактуется как service_account (docker login сейчас — SA-key only; сохраняет
// прежнее поведение data-plane heuristic'а).
func FGASubjectFromID(principalID string) string {
	switch {
	case principalID == "":
		return ""
	case strings.HasPrefix(principalID, principalIDPrefixUser):
		return FGAObjectRef(FGASubjectTypeUser, principalID)
	case strings.HasPrefix(principalID, principalIDPrefixServiceAccount):
		return FGAObjectRef(FGASubjectTypeServiceAccount, principalID)
	default:
		// docker login сейчас — SA-key only (identity-only токен); неизвестный prefix
		// → service_account (сохраняет прежнее поведение data-plane heuristic'а).
		return FGAObjectRef(FGASubjectTypeServiceAccount, principalID)
	}
}

// FGASubjectForPrincipalID — resolve a verified data-plane principal id to its FGA
// subject, honoring the configured anonymous principal id (RG-1 D-7). When
// anonPrincipalID is non-empty AND principalID equals it, the caller is the public
// anonymous principal and resolves to FGASubjectPublicWildcard ("user:*"): a valid
// anon Bearer thus reads only PUBLIC repos (via the repo's `user:* v_get` tuple) and
// can NEVER write (no wildcard write relation exists) — B03 / B14. Every other
// principalID resolves by id-prefix via FGASubjectFromID.
//
// anonPrincipalID=="" → anonymous pull DISABLED (secure-by-default): a token whose sub
// happens to equal the anon id resolves as an ordinary principal, never silently
// gaining the wildcard. The anon principal id is deployment-configured (the iam anon
// Hydra client id); deploy MUST keep it reserved (no real principal shares it), since
// a token proving sub==anonPrincipalID can only be minted by holding the anon client's
// key (the anon flow).
func FGASubjectForPrincipalID(principalID, anonPrincipalID string) string {
	if anonPrincipalID != "" && principalID == anonPrincipalID {
		return FGASubjectPublicWildcard
	}
	return FGASubjectFromID(principalID)
}

// RegisterIntentForCreate — intent на Create реестра: project-tuple ПЕРВЫМ, затем
// (при аутентифицированном principal) owner-tuple. Несёт labels + parent-project
// для label-selectable authz-scope в iam-mirror.
func RegisterIntentForCreate(r *Registry, principalType, principalID string) RegisterIntent {
	tuples := []FGATuple{FGAProjectTuple(r.ID, r.ProjectID)}
	if subject := FGASubjectFromPrincipal(principalType, principalID); subject != "" {
		tuples = append(tuples, FGAOwnerTuple(subject, r.ID))
	}
	return RegisterIntent{
		Kind:            "Registry",
		ResourceID:      r.ID,
		Tuples:          tuples,
		Labels:          copyLabels(r.Labels),
		ParentProjectID: r.ProjectID,
	}
}

// RegisterIntentForUpdate — mirror-feed re-register на Update: project-tuple с
// ОБНОВЛЁННЫМИ labels (без creator-tuple). Снятая из labels метка реально отзывает
// label-scoped доступ в iam-mirror (security-инвариант против label-clear no-op).
func RegisterIntentForUpdate(r *Registry) RegisterIntent {
	return RegisterIntent{
		Kind:            "Registry",
		ResourceID:      r.ID,
		Tuples:          []FGATuple{FGAProjectTuple(r.ID, r.ProjectID)},
		Labels:          copyLabels(r.Labels),
		ParentProjectID: r.ProjectID,
	}
}

// UnregisterIntentForDelete — unregister-intent на Delete: снимает project-tuple
// (owner-tuple снимается iam-side GC при unregister project-hierarchy).
func UnregisterIntentForDelete(registryID, projectID string) RegisterIntent {
	return RegisterIntent{
		Kind:       "Registry",
		ResourceID: registryID,
		Tuples:     []FGATuple{FGAProjectTuple(registryID, projectID)},
	}
}

// repoObjectID — FGA object-id репозитория "<registryID>/<repo>".
func repoObjectID(registryID, repo string) string { return registryID + "/" + repo }

// FGARepoParentTuple — parent-hierarchy tuple репозитория
// "registry_registry:<reg> #parent @registry_repository:<reg>/<repo>". Линкует repo
// к namespace-реестру (наследование tier'ов project→registry→repository).
func FGARepoParentTuple(registryID, repo string) FGATuple {
	return FGATuple{
		SubjectID: FGAObjectRef(FGAObjectTypeRegistry, registryID),
		Relation:  FGARelationParent,
		Object:    FGAObjectRef(FGAObjectTypeRepository, repoObjectID(registryID, repo)),
	}
}

// FGARepoOwnerTuple — creator owner-tuple репозитория
// "<subject> #owner @registry_repository:<reg>/<repo>". subject — FGA subject-строка
// толкающего principal ("service_account:sva…"); пустой subject → tuple пропускается.
func FGARepoOwnerTuple(registryID, repo, subject string) FGATuple {
	return FGATuple{
		SubjectID: subject,
		Relation:  FGARelationOwner,
		Object:    FGAObjectRef(FGAObjectTypeRepository, repoObjectID(registryID, repo)),
	}
}

// RegisterIntentForRepoPush — intent на первый push нового repo: parent-tuple ПЕРВЫМ
// (repo линкуется к реестру раньше creator-tuple — тот же урок порядка, что для
// project→owner), затем (при аутентифицированном pushing-principal) owner-tuple.
// projectID — owning-project реестра-владельца; несётся как ParentProjectID, чтобы
// resource_mirror строка репо в iam получила containment scope и reconciler
// материализовал per-object v_* (без него репо невидим/непуллим даже владельцу).
// Labels репо не несёт (у type нет own-table labels — label-scope неприменим).
// subject — FGA subject толкающего.
func RegisterIntentForRepoPush(registryID, repo, projectID, subject string) RegisterIntent {
	tuples := []FGATuple{FGARepoParentTuple(registryID, repo)}
	if subject != "" {
		tuples = append(tuples, FGARepoOwnerTuple(registryID, repo, subject))
	}
	return RegisterIntent{
		Kind:            "Repository",
		ResourceID:      repoObjectID(registryID, repo),
		Tuples:          tuples,
		ParentProjectID: projectID,
	}
}

// UnregisterIntentForRepo — unregister-intent на удаление последнего тега repo:
// снимает parent-tuple registry_repository:<reg>/<repo> (owner-tuple снимается
// iam-side GC при unregister parent-hierarchy) — не оставляем висячий authz-объект.
func UnregisterIntentForRepo(registryID, repo string) RegisterIntent {
	return RegisterIntent{
		Kind:       "Repository",
		ResourceID: repoObjectID(registryID, repo),
		Tuples:     []FGATuple{FGARepoParentTuple(registryID, repo)},
	}
}

// FGARepoPublicGetTuple — public-read wildcard tuple репозитория
// "user:* #v_get @registry_repository:<reg>/<repo>". Существование этого tuple ⟺
// visibility=PUBLIC (D-7): анонимный (`user:*`) data-plane read проходит Check.
func FGARepoPublicGetTuple(registryID, repo string) FGATuple {
	return FGATuple{
		SubjectID: FGASubjectPublicWildcard,
		Relation:  FGARelationVGet,
		Object:    FGAObjectRef(FGAObjectTypeRepository, repoObjectID(registryID, repo)),
	}
}

// RegisterIntentForRepoPublicGrant — register-intent public-read wildcard tuple:
// материализует "user:* v_get" на repo (visibility стал PUBLIC — per-repo flip B01,
// create-with-PUBLIC B08, inherited-default B12). Идемпотентно at-least-once через
// outbox: повторный register того же wildcard дедуплицируется iam-side.
func RegisterIntentForRepoPublicGrant(registryID, repo string) RegisterIntent {
	return RegisterIntent{
		Kind:       "RepositoryPublicGrant",
		ResourceID: repoObjectID(registryID, repo),
		Tuples:     []FGATuple{FGARepoPublicGetTuple(registryID, repo)},
	}
}

// UnregisterIntentForRepoPublicGrant — unregister-intent public-read wildcard tuple:
// снимает "user:* v_get" (visibility стал PRIVATE — flip B06 — либо repo удалён/
// переименован). anon pull снова fail-closed 404. Per-subject grants не трогаются.
func UnregisterIntentForRepoPublicGrant(registryID, repo string) RegisterIntent {
	return RegisterIntent{
		Kind:       "RepositoryPublicGrant",
		ResourceID: repoObjectID(registryID, repo),
		Tuples:     []FGATuple{FGARepoPublicGetTuple(registryID, repo)},
	}
}

// copyLabels — defensive-копия карты labels (mirror не должен ссылаться на
// внутреннюю карту domain-объекта). Пустая карта → nil (omitempty в payload).
func copyLabels(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
