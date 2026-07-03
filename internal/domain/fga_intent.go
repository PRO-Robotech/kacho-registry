// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

import (
	"encoding/json"
	"fmt"
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

// FGA relation-строки owner-hierarchy tuple'ов registry_registry. `project`
// линкует ресурс к project-у (cascade tier'ов); `owner` — creator-tuple
// (обязателен: модель несёт relation owner, иначе creator-intent застрял бы unsent
// в outbox). Обе входят в allowedProxyRelations iam (fga-proxy privilege-guard).
const (
	FGARelationProject = "project"
	FGARelationOwner   = "owner"
)

// FGA register-intent event-types (parity с CHECK-constraint registry_outbox и с
// kacho-iam RegisterResource/UnregisterResource).
const (
	FGAEventRegister   = "fga.register"
	FGAEventUnregister = "fga.unregister"
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
		SubjectID: "project:" + projectID,
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
