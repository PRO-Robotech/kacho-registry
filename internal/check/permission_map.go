// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package check

import (
	"fmt"

	"github.com/PRO-Robotech/kacho-corelib/authz"
	registryv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/registry/v1"

	"github.com/PRO-Robotech/kacho-registry/internal/domain"
)

// FGA-скоупинг kacho-registry (verb-bearing модель Kachō: verb-relations
// развязаны от grant-tier). Два FGA-типа:
//   - registry_registry     — namespace (List/Create/Delete + list-filter).
//   - registry_repository    — конкретный repo (pull/push/delete, parent=registry).
//
// Create — create-child: Check на PARENT-объекте project (ресурса
// registry_registry:<new-id> ещё нет). List/ListRepositories/ListTags/DeleteTag
// дополнительно per-repo row-filter'уются В ХЕНДЛЕРЕ (gateway List-exempt) — запись
// в PermissionMap здесь работает как namespace call-gate.
// object-type / verb-relation vocabulary — единый источник в internal/domain;
// здесь только локальные alias'ы (никаких независимых строковых литералов —
// rename в domain автоматически распространяется на оба plane'а, drift исключён).
const (
	objectTypeRegistry   = domain.FGAObjectTypeRegistry
	objectTypeRepository = domain.FGAObjectTypeRepository
	objectTypeProject    = domain.FGAObjectTypeProject

	relVGet    = domain.FGARelationVGet
	relVList   = domain.FGARelationVList
	relVCreate = domain.FGARelationVCreate
	relVUpdate = domain.FGARelationVUpdate
	relVDelete = domain.FGARelationVDelete
)

// registryObject — extractor (registry_registry, <registryId>) из request'ов,
// несущих registry_id (Get/Update/Delete/ListRepositories + Internal GC/Stats).
func registryObject() authz.ObjectExtractor {
	return func(req any) (string, string, error) {
		var id string
		switch r := req.(type) {
		case *registryv1.GetRegistryRequest:
			id = r.GetRegistryId()
		case *registryv1.UpdateRegistryRequest:
			id = r.GetRegistryId()
		case *registryv1.DeleteRegistryRequest:
			id = r.GetRegistryId()
		case *registryv1.ListRepositoriesRequest:
			id = r.GetRegistryId()
		case *registryv1.ListRegistryOperationsRequest:
			id = r.GetRegistryId()
		case *registryv1.TriggerGarbageCollectionRequest:
			id = r.GetRegistryId()
		case *registryv1.GetRegistryStatsRequest:
			id = r.GetRegistryId()
		default:
			return "", "", fmt.Errorf("registry object extractor: unexpected request %T", req)
		}
		return objectTypeRegistry, id, nil
	}
}

// projectObject — extractor (project, <projectId>) для create-child Check на
// parent-project (Create) и project-scoped call-gate (List).
func projectObject() authz.ObjectExtractor {
	return func(req any) (string, string, error) {
		var pid string
		switch r := req.(type) {
		case *registryv1.CreateRegistryRequest:
			pid = r.GetProjectId()
		case *registryv1.ListRegistriesRequest:
			pid = r.GetProjectId()
		default:
			return "", "", fmt.Errorf("project object extractor: unexpected request %T", req)
		}
		return objectTypeProject, pid, nil
	}
}

// repositoryObject — extractor (registry_repository, <registryId>/<repo>) для
// per-repo verb Check (ListTags/DeleteTag).
func repositoryObject() authz.ObjectExtractor {
	return func(req any) (string, string, error) {
		var id, repo string
		switch r := req.(type) {
		case *registryv1.ListTagsRequest:
			id, repo = r.GetRegistryId(), r.GetRepository()
		case *registryv1.DeleteTagRequest:
			id, repo = r.GetRegistryId(), r.GetRepository()
		default:
			return "", "", fmt.Errorf("repository object extractor: unexpected request %T", req)
		}
		return objectTypeRepository, id + "/" + repo, nil
	}
}

// PermissionMap сопоставляет каждый registry-RPC → требуемое verb-relation +
// object extractor (зеркалит раздел 2 дизайна). List/ListRepositories/ListTags/DeleteTag
// несут namespace/repo call-gate; финальный per-repo row-filter — в хендлере.
func PermissionMap() authz.RPCMap {
	return authz.RPCMap{
		// ---- control-plane RegistryService (public :9090) ----
		"/kacho.cloud.registry.v1.RegistryService/Get": {
			Relation:   relVGet,
			Extract:    registryObject(),
			Permission: "registry.registries.get",
		},
		// List (registries collection) авторизуется В ХЕНДЛЕРЕ (ScopeFiltered):
		// interceptor пропускает per-RPC Check, а handler делает listauthz row-filter
		// по registry_registry v_list. Единичный per-RPC Check здесь семантически
		// неверен — collection не несёт single object (extract вернул бы пустой
		// object-id коллекции → "empty object id" → 403 на всю выборку). non-member →
		// 200+empty (exempt-parity). Relation/Extract сохранены как catalog-doc.
		"/kacho.cloud.registry.v1.RegistryService/List": {
			Relation:      relVList,
			Extract:       projectObject(),
			Permission:    "registry.registries.list",
			ScopeFiltered: true,
		},
		"/kacho.cloud.registry.v1.RegistryService/Create": {
			Relation:   relVCreate,
			Extract:    projectObject(),
			Permission: "registry.registries.create",
		},
		"/kacho.cloud.registry.v1.RegistryService/Update": {
			Relation:   relVUpdate,
			Extract:    registryObject(),
			Permission: "registry.registries.update",
		},
		"/kacho.cloud.registry.v1.RegistryService/Delete": {
			Relation:   relVDelete,
			Extract:    registryObject(),
			Permission: "registry.registries.delete",
		},
		// ListOperations — per-resource история операций реестра. Interceptor-gated
		// single-object Check v_list на registry_registry:<id> (namespace call-gate,
		// как Get) — этот per-RPC Check остаётся (защищает registry-level операции и
		// гейтит весь RPC). НО операции, scoped к конкретному sub-repo (DeleteTag →
		// metadata.repository + Description "Delete tag … of <reg>/<repo>"),
		// ДОПОЛНИТЕЛЬНО per-repo row-фильтруются В ХЕНДЛЕРЕ (filterOperations) по
		// v_list на registry_repository:<reg>/<repo> — иначе namespace-viewer БЕЗ
		// доступа к чужому repo вывел бы его существование/тег из истории операций
		// (existence-oracle, обходящий per-repo isolation ListTags/checkRepo).
		// Registry-level операции (no repository в metadata) видны под namespace
		// v_list. Единичный interceptor-Check row-filter каталога не покрывает —
		// поэтому фильтр в handler (как List/ListRepositories/ListTags).
		"/kacho.cloud.registry.v1.RegistryService/ListOperations": {
			Relation:   relVList,
			Extract:    registryObject(),
			Permission: "registry.registries.listOperations",
		},
		// ListRepositories/ListTags/DeleteTag авторизуются В ХЕНДЛЕРЕ (ScopeFiltered):
		// interceptor пропускает per-RPC Check, а handler делает call-gate + per-repo
		// row-filter + existence-hiding (deny→NOT_FOUND). Единичный interceptor-Check
		// не покрыл бы row-filter каталога и вернул бы PermissionDenied вместо NOT_FOUND
		// (раскрыв факт существования чужого repo). Relation/Extract сохранены как
		// permission-catalog документация; энфорс — handler.
		"/kacho.cloud.registry.v1.RegistryService/ListRepositories": {
			Relation:      relVList,
			Extract:       registryObject(),
			Permission:    "registry.repositories.list",
			ScopeFiltered: true,
		},
		"/kacho.cloud.registry.v1.RegistryService/ListTags": {
			Relation:      relVList,
			Extract:       repositoryObject(),
			Permission:    "registry.repositories.list",
			ScopeFiltered: true,
		},
		"/kacho.cloud.registry.v1.RegistryService/DeleteTag": {
			Relation:      relVDelete,
			Extract:       repositoryObject(),
			Permission:    "registry.repositories.delete",
			ScopeFiltered: true,
		},

		// ---- OperationService (LRO poll, proto `kacho.cloud.operation`, NOT `.v1`) ----
		// op-id opaque; авторизация на data-уровне (op принадлежит ресурсу вызывающего).
		// Public exempt из per-RPC Check — иначе gateway opsProxy форвардит Get/Cancel
		// сюда, а fail-closed interceptor отвергает unmapped RPC → poll недостижим.
		"/kacho.cloud.operation.OperationService/Get":    {Public: true},
		"/kacho.cloud.operation.OperationService/Cancel": {Public: true},

		// ---- admin InternalRegistryService (cluster-internal :9091) ----
		"/kacho.cloud.registry.v1.InternalRegistryService/TriggerGarbageCollection": {
			Relation:   relVDelete,
			Extract:    registryObject(),
			Permission: "registry.registries.gc",
		},
		"/kacho.cloud.registry.v1.InternalRegistryService/GetRegistryStats": {
			Relation:   relVGet,
			Extract:    registryObject(),
			Permission: "registry.registries.stats",
		},
	}
}
