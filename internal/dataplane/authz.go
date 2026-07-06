// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package dataplane

import (
	"github.com/PRO-Robotech/kacho-registry/internal/domain"
)

// verb-relations data-plane authz — локальные alias'ы единого источника
// internal/domain (verb-bearing модель Kachō: repo-verb НЕ наследуется
// от namespace-tier). check.PermissionMap / handler/listauthz ссылаются на те же
// domain-константы: rename относительной строки — в одном месте, drift между
// planes исключён.
const (
	relVGet    = domain.FGARelationVGet
	relVList   = domain.FGARelationVList
	relVCreate = domain.FGARelationVCreate
	relVUpdate = domain.FGARelationVUpdate
)

// registryObject — FGA object namespace-реестра "registry_registry:<id>"
// (call-gate push-new: право создавать repo в namespace).
func registryObject(registryID string) string {
	return domain.FGAObjectRef(domain.FGAObjectTypeRegistry, registryID)
}

// repositoryObject — FGA object репозитория "registry_repository:<reg>/<repo>".
func repositoryObject(registryID, repo string) string {
	return domain.FGAObjectRef(domain.FGAObjectTypeRepository, registryID+"/"+repo)
}

// repositoryObjectFull — FGA object репозитория по полному имени "<reg>/<repo>"
// (для _catalog listauthz и cross-repo mount `from`).
func repositoryObjectFull(fullName string) string {
	return domain.FGAObjectRef(domain.FGAObjectTypeRepository, fullName)
}

// fgaSubject — FGA subject-строка из JWT `sub` (Kachō principal id). Делегирует
// единому domain.FGASubjectFromID (тип по id-prefix — единственный доступный
// data-plane дискриминатор, согласован с control-plane FGASubjectFromPrincipal).
func fgaSubject(sub string) string {
	return domain.FGASubjectFromID(sub)
}
