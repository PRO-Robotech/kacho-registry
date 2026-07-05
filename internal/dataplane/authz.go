// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package dataplane

import (
	"strings"

	"github.com/PRO-Robotech/kacho-registry/internal/domain"
)

// verb-relations data-plane authz (verb-bearing модель Kachō, anti-#241: repo-verb
// НЕ наследуется от namespace-tier). Зеркалят check.PermissionMap / handler listauthz.
const (
	relVGet    = "v_get"
	relVList   = "v_list"
	relVCreate = "v_create"
	relVUpdate = "v_update"
)

// registryObject — FGA object namespace-реестра "registry_registry:<id>"
// (call-gate push-new: право создавать repo в namespace).
func registryObject(registryID string) string {
	return domain.FGAObjectTypeRegistry + ":" + registryID
}

// repositoryObject — FGA object репозитория "registry_repository:<reg>/<repo>".
func repositoryObject(registryID, repo string) string {
	return domain.FGAObjectTypeRepository + ":" + registryID + "/" + repo
}

// repositoryObjectFull — FGA object репозитория по полному имени "<reg>/<repo>"
// (для _catalog listauthz и cross-repo mount `from`).
func repositoryObjectFull(fullName string) string {
	return domain.FGAObjectTypeRepository + ":" + fullName
}

// fgaSubject — FGA subject-строка из JWT `sub` (Kachō principal id). Тип выводится по
// 3-символьному id-prefix: "usr" → user, прочее (в т.ч. "sva") → service_account.
// docker login сейчас — SA-key only (identity-only токен); user-scoped PAT
// подключается вторым validator'ом в IAM /token без изменений proxy. Пустой sub → ""
// (невалидный caller — AuthN не должен был его пропустить).
func fgaSubject(sub string) string {
	if sub == "" {
		return ""
	}
	if strings.HasPrefix(sub, "usr") {
		return "user:" + sub
	}
	return "service_account:" + sub
}
