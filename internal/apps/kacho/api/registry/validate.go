// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	"github.com/PRO-Robotech/kacho-corelib/ids"
	corevalidate "github.com/PRO-Robotech/kacho-corelib/validate"

	"github.com/PRO-Robotech/kacho-registry/internal/domain"
)

// ValidateRegistryID отсекает malformed registry-id синхронно первым стейтментом
// RPC: prefix `reg` (family-agnostic) → InvalidArgument "invalid registry id '<X>'".
// Пустой id пропускается (required-проверка — отдельно у caller'а). Экспортирован —
// единый канонический валидатор для use-case и handler-предчека ScopeFiltered-RPC
// (текст ошибки — часть контракта, не дублируем правило по слоям).
func ValidateRegistryID(id string) error {
	return corevalidate.ResourceID("registry", ids.PrefixRegistry, id)
}

// validatePageSize приводит page_size к контракту List (0→default 50, вне [0..1000]
// → InvalidArgument). Возвращает effective-значение для LIMIT.
func validatePageSize(size int64) (int64, error) {
	return corevalidate.PageSize("page_size", size)
}

// knownUpdateFields — whitelist update_mask Registry. name/project_id входят как
// известные, но hard-immutable (см. immutableUpdateFields) — их наличие в mask
// даёт InvalidArgument с каноничным immutable-текстом, а не unknown-field.
var knownUpdateFields = map[string]struct{}{
	"name":               {},
	"project_id":         {},
	"projectId":          {},
	"description":        {},
	"labels":             {},
	"default_visibility": {},
	"defaultVisibility":  {},
}

// immutableUpdateFields → каноничный immutable-текст (update_mask
// discipline): поле в mask, но менять нельзя после Create. name — mutable
// (смена не трогает endpoint/zot по id), поэтому здесь только project_id.
var immutableUpdateFields = map[string]string{
	"project_id": "projectId is immutable after Registry.Create",
	"projectId":  "projectId is immutable after Registry.Create",
}

// knownRepoUpdateFields — whitelist update_mask config-overlay Repository (RG-1).
// name/registry_id входят как известные, но hard-immutable (см. immutableRepoUpdateFields):
// их наличие → InvalidArgument с каноничным immutable-текстом (смена имени — только
// RenameRepository), а не generic unknown-field.
var knownRepoUpdateFields = map[string]struct{}{
	"description": {},
	"labels":      {},
	"visibility":  {},
	"name":        {},
	"registry_id": {},
	"registryId":  {},
}

// immutableRepoUpdateFields → каноничный immutable-текст. name — hard-immutable для
// Update (смена имени только RenameRepository); registry_id — натуральный ключ.
var immutableRepoUpdateFields = map[string]string{
	"name":        "name is immutable after Repository.Create",
	"registry_id": "registryId is immutable after Repository.Create",
	"registryId":  "registryId is immutable after Repository.Create",
}

// resolveRepoUpdateMask применяет update_mask discipline к RepositoryConfigUpdate:
//   - immutable поле (name/registry_id) → InvalidArgument (каноничный immutable-текст,
//     ДО UpdateMask — иначе known-set отверг бы их как generic unknown, api-conventions.md);
//   - unknown поле → InvalidArgument (corevalidate.UpdateMask с known-set);
//   - пустой mask → full-object PATCH (description/labels/visibility);
//   - mutable поле → соответствующий Apply*-флаг.
func resolveRepoUpdateMask(spec RepositoryConfigUpdate, mask []string) (RepositoryConfigUpdate, error) {
	for _, p := range mask {
		if msg, ok := immutableRepoUpdateFields[p]; ok {
			return spec, failInvalidArg("%s", msg)
		}
	}
	if err := corevalidate.UpdateMask("update_mask", mask, knownRepoUpdateFields); err != nil {
		return spec, err
	}
	if len(mask) == 0 {
		spec.ApplyDescription = true
		spec.ApplyLabels = true
		spec.ApplyVisibility = true
		return spec, nil
	}
	for _, p := range mask {
		switch p {
		case "description":
			spec.ApplyDescription = true
		case "labels":
			spec.ApplyLabels = true
		case "visibility":
			spec.ApplyVisibility = true
		}
	}
	return spec, nil
}

// resolveUpdateMask применяет update_mask discipline к UpdateSpec:
//   - unknown поле → InvalidArgument (corevalidate.UpdateMask);
//   - immutable поле (project) → InvalidArgument (каноничный текст);
//   - пустой mask → full-object PATCH (все mutable-поля; name — только если задан
//     в теле, иначе description/labels-only PATCH не должен «очистить» имя);
//   - mutable поле → соответствующий Apply*-флаг.
//
// Мутирует spec.ApplyName/ApplyDescription/ApplyLabels, возвращает нормализованный spec.
func resolveUpdateMask(spec UpdateSpec) (UpdateSpec, error) {
	if err := corevalidate.UpdateMask("update_mask", spec.Mask, knownUpdateFields); err != nil {
		return spec, err
	}
	for _, p := range spec.Mask {
		if msg, ok := immutableUpdateFields[p]; ok {
			return spec, failInvalidArg("%s", msg)
		}
	}
	if len(spec.Mask) == 0 {
		// full-object PATCH: применяются все mutable-поля. name применяем только
		// если он реально передан (непустой) — иначе PATCH без имени (обновляющий
		// лишь description/labels) не должен пытаться выставить пустое имя.
		spec.ApplyName = spec.Name != ""
		spec.ApplyDescription = true
		spec.ApplyLabels = true
		// default_visibility в full-PATCH применяем ТОЛЬКО если задано конкретное
		// значение (UNSPECIFIED=не передано клиентом → не клобберим сид в 0; parity с
		// ApplyName). Явный PRIVATE/PUBLIC в теле пустого mask → применяется.
		spec.ApplyDefaultVisibility = spec.DefaultVisibility != domain.VisibilityUnspecified
		return spec, nil
	}
	for _, p := range spec.Mask {
		switch p {
		case "name":
			spec.ApplyName = true
		case "description":
			spec.ApplyDescription = true
		case "labels":
			spec.ApplyLabels = true
		case "default_visibility", "defaultVisibility":
			spec.ApplyDefaultVisibility = true
		}
	}
	return spec, nil
}
