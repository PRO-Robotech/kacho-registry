// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-corelib/ids"
	corevalidate "github.com/PRO-Robotech/kacho-corelib/validate"
)

// validateRegistryID отсекает malformed registry-id синхронно первым стейтментом
// RPC: prefix `reg` (family-agnostic) → InvalidArgument "invalid registry id '<X>'".
// Пустой id пропускается (required-проверка — отдельно у caller'а).
func validateRegistryID(id string) error {
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
	"name":        {},
	"project_id":  {},
	"projectId":   {},
	"description": {},
	"labels":      {},
}

// immutableUpdateFields → каноничный immutable-текст (api-conventions.md
// §update_mask): поле в mask, но менять нельзя после Create.
var immutableUpdateFields = map[string]string{
	"name":       "name is immutable after Registry.Create",
	"project_id": "projectId is immutable after Registry.Create",
	"projectId":  "projectId is immutable after Registry.Create",
}

// resolveUpdateMask применяет update_mask discipline к UpdateSpec:
//   - unknown поле → InvalidArgument (corevalidate.UpdateMask);
//   - immutable поле (name/project) → InvalidArgument (каноничный текст);
//   - пустой mask → full-object PATCH (все mutable-поля применяются);
//   - mutable поле → соответствующий Apply*-флаг.
//
// Мутирует spec.ApplyDescription / spec.ApplyLabels, возвращает нормализованный spec.
func resolveUpdateMask(spec UpdateSpec) (UpdateSpec, error) {
	if err := corevalidate.UpdateMask("update_mask", spec.Mask, knownUpdateFields); err != nil {
		return spec, err
	}
	for _, p := range spec.Mask {
		if msg, ok := immutableUpdateFields[p]; ok {
			return spec, status.Error(codes.InvalidArgument, msg)
		}
	}
	if len(spec.Mask) == 0 {
		// full-object PATCH: применяются все mutable-поля.
		spec.ApplyDescription = true
		spec.ApplyLabels = true
		return spec, nil
	}
	for _, p := range spec.Mask {
		switch p {
		case "description":
			spec.ApplyDescription = true
		case "labels":
			spec.ApplyLabels = true
		}
	}
	return spec, nil
}
