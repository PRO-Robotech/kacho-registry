// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	"context"

	"github.com/PRO-Robotech/kacho-registry/internal/domain"
)

// ReferrersQuery — вход ListReferrers (bounded full-set одного subject_digest, D-8:
// без page_token/page_size — зеркалит OCI single-index /referrers/<digest>). ArtifactType
// — опциональный server-side facet-фильтр (media-type подписи/SBOM/аттестации, C01).
type ReferrersQuery struct {
	RegistryID    string
	Repository    string
	SubjectDigest string
	ArtifactType  string
}

// ListReferrers — sync read-проекция referrer-графа одного subject_digest (RG-1, D-8):
// фундамент под signing/scanning/SBOM. Sync-часть: format-валидация registry_id/
// repository + subject_digest (malformed → INVALID_ARGUMENT ДО engine-вызова, C04).
// per-repo v_get Check (unauthorized|absent repo → NOT_FOUND, existence-hiding C02) —
// в handler'е ДО вызова. subject без referrer'ов → пустой список (не 404, C03).
// Ответ инфра-полей НЕ несёт (X01). zot недоступен → Unavailable.
func (u *UseCase) ListReferrers(ctx context.Context, q ReferrersQuery) ([]*domain.Referrer, error) {
	if err := u.assertRepoWired(); err != nil {
		return nil, err
	}
	if err := ValidateRegistryID(q.RegistryID); err != nil {
		return nil, err
	}
	if err := domain.ValidateRepositoryName("repository", q.Repository); err != nil {
		return nil, failInvalidArg("%s", err.Error())
	}
	if err := domain.ValidateSubjectDigest(q.SubjectDigest); err != nil {
		return nil, failInvalidArg("%s", err.Error())
	}

	referrers, err := u.zot.ListReferrers(ctx, q.RegistryID, q.Repository, q.SubjectDigest, q.ArtifactType)
	if err != nil {
		return nil, mapRepoErr(err)
	}
	return referrers, nil
}
