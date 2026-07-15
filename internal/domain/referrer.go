// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

import (
	"fmt"
	"regexp"
	"time"
)

// Referrer — output-only проекция referrer-графа OCI-репозитория из zot (RG-1, D-8):
// артефакт (подпись / SBOM / аттестация / generic), привязанный к subject-манифесту
// через `subjectDigest`. Source of truth = zot; в БД kacho-registry НЕ хранится,
// читается на request-path. Инфра-полей НЕ несёт (scanner-engine id / blob-layout /
// host — те Internal-only, security.md §Инфра-чувствительные данные, X01).
type Referrer struct {
	RegistryID    string
	Repository    string
	SubjectDigest string
	// Digest — digest самого referrer-артефакта ("sha256:<hex>").
	Digest string
	// ArtifactType — OCI artifactType (media-type facet: тип подписи/SBOM/аттестации;
	// server-side фильтруемый в ListReferrers).
	ArtifactType string
	SizeBytes    int64
	// Annotations — OCI-аннотации referrer-манифеста.
	Annotations map[string]string
	// CreatedAt — момент создания referrer-артефакта (truncate до секунд в proto).
	CreatedAt time.Time
}

// ociDigestRe — OCI digest grammar: `<algorithm>:<hex>` (алгоритм lowercase alnum с
// разделителями, hex — минимум 32 символа). Практически всегда `sha256:<64-hex>`, но
// grammar допускает sha512 и др. (OCI-spec). Валидируется до repo/engine-вызова (C04).
var ociDigestRe = regexp.MustCompile(`^[a-z0-9]+(?:[.+_-][a-z0-9]+)*:[0-9a-fA-F]{32,}$`)

// ValidateSubjectDigest проверяет OCI-digest subject'а (ListReferrers, C04): непустой,
// соответствует digest grammar. malformed → "invalid subject digest '<X>'"
// (валидируется ПЕРВЫМ, до engine-вызова, api-conventions.md malformed-first).
func ValidateSubjectDigest(value string) error {
	if value == "" {
		return fmt.Errorf("subject_digest is required")
	}
	if !ociDigestRe.MatchString(value) {
		return fmt.Errorf("invalid subject digest '%s'", value)
	}
	return nil
}
