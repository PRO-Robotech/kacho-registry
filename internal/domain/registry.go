// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package domain — сущности kacho-registry (Registry-namespace + read-only
// проекции Repository / Tag из zot).
//
// Domain-слой чистой архитектуры: чистый Go (только stdlib). Registry — плоский
// tenant-namespace над общим zot-бэкендом; блобы/манифесты в БД kacho-registry
// НЕ хранятся (source of truth = zot), тут живут только метаданные namespace.
// Repository/Tag — output-only зеркало zot, вычитываемое на request-path.
package domain

import (
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"
)

// maxNameLen — верхняя граница длины имени Registry. Имя используется как
// DNS-safe сегмент OCI-namespace, поэтому валидируется и по длине, и по charset.
const maxNameLen = 255

// dnsName — DNS-label-подобный слог имени реестра (lowercase alnum + `-`/`.`,
// без ведущего/замыкающего разделителя). Имя участвует в OCI-пути
// registry.kacho.local/<id>/<repo>, поэтому uppercase/underscore/пробелы
// недопустимы.
var dnsName = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)

// RegistryStatus — состояние жизненного цикла namespace. Ширина int32 совпадает
// с registryv1.RegistryStatus, поэтому конверсии domain↔proto точны.
type RegistryStatus int32

// Значения RegistryStatus (parity с proto-enum registry.v1:
// UNSPECIFIED=0, ACTIVE=1, DELETING=2).
const (
	RegistryStatusUnspecified RegistryStatus = iota
	RegistryStatusActive
	RegistryStatusDeleting
)

// Validate проверяет, что статус — известное значение.
func (s RegistryStatus) Validate() error {
	switch s {
	case RegistryStatusUnspecified, RegistryStatusActive, RegistryStatusDeleting:
		return nil
	default:
		return fmt.Errorf("registry status %d is out of range", int32(s))
	}
}

// ValidateName проверяет имя реестра: непустое, в пределах длины, DNS-safe.
// Выделено отдельно, чтобы partial-Update мог валидировать только заданное имя.
func ValidateName(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s is required", field)
	}
	if utf8.RuneCountInString(value) > maxNameLen {
		return fmt.Errorf("%s exceeds %d characters", field, maxNameLen)
	}
	if !dnsName.MatchString(value) {
		return fmt.Errorf("%s must be DNS-safe (lowercase alnum, '-', '.')", field)
	}
	return nil
}

// Registry — tenant-namespace реестра образов. id (prefix "reg") — immutable PK;
// project_id — cross-domain ref на iam (TEXT, без FK); name — UNIQUE в рамках
// project среди живых реестров. Метки участвуют в authz label-scoping.
type Registry struct {
	ID          string
	ProjectID   string
	Name        string
	Description string
	Labels      map[string]string
	Status      RegistryStatus
	CreatedAt   time.Time
	// DefaultVisibility — сид visibility для НОВЫХ repo реестра (RG-1, D-6). Mutable
	// через UpdateRegistry; переход →PUBLIC подчинён any-path-to-PUBLIC admin-gate
	// (B10/B11). Дефолт PRIVATE (fail-safe). CreateRepository без явного visibility
	// наследует это значение (B12 gate-at-default).
	DefaultVisibility Visibility
}

// Validate проверяет domain-инварианты Registry перед созданием/сохранением:
// project_id обязателен (cross-domain owner), name — DNS-safe в пределах длины,
// status — известное значение enum.
func (r Registry) Validate() error {
	if r.ProjectID == "" {
		return fmt.Errorf("registry project_id is required")
	}
	if err := ValidateName("name", r.Name); err != nil {
		return err
	}
	if err := r.Status.Validate(); err != nil {
		return err
	}
	return nil
}

// Repository — публичная проекция OCI-репозитория (RG-1: overlay ⟂ projection).
// Projection-поля (tag_count/size/artifact-типы/timestamps) — output-only зеркало zot
// (source of truth = zot). Overlay-поля (Description/Labels/Visibility/CreatedAt) —
// config-overlay из repository_configs (durable-repo); пусты у ephemeral-repo
// (проекция без overlay-строки). Get/List отдают LEFT JOIN overlay + projection.
type Repository struct {
	RegistryID string
	Name       string
	// Description — overlay-поле (durable). Пусто у ephemeral.
	Description string
	// Labels — overlay-поле (durable). Пусто у ephemeral.
	Labels map[string]string
	// Visibility — overlay-authoritative (D-6). Дефолт PRIVATE (ephemeral несёт PRIVATE).
	Visibility Visibility
	// CreatedAt — момент создания overlay-строки (durable). Нулевой у ephemeral
	// (проекция без своей строки/created_at).
	CreatedAt time.Time
	TagCount  int32
	SizeBytes int64
	UpdatedAt time.Time
	// ArtifactType — доминирующий (первый) тип артефакта репозитория; для обратной
	// совместимости фильтра. Полный набор — ArtifactTypes.
	ArtifactType ArtifactType
	// ArtifactTypes — упорядоченно-уникальный набор типов артефактов среди тегов.
	// Репозиторий может одновременно содержать контейнерные образы И helm-чарты
	// (mixed) — тогда набор несёт оба значения. Пусто — нет тегов / не классифицировано.
	ArtifactTypes []ArtifactType
	// LastPulledAt — момент последнего pull любого тега репозитория (max по тегам).
	// Нулевой — ни один тег ещё не скачивался.
	LastPulledAt time.Time
	// DownloadCount — суммарное число скачиваний тегов репозитория (zot download-count).
	DownloadCount int64
}

// Tag — output-only проекция тега/манифеста из zot (source of truth = zot).
type Tag struct {
	RegistryID string
	Repository string
	Tag        string
	Digest     string
	SizeBytes  int64
	MediaType  string
	CreatedAt  time.Time
	// Architecture — платформа образа "<os>/<arch>" (из image-config), "multi-arch"
	// для index-манифеста, либо пусто (helm-чарт / config без platform).
	Architecture string
	// LastPulledAt — момент последнего pull тега (zot last-pull). Нулевой — ни разу.
	LastPulledAt time.Time
	// PushedBy — subject, выполнивший push тега (zot pushed-by), если известен.
	PushedBy string
	// DownloadCount — число скачиваний тега (zot download-count).
	DownloadCount int64
}

// RegistryStats — инфра-проекция namespace (repo/tag count, суммарный размер,
// число уникальных блобов). Раскрывается ТОЛЬКО через Internal-API (:9091).
type RegistryStats struct {
	RegistryID      string
	RepositoryCount int32
	TagCount        int32
	TotalSizeBytes  int64
	BlobCount       int64
}
