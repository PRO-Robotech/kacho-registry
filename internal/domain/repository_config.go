// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

import (
	"fmt"
	"regexp"
	"time"
)

// Visibility — доступность OCI-репозитория (RG-1, D-6). PRIVATE (дефолт, fail-safe)
// требует per-subject authz; PUBLIC несёт FGA-tuple `user:* v_get` (anonymous pull).
// Ширина int32 совпадает с registryv1.Visibility, поэтому конверсии domain↔proto
// точны (UNSPECIFIED=0, PRIVATE=1, PUBLIC=2).
type Visibility int32

// Значения Visibility (parity с proto-enum registry.v1.Visibility).
const (
	VisibilityUnspecified Visibility = iota // 0 — не задано клиентом (наследует default_visibility)
	VisibilityPrivate                       // 1 — приватный (дефолт)
	VisibilityPublic                        // 2 — публичный (anon-pull через user:* tuple)
)

// Validate проверяет, что visibility — известное НЕ-unspecified значение (для
// persist: строка overlay всегда несёт конкретный PRIVATE|PUBLIC, UNSPECIFIED
// резолвится в default_visibility ДО записи).
func (v Visibility) Validate() error {
	switch v {
	case VisibilityPrivate, VisibilityPublic:
		return nil
	default:
		return fmt.Errorf("visibility %d is out of range", int32(v))
	}
}

// String возвращает DB-репрезентацию visibility (колонка TEXT + CHECK). UNSPECIFIED
// и out-of-range схлопываются в fail-safe PRIVATE — строка overlay никогда не пишется
// «открытой по ошибке».
func (v Visibility) String() string {
	if v == VisibilityPublic {
		return "PUBLIC"
	}
	return "PRIVATE"
}

// VisibilityFromString парсит DB-колонку visibility в domain-enum (fail-safe: любое
// неизвестное значение → PRIVATE, не PUBLIC).
func VisibilityFromString(s string) Visibility {
	if s == "PUBLIC" {
		return VisibilityPublic
	}
	return VisibilityPrivate
}

// repoNameRe — OCI repo-name grammar: lowercase alnum path-компоненты, разделённые
// одиночным `/`, внутри компонента допустимы `.`/`_`/`__`/`-` как разделители
// (шаблон `[a-z0-9]+(?:(?:[._]|__|-+|/)[a-z0-9]+)*`). Имена репозиториев несут `/`
// (напр. `backend/api`). Uppercase/пробелы/`!` недопустимы. Верхняя граница длины —
// maxRepoNameLen (весь путь).
var repoNameRe = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+|/)[a-z0-9]+)*$`)

// maxRepoNameLen — верхняя граница длины полного repo-имени (OCI-путь).
const maxRepoNameLen = 255

// ValidateRepositoryName проверяет имя репозитория: непустое, в пределах длины,
// соответствует OCI repo-name grammar. Тексты — часть контракта (api-conventions.md):
// пусто → "<field> is required"; malformed → "invalid repository name '<X>'".
// Валидируется ПЕРВЫМ стейтментом RPC (до repo/engine-вызова, malformed-first).
func ValidateRepositoryName(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s is required", field)
	}
	if len(value) > maxRepoNameLen {
		return fmt.Errorf("invalid repository name '%s'", value)
	}
	if !repoNameRe.MatchString(value) {
		return fmt.Errorf("invalid repository name '%s'", value)
	}
	return nil
}

// RepositoryConfig — DB-owned config-overlay OCI-репозитория (RG-1). Натуральный
// ключ (RegistryID, Name). Overlay ⟂ projection: строка «переживает пустоту»
// (durable-repo виден с tagCount=0), не источник контента (source of truth = zot).
// visibility authoritative на overlay (D-6); description/labels — tenant-intent.
type RepositoryConfig struct {
	RegistryID  string
	Name        string
	Description string
	Labels      map[string]string
	Visibility  Visibility
	CreatedAt   time.Time
}

// Validate проверяет domain-инварианты RepositoryConfig перед persist: registry_id
// обязателен (owner-namespace), name — валидное OCI repo-имя, visibility —
// конкретное PRIVATE|PUBLIC (UNSPECIFIED резолвится в default ДО Validate).
func (c RepositoryConfig) Validate() error {
	if c.RegistryID == "" {
		return fmt.Errorf("registry_id is required")
	}
	if err := ValidateRepositoryName("repository", c.Name); err != nil {
		return err
	}
	if err := c.Visibility.Validate(); err != nil {
		return err
	}
	return nil
}
