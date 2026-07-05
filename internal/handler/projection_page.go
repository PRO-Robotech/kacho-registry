// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// projection_page.go — cursor-пагинация output-only проекций zot (Repository/Tag)
// в transport-слое. Делегирует единому namepage-хелперу (тот же курсор-кодек, что
// у zot-адаптера — байт-совместимость слоёв).
//
// ВАЖНО (anti-DoS, CWE-770): для ListRepositories окно применяется В АДАПТЕРЕ — ДО
// per-repo ImageList-fan-out к zot И ДО per-repo authz-Check к iam. handler лишь
// довершает authz-фильтр уже-ограниченного окна. ListTags per-item fan-out не имеет
// (единый repo-Check); его окно режется здесь, поверх полной tag-проекции repo.
package handler

import (
	"github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/shared/namepage"
)

// pageByName режет отсортированный по имени срез по (page_size, page_token) —
// тонкая обёртка над namepage.Window (используется ListTags). Ошибка (bad size/token)
// → sentinel; caller маппит через mapErr.
func pageByName[T any](items []T, keyOf func(T) string, pageSize int64, pageToken string) ([]T, string, error) {
	return namepage.Window(items, keyOf, pageSize, pageToken)
}
