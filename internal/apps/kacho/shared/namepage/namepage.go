// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package namepage — единый horizontal-хелпер cursor-пагинации по имени (ASC) для
// output-only проекций zot. Общий источник для transport-слоя (handler) и
// zot-адаптера, чтобы курсор был БАЙТ-совместим между слоями: адаптер режет окно у
// источника (bound per-request fan-out к zot/iam — CWE-770), handler довершает
// authz-фильтр окна. Курсор — opaque base64 последнего имени; невалидный →
// ErrInvalidArg-sentinel (маппинг в gRPC — на границе serviceerr/mapErr).
package namepage

import (
	"encoding/base64"
	"fmt"
	"strconv"

	corevalidate "github.com/PRO-Robotech/kacho-corelib/validate"

	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// Window режет отсортированный по имени (ASC) срез по (pageSize, pageToken).
// Возвращает страницу + next-token ("" если больше нет). pageSize вне [0..1000] →
// InvalidArgument (corevalidate.PageSize; 0 → default 50); garbage token →
// ErrInvalidArg-sentinel. keyOf извлекает имя-ключ элемента.
func Window[T any](items []T, keyOf func(T) string, pageSize int64, pageToken string) ([]T, string, error) {
	size, err := corevalidate.PageSize("page_size", pageSize)
	if err != nil {
		return nil, "", err
	}
	start := 0
	if pageToken != "" {
		tok, derr := Decode(pageToken)
		if derr != nil {
			return nil, "", fmt.Errorf("%w: invalid page_token", regerrors.ErrInvalidArg)
		}
		for start < len(items) && keyOf(items[start]) <= tok {
			start++
		}
	}
	if start >= len(items) {
		return nil, "", nil
	}
	end := start + int(size)
	if end >= len(items) {
		return items[start:], "", nil
	}
	page := items[start:end]
	return page, Encode(keyOf(page[len(page)-1])), nil
}

// WindowByOffset режет отсортированный срез по ОПАКОВОМУ offset-курсору (позиция, а не
// имя элемента). Для проекций, где per-item authz-фильтр применяется ПОСЛЕ окна
// (ListRepositories: per-repo v_list в handler'е): name-курсор echo'ил бы имя
// отфильтрованного (скрытого) элемента → existence-oracle. Offset ничего не именует и
// доводит пагинацию до всех разрешённых элементов даже через полностью-скрытые окна.
// pageSize вне [0..1000] → InvalidArgument; garbage token → ErrInvalidArg-sentinel.
// items ожидается детерминированно отсортированным (позиция стабильна между вызовами).
func WindowByOffset[T any](items []T, pageSize int64, pageToken string) ([]T, string, error) {
	size, err := corevalidate.PageSize("page_size", pageSize)
	if err != nil {
		return nil, "", err
	}
	start := 0
	if pageToken != "" {
		off, derr := decodeOffset(pageToken)
		if derr != nil || off < 0 {
			return nil, "", fmt.Errorf("%w: invalid page_token", regerrors.ErrInvalidArg)
		}
		start = off
	}
	if start >= len(items) {
		return nil, "", nil
	}
	end := start + int(size)
	if end >= len(items) {
		return items[start:], "", nil
	}
	return items[start:end], encodeOffset(end), nil
}

// Encode кодирует имя в opaque base64-курсор.
func Encode(name string) string {
	return base64.StdEncoding.EncodeToString([]byte(name))
}

// encodeOffset кодирует позицию в опаковый base64-курсор (не несёт имён).
func encodeOffset(offset int) string {
	return base64.StdEncoding.EncodeToString([]byte(strconv.Itoa(offset)))
}

// decodeOffset разбирает опаковый offset-курсор обратно в позицию.
func decodeOffset(token string) (int, error) {
	b, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(string(b))
}

// Decode разбирает opaque base64-курсор в имя.
func Decode(token string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
