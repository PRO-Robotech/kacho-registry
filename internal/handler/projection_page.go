// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// projection_page.go — cursor-пагинация output-only проекций zot (Repository/Tag).
// zot-клиент возвращает полную namespace/tag-выборку (отсортированную по имени ASC),
// а handler применяет page_size/page_token ПОСЛЕ per-repo authz-фильтра — иначе
// фильтрация «сломала» бы страницу (filter-before-limit). Cursor — opaque base64
// последнего отданного имени; garbage token → InvalidArgument (не silent).
package handler

import (
	"encoding/base64"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	corevalidate "github.com/PRO-Robotech/kacho-corelib/validate"
)

// pageByName режет отсортированный по имени срез по (page_size, page_token). Возвращает
// страницу + next-token ("" если больше нет). page_size вне [0..1000] → InvalidArgument;
// garbage token → InvalidArgument.
func pageByName[T any](items []T, keyOf func(T) string, pageSize int64, pageToken string) ([]T, string, error) {
	size, err := corevalidate.PageSize("page_size", pageSize)
	if err != nil {
		return nil, "", err
	}
	start := 0
	if pageToken != "" {
		tok, derr := decodeNameCursor(pageToken)
		if derr != nil {
			return nil, "", status.Error(codes.InvalidArgument, "invalid page_token")
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
	return page, encodeNameCursor(keyOf(page[len(page)-1])), nil
}

func encodeNameCursor(name string) string {
	return base64.StdEncoding.EncodeToString([]byte(name))
}

func decodeNameCursor(token string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
