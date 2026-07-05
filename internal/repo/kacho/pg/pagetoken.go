// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// pageCursor — непрозрачный курсор, кодируемый в page_token (base64 JSON).
// Registry List сортирует по (created_at, id) ASC (стабильный ключ пагинации).
type pageCursor struct {
	CreatedAt time.Time `json:"created_at"`
	ID        string    `json:"id"`
}

// encodePageToken собирает непрозрачный base64-курсор из (created_at, id).
func encodePageToken(createdAt time.Time, id string) string {
	b, _ := json.Marshal(pageCursor{CreatedAt: createdAt, ID: id})
	return base64.StdEncoding.EncodeToString(b)
}

// decodePageToken разбирает непрозрачный курсор; возвращает (cursor, err).
func decodePageToken(token string) (pageCursor, error) {
	raw, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return pageCursor{}, err
	}
	var c pageCursor
	if err := json.Unmarshal(raw, &c); err != nil {
		return pageCursor{}, err
	}
	if c.ID == "" {
		return pageCursor{}, fmt.Errorf("empty cursor id")
	}
	return c, nil
}

// invalidPageTokenErr оборачивает мусорный page_token в domain-sentinel
// ErrInvalidArg (repo НЕ формирует gRPC-статус — маппинг sentinel→gRPC в serviceerr).
// serviceerr.ToStatus срежет префикс → клиент видит "invalid page_token: <причина>"
// с кодом INVALID_ARGUMENT (контракт сообщения сохранён).
func invalidPageTokenErr(err error) error {
	return fmt.Errorf("%w: invalid page_token: %v", regerrors.ErrInvalidArg, err)
}
