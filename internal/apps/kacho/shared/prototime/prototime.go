// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package prototime — единый horizontal-хелпер domain time.Time → proto Timestamp.
// Ранее truncate-до-секунд был продублирован byte-for-byte в двух слоях
// (handler.ts и use-case mapping.protoTimestamp) — смена политики точности молча
// расходила бы Registry-проекцию (worker/Get) с Repository/Tag/Stats-проекцией.
// Один источник истины: обе проекции зовут prototime.Truncate.
package prototime

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// Truncate конвертирует time.Time → proto Timestamp, усечённый до секунд.
// Нулевое время → nil (поле опущено).
func Truncate(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t.Truncate(time.Second))
}
