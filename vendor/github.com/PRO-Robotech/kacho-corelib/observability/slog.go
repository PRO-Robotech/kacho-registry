// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package observability

import (
	"io"
	"log/slog"
)

// NewSloggerLevel создает структурированный JSON-логгер, пишущий в w, с
// заданным минимальным уровнем. level — slog.Leveler (slog.Level или
// динамический *slog.LevelVar). Композиционный корень парсит
// оператор-сконфигурированный уровень и передает его сюда.
func NewSloggerLevel(w io.Writer, level slog.Leveler) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level}))
}

// NewSlogger создает структурированный JSON-логгер, пишущий в w.
// Минимальный уровень — Info. Back-compat обертка над NewSloggerLevel для
// вызывающих, которым не нужен настраиваемый уровень.
func NewSlogger(w io.Writer) *slog.Logger {
	return NewSloggerLevel(w, slog.LevelInfo)
}
