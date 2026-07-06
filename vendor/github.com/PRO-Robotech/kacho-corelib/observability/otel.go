// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package observability

import (
	"context"
	"log/slog"
	"os"
)

// ShutdownFn — функция завершения работы провайдера телеметрии.
type ShutdownFn func(context.Context) error

// InitOtel инициализирует экспорт телеметрии по endpoint'у из
// KACHO_OTEL_EXPORTER_OTLP_ENDPOINT и возвращает ShutdownFn для graceful-flush.
//
// Если endpoint не задан — телеметрия отключена, возвращается no-op. Если endpoint
// задан, но OTLP-exporter в этой сборке не подключен, функция НЕ делает вид, что
// телеметрия работает: пишет явный WARN (чтобы оператор не считал, что трейсы
// уходят) и возвращает no-op shutdown. Это честный контракт вместо «тихого»
// no-op, который ранее молча терял телеметрию при настроенном endpoint'е.
func InitOtel(ctx context.Context, serviceName string) (ShutdownFn, error) {
	noop := func(context.Context) error { return nil }
	endpoint := os.Getenv("KACHO_OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		return noop, nil
	}
	slog.Warn("OTLP endpoint configured but trace exporter is not wired in this build; "+
		"distributed tracing is DISABLED (only structured slog logging is active)",
		"service", serviceName, "endpoint", endpoint)
	return noop, nil
}
