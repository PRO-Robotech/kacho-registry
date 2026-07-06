// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package baggage — извлечение наблюдательных метаданных из caller-context
// в context для autonomous-worker'а.
//
// Назначение: async worker'у (например, `operations.Run`, outbox-drain,
// reconciler) нужны два противоречащих требования к контексту:
//
//  1. Сохранить **наблюдательные** values из request-ctx (OpenTelemetry
//     SpanContext, request-id, slog logger, tenant/IAM claims) — иначе
//     логи и трейсы worker'а оторваны от исходного запроса, debugability
//     теряется.
//
//  2. **Отвязаться** от deadline / cancellation request-ctx — handler
//     возвращает Operation клиенту сразу и его ctx cancel-ится через
//     миллисекунды; worker должен жить независимо до собственного timeout.
//
// Этого добивается `Extract` через `context.WithoutCancel` (Go 1.21+):
// производный ctx сохраняет ВСЕ values (любые `context.WithValue`-ключи,
// включая внутренние OTel SpanContext и slog handler), но не наследует
// ни deadline, ни cancel-сигнал. Caller затем оборачивает результат в
// `context.WithTimeout(workerCtx, opTimeout)` для autonomous-lifecycle.
//
// Преимущество перед ручным перечислением «известных ключей»: список
// propagated-values эволюционирует (добавятся tenant-id, locale, audit-id),
// и забыть скопировать новый ключ — тихий regression в observability.
// WithoutCancel-подход zero-maintenance: новые WithValue-ключи
// автоматически propagate'ятся в worker без правки этого пакета.
package baggage

import "context"

// Extract возвращает новый context, который:
//   - сохраняет все Values из callerCtx (OTel span, request-id, slog logger,
//     tenant claims, любые custom WithValue-ключи);
//   - НЕ наследует deadline callerCtx;
//   - НЕ наследует cancel-сигнал callerCtx.
//
// Применение: вызывающий worker оборачивает результат в собственный
// `context.WithTimeout` / `context.WithCancel` для управления своим
// lifecycle, не привязанным к request:
//
//	workerCtx := baggage.Extract(callerCtx)
//	workerCtx, cancel := context.WithTimeout(workerCtx, opTimeout)
//	defer cancel()
//	go fn(workerCtx)
//
// Если callerCtx == nil — возвращается context.Background() (defensive;
// в production это сигнал бага, но мы не паникуем).
func Extract(callerCtx context.Context) context.Context {
	if callerCtx == nil {
		return context.Background()
	}
	return context.WithoutCancel(callerCtx)
}
