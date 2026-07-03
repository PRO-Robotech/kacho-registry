// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package outbox — doc-only анкер для owner-tuple outbox kacho-registry.
//
// registry_outbox (миграция internal/migrations) хранит intent'ы
// RegisterResource/UnregisterResource owner-hierarchy-tuple, эмитируемые в той
// же writer-tx, что INSERT/DELETE реестра (transactional-outbox, at-least-once).
// Отдельный register-drainer (corelib outbox/drainer, FOR UPDATE SKIP LOCKED)
// применяет каждую строку через kacho-iam InternalIAMService.RegisterResource /
// UnregisterResource по mTLS (идемпотентно). Drainer-wiring и intent-кодек —
// реализует rpc-implementer.
package outbox
