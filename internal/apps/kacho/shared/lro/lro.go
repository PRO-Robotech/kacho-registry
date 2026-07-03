// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package lro — общие константы Long-Running Operations каталога kacho-registry.
package lro

// OperationPrefix — 3-символьный префикс operation-id каталога registry. По нему
// api-gateway opsproxy маршрутизирует OperationService.Get/Cancel в backend
// kacho-registry (parity с per-domain operation-префиксами прочих сервисов).
const OperationPrefix = "reo"
