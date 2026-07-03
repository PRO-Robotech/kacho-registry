// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package lro — общие константы Long-Running Operations каталога kacho-registry.
package lro

import "github.com/PRO-Robotech/kacho-corelib/ids"

// OperationPrefix — 3-символьный префикс operation-id каталога registry. По нему
// api-gateway opsproxy маршрутизирует OperationService.Get/Cancel в backend
// kacho-registry (parity с per-domain operation-префиксами прочих сервисов).
// Источник истины — corelib ids.PrefixOperationReg ("rop"); хардкод "reo" был бы
// рассинхроном с маршрутизацией opsproxy.
const OperationPrefix = ids.PrefixOperationReg
