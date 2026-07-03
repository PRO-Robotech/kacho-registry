// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package handler

import (
	"github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/shared/serviceerr"
)

// mapErr переводит ошибку use-case/repo/clients в gRPC-статус Kachō. Делегирует
// единому маппингу serviceerr.ToStatus (тот же, что async-worker сохраняет в
// Operation.error) — sync- и async-ветки дают идентичные коды и тексты.
func mapErr(err error) error {
	return serviceerr.ToStatus(err)
}
