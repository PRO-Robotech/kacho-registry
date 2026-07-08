// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package check — per-RPC authz-гейт для kacho-registry. Оборачивает
// authz-интерсептор из corelib registry-шной PermissionMap и CheckClient поверх
// IAM (InternalIAMService.Check → OpenFGA/ReBAC). registry — CONSUMER iam-authz
// (ребро registry→iam Check); интерсептор навешивается на ОБА листенера
// (public :9090 + internal :9091) — internal НЕ освобождён (security.md).
package check

import (
	"context"
	"time"

	"google.golang.org/grpc"

	"github.com/PRO-Robotech/kacho-corelib/auth"
	"github.com/PRO-Robotech/kacho-corelib/authz"
	iamv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/iam/v1"
)

// checkTimeout — per-call deadline на один Check-вызов к iam. Зеркалит corelib
// authz.InterceptorOptions.CheckTimeout default (2s): registry-interceptor
// (internal/check/factory.go) её не конфигурирует, и, что важнее, эта
// interceptor-side защита покрывает только Check, инициированный САМИМ
// authz.Interceptor.Unary() — а не прямые вызовы IAMCheckClient.Check из
// internal/dataplane (per-request data-plane authz на raw request ctx) и
// internal/handler/listauthz.go (ScopeFiltered per-repo fan-out, до 1000 Check на
// ListRepositories), которые обходят interceptor и раньше форвардили сырой inbound
// ctx без собственного дедлайна. Зависший iam пинил горутину навсегда
// (architecture.md "Per-call deadline на КАЖДОМ внешнем вызове"). Таймаут — здесь,
// ВНУТРИ клиента, чтобы одной правкой покрыть оба call-site'а uniformly.
const checkTimeout = 2 * time.Second

// IAMCheckClient адаптирует kacho-iam.InternalIAMService.Check под authz.CheckClient.
type IAMCheckClient struct {
	cli iamv1.InternalIAMServiceClient
}

// NewIAMCheckClient строит адаптер поверх conn к internal-листенеру kacho-iam (:9091).
func NewIAMCheckClient(conn grpc.ClientConnInterface) *IAMCheckClient {
	return &IAMCheckClient{cli: iamv1.NewInternalIAMServiceClient(conn)}
}

// Check вызывает InternalIAMService.Check с собственным per-call deadline
// (checkTimeout) — НЕ полагается на дедлайн вызывающего ctx. Исходящий ctx
// оборачивается auth.PropagateOutgoing, чтобы на стороне iam principal-extract
// видел реального вызывающего. Timeout/iam-error → non-nil error (caller
// fail-closed'ит: data-plane → 503, listauthz → UNAVAILABLE).
func (c *IAMCheckClient) Check(ctx context.Context, subjectID, relation, object string) (bool, error) {
	cctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	resp, err := c.cli.Check(auth.PropagateOutgoing(cctx), &iamv1.CheckRequest{
		SubjectId: subjectID,
		Relation:  relation,
		Object:    object,
	})
	if err != nil {
		return false, err
	}
	return resp.GetAllowed(), nil
}

var _ authz.CheckClient = (*IAMCheckClient)(nil)
