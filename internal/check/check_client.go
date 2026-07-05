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

	"google.golang.org/grpc"

	"github.com/PRO-Robotech/kacho-corelib/auth"
	"github.com/PRO-Robotech/kacho-corelib/authz"
	iamv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/iam/v1"
)

// IAMCheckClient адаптирует kacho-iam.InternalIAMService.Check под authz.CheckClient.
type IAMCheckClient struct {
	cli iamv1.InternalIAMServiceClient
}

// NewIAMCheckClient строит адаптер поверх conn к internal-листенеру kacho-iam (:9091).
func NewIAMCheckClient(conn grpc.ClientConnInterface) *IAMCheckClient {
	return &IAMCheckClient{cli: iamv1.NewInternalIAMServiceClient(conn)}
}

// Check вызывает InternalIAMService.Check. Исходящий ctx оборачивается
// auth.PropagateOutgoing, чтобы на стороне iam principal-extract видел реального
// вызывающего.
func (c *IAMCheckClient) Check(ctx context.Context, subjectID, relation, object string) (bool, error) {
	resp, err := c.cli.Check(auth.PropagateOutgoing(ctx), &iamv1.CheckRequest{
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
