// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package iam — adapter-клиент к kacho-registry-консумируемым RPC kacho-iam.
// Реализует порт registry.IAMClient: cross-domain валидация project'а на Create
// (ProjectService.Get). Owner-tuple lifecycle (RegisterResource/UnregisterResource)
// живёт в register_applier.go (drainer-half), а per-RPC authz-Check — в
// internal/check — это разные консумируемые поверхности kacho-iam.
package iam

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-corelib/auth"
	"github.com/PRO-Robotech/kacho-corelib/retry"
	iamv1 "github.com/PRO-Robotech/kacho-iam/proto/gen/go/kacho/cloud/iam/v1"

	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// Client — adapter к kacho-iam поверх grpc-conn к internal-листенеру (:9091).
type Client struct {
	conn grpc.ClientConnInterface
}

// New оборачивает grpc-conn (к kacho-iam :9091 — ProjectService.Get). nil conn →
// методы отвечают Unavailable (мутация fail-closed).
func New(conn grpc.ClientConnInterface) *Client { return &Client{conn: conn} }

// ready — conn к kacho-iam обязан быть подан (иначе fail-closed Unavailable).
func (c *Client) ready() error {
	if c.conn == nil {
		return regerrors.ErrUnavailable
	}
	return nil
}

// ProjectExists валидирует project-владельца на Create через ProjectService.Get.
// Семантика ошибок (existence-hiding: tenant не различает "нет" и "нет доступа"):
//
//	NotFound / PermissionDenied / InvalidArgument → ErrInvalidArg ("project not found")
//	Unavailable / DeadlineExceeded                → ErrUnavailable (мутация fail-closed)
//
// Исходящий ctx оборачивается auth.PropagateOutgoing — iam-side ProjectService.Get
// проходит per-RPC Check от реального вызывающего (не SystemPrincipal-fallback).
func (c *Client) ProjectExists(ctx context.Context, projectID string) error {
	if err := c.ready(); err != nil {
		return err
	}
	if projectID == "" {
		return regerrors.ErrInvalidArg
	}
	cli := iamv1.NewProjectServiceClient(c.conn)
	err := retry.OnUnavailable(ctx, func(ctx context.Context) error {
		_, gerr := cli.Get(auth.PropagateOutgoing(ctx), &iamv1.GetProjectRequest{ProjectId: projectID})
		return gerr
	})
	if err == nil {
		return nil
	}
	st, ok := status.FromError(err)
	if !ok {
		return regerrors.ErrInternal
	}
	switch st.Code() {
	case codes.NotFound, codes.PermissionDenied, codes.InvalidArgument:
		return regerrors.ErrInvalidArg
	case codes.Unavailable, codes.DeadlineExceeded:
		return regerrors.ErrUnavailable
	}
	return regerrors.ErrInternal
}
