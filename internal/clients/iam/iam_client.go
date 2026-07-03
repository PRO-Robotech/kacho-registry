// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package iam — adapter-клиент к kacho-registry-консумируемым RPC kacho-iam.
// Реализует порт registry.IAMClient: cross-domain валидация project'а на Create
// (ProjectService.Get) + owner-tuple lifecycle через fga-proxy
// (InternalIAMService.RegisterResource/UnregisterResource, Internal :9091, mTLS,
// идемпотентно).
//
// Отделён от internal/check (authz-Check-интерсептор) — это разные консумируемые
// поверхности iam. Тела вызовов (маппинг port→grpc, propagate outgoing ctx)
// наполняет rpc-implementer; здесь — скелет-адаптер с сигнатурами порта.
package iam

import (
	"context"

	"google.golang.org/grpc"

	registry "github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/api/registry"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// Client — adapter к kacho-iam поверх grpc-conn к internal-листенеру (:9091).
type Client struct {
	conn grpc.ClientConnInterface
}

// New оборачивает grpc-conn (к kacho-iam :9091 — ProjectService.Get и
// InternalIAMService.Register/Unregister). nil conn → методы отвечают Unavailable.
func New(conn grpc.ClientConnInterface) *Client { return &Client{conn: conn} }

// ready — conn к kacho-iam обязан быть подан (иначе fail-closed Unavailable).
func (c *Client) ready() error {
	if c.conn == nil {
		return regerrors.ErrUnavailable
	}
	return nil
}

// ProjectExists валидирует project-владельца на Create через ProjectService.Get
// (не найдено → ErrInvalidArg; iam недоступен → ErrUnavailable). Реализует rpc-implementer.
func (c *Client) ProjectExists(ctx context.Context, projectID string) error {
	if err := c.ready(); err != nil {
		return err
	}
	return regerrors.ErrUnimplemented
}

// RegisterResource пишет owner/project owner-tuple созданного реестра через
// InternalIAMService.RegisterResource (идемпотентно). Реализует rpc-implementer.
func (c *Client) RegisterResource(ctx context.Context, registryID, projectID, subjectID string) error {
	if err := c.ready(); err != nil {
		return err
	}
	return regerrors.ErrUnimplemented
}

// UnregisterResource снимает owner-tuple удалённого реестра. Реализует rpc-implementer.
func (c *Client) UnregisterResource(ctx context.Context, registryID string) error {
	if err := c.ready(); err != nil {
		return err
	}
	return regerrors.ErrUnimplemented
}

var _ registry.IAMClient = (*Client)(nil)
