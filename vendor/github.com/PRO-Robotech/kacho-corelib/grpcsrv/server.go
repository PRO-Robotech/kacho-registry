// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package grpcsrv

import (
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"
)

// DefaultKeepaliveEnforcement — server-side EnforcementPolicy, допускающая частые
// idle keepalive-пинги client'ов.
//
// gRPC-дефолт (MinTime: 5m, PermitWithoutStream: false) забанил бы клиента с
// PermitWithoutStream-пингами каждые 10s → GOAWAY too_many_pings. Чтобы idle-prone
// conn'ы (compute→iam-internal authz, iam subject-drainer→api-gateway) могли держать
// conn теплым, сервер обязан разрешать такие пинги: MinTime <= клиентский Time (10s)
// и PermitWithoutStream=true.
func DefaultKeepaliveEnforcement() keepalive.EnforcementPolicy {
	return keepalive.EnforcementPolicy{
		MinTime:             5 * time.Second,
		PermitWithoutStream: true,
	}
}

// NewServer создает gRPC-сервер с зарегистрированными Health-сервисом в состоянии SERVING
// и server-reflection (для grpcurl, debug, dev-tooling).
//
// DefaultKeepaliveEnforcement() ставится ПЕРВЫМ в opts, чтобы caller-opts могли его
// переопределить.
func NewServer(opts ...grpc.ServerOption) *grpc.Server {
	s := grpc.NewServer(append([]grpc.ServerOption{
		grpc.KeepaliveEnforcementPolicy(DefaultKeepaliveEnforcement()),
	}, opts...)...)
	h := health.NewServer()
	h.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(s, h)
	reflection.Register(s)
	return s
}
