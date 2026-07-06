// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package grpcclient — горизонтальный cross-cutting helper для client-side gRPC
// keepalive. Единая точка истины для keepalive-параметров inter-service
// dial-сайтов (compute dialPeer, iam subject-drainer, vpc-sdk).
//
// Проблема: bare-dial-сайты (`grpc.NewClient(addr, …)` без keepalive) держат
// conn'ы, которые между всплесками трафика простаивают и становятся half-open;
// первый RPC всплеска висит ~30с на переустановке TCP/HTTP2. keepalive-пинги
// проактивно обнаруживают мертвый conn и переустанавливают его.
//
// Серверная сторона, принимающая idle keepalive (PermitWithoutStream=true),
// должна разрешать частые пинги — см. grpcsrv.DefaultKeepaliveEnforcement.
package grpcclient

import (
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

const (
	// DefaultKeepaliveTime — интервал ping'а: агрессивный 10s, чтобы поймать
	// half-open до следующего всплеска в kind, где idle-flow умирает быстрее 30s.
	DefaultKeepaliveTime = 10 * time.Second
	// DefaultKeepaliveTimeout — ack-deadline = треть интервала (инвариант
	// «таймаут = треть Time»).
	DefaultKeepaliveTimeout = DefaultKeepaliveTime / 3
)

// KeepaliveParams — стандартные client keepalive-параметры.
//
// permitWithoutStream=true для преимущественно-idle conn'ов (authz, drainer):
// пинги держат conn теплым даже без активных стримов — прямо лечит half-open-столл.
// Для активно используемых conn'ов — false (там всегда есть трафик).
func KeepaliveParams(permitWithoutStream bool) keepalive.ClientParameters {
	return keepalive.ClientParameters{
		Time:                DefaultKeepaliveTime,
		Timeout:             DefaultKeepaliveTimeout,
		PermitWithoutStream: permitWithoutStream,
	}
}

// KeepaliveDialOption — grpc.DialOption с дефолтными keepalive-параметрами.
func KeepaliveDialOption(permitWithoutStream bool) grpc.DialOption {
	return grpc.WithKeepaliveParams(KeepaliveParams(permitWithoutStream))
}
