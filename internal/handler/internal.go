// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package handler — internal.go: admin-RPC InternalRegistryService
// (TriggerGarbageCollection / GetRegistryStats). Регистрируется ТОЛЬКО на
// cluster-internal листенере (:9091) — никогда на внешнем TLS endpoint (ban #6).
// GetRegistryStats несёт инфра-проекцию namespace (infra-sensitive → только :9091).
//
// Методы — тонкий transport: делегируют use-case'у, без бизнес-логики.
package handler

import (
	"context"

	registryv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/registry/v1"

	registry "github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/api/registry"
)

// InternalRegistryHandler реализует registryv1.InternalRegistryServiceServer.
type InternalRegistryHandler struct {
	registryv1.UnimplementedInternalRegistryServiceServer
	uc *registry.UseCase
}

// NewInternalRegistryHandler конструирует InternalRegistryHandler.
func NewInternalRegistryHandler(uc *registry.UseCase) *InternalRegistryHandler {
	return &InternalRegistryHandler{uc: uc}
}

// TriggerGarbageCollection запускает async-GC namespace в zot и возвращает Operation.
func (h *InternalRegistryHandler) TriggerGarbageCollection(ctx context.Context, req *registryv1.TriggerGarbageCollectionRequest) (*operationProto, error) {
	op, err := h.uc.TriggerGC(ctx, req.GetRegistryId())
	if err != nil {
		return nil, mapErr(err)
	}
	return operationToProto(op), nil
}

// GetRegistryStats возвращает инфра-статистику namespace (sync, только :9091).
func (h *InternalRegistryHandler) GetRegistryStats(ctx context.Context, req *registryv1.GetRegistryStatsRequest) (*registryv1.RegistryStats, error) {
	s, err := h.uc.Stats(ctx, req.GetRegistryId())
	if err != nil {
		return nil, mapErr(err)
	}
	return toProtoStats(s), nil
}
