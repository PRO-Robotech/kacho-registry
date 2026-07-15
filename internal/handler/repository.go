// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// repository.go — тонкий gRPC-transport config-overlay Repository RPC (RG-1, public
// :9090): sync GetRepository/ListReferrers + async Create/Update/Delete/Rename
// Repository (→ Operation). Все методы — parse → authz-gate (В ХЕНДЛЕРЕ: ScopeFiltered
// per-repo Check + existence-hiding + any-path-to-PUBLIC admin-gate) → use-case → format.
// Никакой бизнес-логики (mask-discipline / overlay-merge / reject-if-tags — в use-case).
package handler

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	registryv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/registry/v1"

	registry "github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/api/registry"
	"github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/shared/prototime"
	"github.com/PRO-Robotech/kacho-registry/internal/domain"
)

// GetRepository возвращает публичный Repository (sync, overlay ⟂ projection). Malformed
// registry_id → InvalidArgument ПЕРВЫМ (A06). per-repo v_get Check В ХЕНДЛЕРЕ: unauthorized|
// absent → NOT_FOUND "repository not found" (existence-hiding, A08).
func (h *RegistryHandler) GetRepository(ctx context.Context, req *registryv1.GetRepositoryRequest) (*registryv1.Repository, error) {
	registryID, repository := req.GetRegistryId(), req.GetRepository()
	if err := registry.ValidateRegistryID(registryID); err != nil {
		return nil, mapErr(err)
	}
	if repository == "" {
		return nil, status.Error(codes.InvalidArgument, "repository is required")
	}
	if err := h.authz.checkRepository(ctx, registryID, repository, relationVGet); err != nil {
		return nil, err
	}
	repo, err := h.uc.GetRepository(ctx, registryID, repository)
	if err != nil {
		return nil, mapErr(err)
	}
	return h.uc.ProtoRepository(repo), nil
}

// CreateRepository запускает async-вставку overlay и возвращает Operation. Malformed
// registry_id → InvalidArgument ПЕРВЫМ (A06). namespace call-gate v_create (невидимый
// реестр → NOT_FOUND, X04). Явный visibility=PUBLIC требует registry admin (B08 →
// PERMISSION_DENIED). Дубликат/DELETING/payload — sync reject в use-case.
func (h *RegistryHandler) CreateRepository(ctx context.Context, req *registryv1.CreateRepositoryRequest) (*operationProto, error) {
	registryID := req.GetRegistryId()
	if err := registry.ValidateRegistryID(registryID); err != nil {
		return nil, mapErr(err)
	}
	if err := h.authz.registryGate(ctx, registryID, relationVCreate); err != nil {
		return nil, err
	}
	if req.GetVisibility() == registryv1.Visibility_PUBLIC {
		if err := h.authz.requireRegistryAdmin(ctx, registryID, "creating a public repository requires registry admin"); err != nil {
			return nil, err
		}
	}
	op, err := h.uc.CreateRepository(ctx, registry.CreateRepositorySpec{
		RegistryID:  registryID,
		Repository:  req.GetRepository(),
		Description: req.GetDescription(),
		Labels:      req.GetLabels(),
		Visibility:  domain.Visibility(req.GetVisibility()),
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return operationToProto(op), nil
}

// UpdateRepository запускает async FieldMask-PATCH overlay и возвращает Operation.
// Malformed registry_id → InvalidArgument ПЕРВЫМ (A06). per-repo v_update Check
// (deny|absent → NOT_FOUND). visibility→PUBLIC в mask требует registry admin (B02 →
// PERMISSION_DENIED). immutable/unknown mask + payload-границы — sync reject в use-case.
func (h *RegistryHandler) UpdateRepository(ctx context.Context, req *registryv1.UpdateRepositoryRequest) (*operationProto, error) {
	registryID, repository := req.GetRegistryId(), req.GetRepository()
	if err := registry.ValidateRegistryID(registryID); err != nil {
		return nil, mapErr(err)
	}
	if repository == "" {
		return nil, status.Error(codes.InvalidArgument, "repository is required")
	}
	if err := h.authz.checkRepository(ctx, registryID, repository, relationVUpdate); err != nil {
		return nil, err
	}
	if maskContains(req.GetUpdateMask().GetPaths(), "visibility") && req.GetVisibility() == registryv1.Visibility_PUBLIC {
		if err := h.authz.requireRegistryAdmin(ctx, registryID, "changing repository visibility requires registry admin"); err != nil {
			return nil, err
		}
	}
	op, err := h.uc.UpdateRepository(ctx, registry.UpdateRepositorySpec{
		RegistryID:  registryID,
		Repository:  repository,
		Description: req.GetDescription(),
		Labels:      req.GetLabels(),
		Visibility:  domain.Visibility(req.GetVisibility()),
		Mask:        req.GetUpdateMask().GetPaths(),
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return operationToProto(op), nil
}

// DeleteRepository запускает async reject-if-tags удаление overlay и возвращает Operation.
// Malformed registry_id → InvalidArgument ПЕРВЫМ (A06). per-repo v_delete Check СИНХРОННО
// ДО создания Operation: deny|absent → NOT_FOUND, Operation НЕ создаётся (existence-hiding,
// A15 — как DeleteTag). reject-if-tags/engine-down → Operation error в worker'е.
func (h *RegistryHandler) DeleteRepository(ctx context.Context, req *registryv1.DeleteRepositoryRequest) (*operationProto, error) {
	registryID, repository := req.GetRegistryId(), req.GetRepository()
	if err := registry.ValidateRegistryID(registryID); err != nil {
		return nil, mapErr(err)
	}
	if repository == "" {
		return nil, status.Error(codes.InvalidArgument, "repository is required")
	}
	if err := h.authz.checkRepository(ctx, registryID, repository, relationVDelete); err != nil {
		return nil, err
	}
	op, err := h.uc.DeleteRepository(ctx, registryID, repository)
	if err != nil {
		return nil, mapErr(err)
	}
	return operationToProto(op), nil
}

// RenameRepository запускает async-переименование overlay+engine и возвращает Operation.
// Malformed registry_id → InvalidArgument ПЕРВЫМ (A06). v_update@old + v_create@registry
// Check (deny|absent → NOT_FOUND). malformed/no-op new_name → InvalidArgument sync-first
// в use-case (A19). engine-down mid-remap → Operation error UNAVAILABLE (A21).
func (h *RegistryHandler) RenameRepository(ctx context.Context, req *registryv1.RenameRepositoryRequest) (*operationProto, error) {
	registryID, repository := req.GetRegistryId(), req.GetRepository()
	if err := registry.ValidateRegistryID(registryID); err != nil {
		return nil, mapErr(err)
	}
	if repository == "" {
		return nil, status.Error(codes.InvalidArgument, "repository is required")
	}
	if err := h.authz.checkRepository(ctx, registryID, repository, relationVUpdate); err != nil {
		return nil, err
	}
	if err := h.authz.registryGate(ctx, registryID, relationVCreate); err != nil {
		return nil, err
	}
	op, err := h.uc.RenameRepository(ctx, registryID, repository, req.GetNewName())
	if err != nil {
		return nil, mapErr(err)
	}
	return operationToProto(op), nil
}

// ListReferrers возвращает referrer-проекцию subject_digest (sync, bounded full-set).
// Malformed registry_id → InvalidArgument ПЕРВЫМ (A06). per-repo v_get Check (unauthorized|
// absent → NOT_FOUND, C02). malformed subject_digest → InvalidArgument sync-first (C04).
// subject без referrer'ов → пустой список (C03). Инфра-полей НЕ несёт (X01).
func (h *RegistryHandler) ListReferrers(ctx context.Context, req *registryv1.ListReferrersRequest) (*registryv1.ListReferrersResponse, error) {
	registryID, repository := req.GetRegistryId(), req.GetRepository()
	if err := registry.ValidateRegistryID(registryID); err != nil {
		return nil, mapErr(err)
	}
	if repository == "" {
		return nil, status.Error(codes.InvalidArgument, "repository is required")
	}
	if err := h.authz.checkRepository(ctx, registryID, repository, relationVGet); err != nil {
		return nil, err
	}
	referrers, err := h.uc.ListReferrers(ctx, registry.ReferrersQuery{
		RegistryID:    registryID,
		Repository:    repository,
		SubjectDigest: req.GetSubjectDigest(),
		ArtifactType:  req.GetArtifactType(),
	})
	if err != nil {
		return nil, mapErr(err)
	}
	resp := &registryv1.ListReferrersResponse{}
	for _, r := range referrers {
		resp.Referrers = append(resp.Referrers, toProtoReferrer(r))
	}
	return resp, nil
}

// toProtoReferrer конвертирует domain.Referrer → registryv1.Referrer (created_at
// truncate до секунд). Инфра-полей НЕ несёт (X01).
func toProtoReferrer(r *domain.Referrer) *registryv1.Referrer {
	if r == nil {
		return nil
	}
	return &registryv1.Referrer{
		RegistryId:    r.RegistryID,
		Repository:    r.Repository,
		SubjectDigest: r.SubjectDigest,
		Digest:        r.Digest,
		ArtifactType:  r.ArtifactType,
		SizeBytes:     r.SizeBytes,
		Annotations:   r.Annotations,
		CreatedAt:     prototime.Truncate(r.CreatedAt),
	}
}

// maskContains сообщает, содержит ли update_mask поле field (case-sensitive proto-path).
func maskContains(mask []string, field string) bool {
	for _, p := range mask {
		if p == field {
			return true
		}
	}
	return false
}
