// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package handler — тонкий gRPC-transport kacho-registry (parse → use-case →
// format, без бизнес-логики). public.go — control-plane RegistryService
// (public :9090): sync Get/List/ListRepositories/ListTags + async
// Create/Update/Delete/DeleteTag (→ Operation). Admin InternalRegistryService —
// в internal.go (только :9091).
//
// Все методы делегируют use-case'у; в скелете use-case/порты возвращают
// ErrUnimplemented → клиент видит codes.Unimplemented. Наполнение — rpc-implementer.
package handler

import (
	"context"

	registryv1 "github.com/PRO-Robotech/kacho-registry/proto/gen/go/kacho/cloud/registry/v1"

	registry "github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/api/registry"
)

// RegistryHandler реализует registryv1.RegistryServiceServer.
type RegistryHandler struct {
	registryv1.UnimplementedRegistryServiceServer
	uc *registry.UseCase
}

// NewRegistryHandler конструирует RegistryHandler.
func NewRegistryHandler(uc *registry.UseCase) *RegistryHandler { return &RegistryHandler{uc: uc} }

// Get возвращает Registry по id (sync).
func (h *RegistryHandler) Get(ctx context.Context, req *registryv1.GetRegistryRequest) (*registryv1.Registry, error) {
	r, err := h.uc.Get(ctx, req.GetRegistryId())
	if err != nil {
		return nil, mapErr(err)
	}
	return h.uc.ProtoRegistry(r), nil
}

// List возвращает реестры project'а (sync, cursor-пагинация; listauthz-фильтр).
func (h *RegistryHandler) List(ctx context.Context, req *registryv1.ListRegistriesRequest) (*registryv1.ListRegistriesResponse, error) {
	items, next, err := h.uc.List(ctx, registry.ListQuery{
		ProjectID: req.GetProjectId(),
		PageSize:  int64(req.GetPageSize()),
		PageToken: req.GetPageToken(),
		Filter:    req.GetFilter(),
	})
	if err != nil {
		return nil, mapErr(err)
	}
	resp := &registryv1.ListRegistriesResponse{NextPageToken: next}
	for _, r := range items {
		resp.Registries = append(resp.Registries, h.uc.ProtoRegistry(r))
	}
	return resp, nil
}

// Create запускает async-создание реестра и возвращает Operation (done=false).
func (h *RegistryHandler) Create(ctx context.Context, req *registryv1.CreateRegistryRequest) (*operationProto, error) {
	op, err := h.uc.Create(ctx, registry.CreateSpec{
		ProjectID:   req.GetProjectId(),
		Name:        req.GetName(),
		Description: req.GetDescription(),
		Labels:      req.GetLabels(),
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return operationToProto(op), nil
}

// Update запускает async-смену mutable-полей (labels/description) и возвращает Operation.
func (h *RegistryHandler) Update(ctx context.Context, req *registryv1.UpdateRegistryRequest) (*operationProto, error) {
	op, err := h.uc.Update(ctx, registry.UpdateSpec{
		RegistryID:  req.GetRegistryId(),
		Description: req.GetDescription(),
		Labels:      req.GetLabels(),
		Mask:        req.GetUpdateMask().GetPaths(),
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return operationToProto(op), nil
}

// Delete запускает async-удаление реестра и возвращает Operation.
func (h *RegistryHandler) Delete(ctx context.Context, req *registryv1.DeleteRegistryRequest) (*operationProto, error) {
	op, err := h.uc.Delete(ctx, req.GetRegistryId())
	if err != nil {
		return nil, mapErr(err)
	}
	return operationToProto(op), nil
}

// ListRepositories возвращает проекцию repos namespace из zot (sync, per-repo filter).
func (h *RegistryHandler) ListRepositories(ctx context.Context, req *registryv1.ListRepositoriesRequest) (*registryv1.ListRepositoriesResponse, error) {
	items, next, err := h.uc.ListRepositories(ctx, registry.RepoListQuery{
		RegistryID: req.GetRegistryId(),
		PageSize:   int64(req.GetPageSize()),
		PageToken:  req.GetPageToken(),
	})
	if err != nil {
		return nil, mapErr(err)
	}
	resp := &registryv1.ListRepositoriesResponse{NextPageToken: next}
	for _, r := range items {
		resp.Repositories = append(resp.Repositories, toProtoRepository(r))
	}
	return resp, nil
}

// ListTags возвращает проекцию тегов repo из zot (sync, per-repo Check).
func (h *RegistryHandler) ListTags(ctx context.Context, req *registryv1.ListTagsRequest) (*registryv1.ListTagsResponse, error) {
	items, next, err := h.uc.ListTags(ctx, registry.TagListQuery{
		RegistryID: req.GetRegistryId(),
		Repository: req.GetRepository(),
		PageSize:   int64(req.GetPageSize()),
		PageToken:  req.GetPageToken(),
	})
	if err != nil {
		return nil, mapErr(err)
	}
	resp := &registryv1.ListTagsResponse{NextPageToken: next}
	for _, t := range items {
		resp.Tags = append(resp.Tags, toProtoTag(t))
	}
	return resp, nil
}

// DeleteTag запускает async-удаление тега/манифеста и возвращает Operation.
func (h *RegistryHandler) DeleteTag(ctx context.Context, req *registryv1.DeleteTagRequest) (*operationProto, error) {
	op, err := h.uc.DeleteTag(ctx, req.GetRegistryId(), req.GetRepository(), req.GetTag())
	if err != nil {
		return nil, mapErr(err)
	}
	return operationToProto(op), nil
}
