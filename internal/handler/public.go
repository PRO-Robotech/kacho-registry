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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	registryv1 "github.com/PRO-Robotech/kacho-registry/proto/gen/go/kacho/cloud/registry/v1"

	registry "github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/api/registry"
	"github.com/PRO-Robotech/kacho-registry/internal/domain"
)

// RegistryHandler реализует registryv1.RegistryServiceServer.
type RegistryHandler struct {
	registryv1.UnimplementedRegistryServiceServer
	uc    *registry.UseCase
	authz repoAuthz
}

// NewRegistryHandler конструирует RegistryHandler. authz — per-repo Check-порт для
// ScopeFiltered RPC (ListRepositories/ListTags/DeleteTag); nil → breakglass (bypass).
func NewRegistryHandler(uc *registry.UseCase, authz Authorizer) *RegistryHandler {
	return &RegistryHandler{uc: uc, authz: newRepoAuthz(authz)}
}

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

// ListRepositories возвращает проекцию repos namespace из zot (sync). Authz — два
// уровня В ХЕНДЛЕРЕ (RPC ScopeFiltered, interceptor пропускает): (1) namespace
// call-gate v_list на registry_registry:<reg> (deny→NOT_FOUND, existence-hiding);
// (2) per-repo row-filter — только repos, на которые subject имеет v_list
// (namespace-viewer НЕ видит все repos автоматически). Пагинация — ПОСЛЕ фильтра.
func (h *RegistryHandler) ListRepositories(ctx context.Context, req *registryv1.ListRepositoriesRequest) (*registryv1.ListRepositoriesResponse, error) {
	registryID := req.GetRegistryId()
	if err := validateRegistryID(registryID); err != nil {
		return nil, mapErr(err)
	}
	if err := h.authz.namespaceGate(ctx, registryID); err != nil {
		return nil, err
	}
	items, _, err := h.uc.ListRepositories(ctx, registry.RepoListQuery{RegistryID: registryID})
	if err != nil {
		return nil, mapErr(err)
	}
	filtered, err := h.authz.filterRepos(ctx, registryID, items)
	if err != nil {
		return nil, err
	}
	page, next, err := pageByName(filtered, func(r *domain.Repository) string { return r.Name },
		int64(req.GetPageSize()), req.GetPageToken())
	if err != nil {
		return nil, mapErr(err)
	}
	resp := &registryv1.ListRepositoriesResponse{NextPageToken: next}
	for _, r := range page {
		resp.Repositories = append(resp.Repositories, toProtoRepository(r))
	}
	return resp, nil
}

// ListTags возвращает проекцию тегов repo из zot (sync). Authz В ХЕНДЛЕРЕ: per-repo
// Check v_list на registry_repository:<reg>/<repo> (deny→NOT_FOUND, existence-hiding —
// теги чужого repo не раскрываются). Пагинация — по имени тега.
func (h *RegistryHandler) ListTags(ctx context.Context, req *registryv1.ListTagsRequest) (*registryv1.ListTagsResponse, error) {
	registryID, repository := req.GetRegistryId(), req.GetRepository()
	if err := validateRegistryID(registryID); err != nil {
		return nil, mapErr(err)
	}
	if repository == "" {
		return nil, status.Error(codes.InvalidArgument, "repository is required")
	}
	if err := h.authz.checkRepo(ctx, registryID, repository, relationVList); err != nil {
		return nil, err
	}
	items, _, err := h.uc.ListTags(ctx, registry.TagListQuery{RegistryID: registryID, Repository: repository})
	if err != nil {
		return nil, mapErr(err)
	}
	page, next, err := pageByName(items, func(t *domain.Tag) string { return t.Tag },
		int64(req.GetPageSize()), req.GetPageToken())
	if err != nil {
		return nil, mapErr(err)
	}
	resp := &registryv1.ListTagsResponse{NextPageToken: next}
	for _, t := range page {
		resp.Tags = append(resp.Tags, toProtoTag(t))
	}
	return resp, nil
}

// DeleteTag запускает async-удаление тега/манифеста и возвращает Operation. Per-repo
// Check v_delete на registry_repository:<reg>/<repo> — В ХЕНДЛЕРЕ, СИНХРОННО, ДО
// создания Operation: deny → NOT_FOUND (existence-hiding), Operation НЕ создаётся,
// worker НЕ запускается (async-Operation с error раскрыл бы факт приёма мутации).
func (h *RegistryHandler) DeleteTag(ctx context.Context, req *registryv1.DeleteTagRequest) (*operationProto, error) {
	registryID, repository, tag := req.GetRegistryId(), req.GetRepository(), req.GetTag()
	if err := validateRegistryID(registryID); err != nil {
		return nil, mapErr(err)
	}
	if repository == "" {
		return nil, status.Error(codes.InvalidArgument, "repository is required")
	}
	if tag == "" {
		return nil, status.Error(codes.InvalidArgument, "tag is required")
	}
	if err := h.authz.checkRepo(ctx, registryID, repository, relationVDelete); err != nil {
		return nil, err
	}
	op, err := h.uc.DeleteTag(ctx, registryID, repository, tag)
	if err != nil {
		return nil, mapErr(err)
	}
	return operationToProto(op), nil
}
