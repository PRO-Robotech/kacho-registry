// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package handler

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/PRO-Robotech/kacho-corelib/operations"
	operationpb "github.com/PRO-Robotech/kacho-corelib/proto/gen/go/kacho/cloud/operation"
	registryv1 "github.com/PRO-Robotech/kacho-registry/proto/gen/go/kacho/cloud/registry/v1"

	"github.com/PRO-Robotech/kacho-registry/internal/domain"
)

// operationProto — псевдоним типа operation.Operation в форме, которую возвращают
// gRPC-стабы RegistryService мутаций (совпадает с corelib operation proto).
type operationProto = operationpb.Operation

// Проекция domain.Registry → registryv1.Registry (с output-only endpoint) —
// единый источник в use-case (UseCase.ProtoRegistry), т.к. endpoint зависит от
// конфигурируемой base. Handler зовёт h.uc.ProtoRegistry, отдельного конвертера
// Registry в transport-слое нет.

// toProtoRepository конвертирует domain.Repository → registryv1.Repository.
func toProtoRepository(r *domain.Repository) *registryv1.Repository {
	if r == nil {
		return nil
	}
	return &registryv1.Repository{
		RegistryId:   r.RegistryID,
		Name:         r.Name,
		TagCount:     r.TagCount,
		SizeBytes:    r.SizeBytes,
		UpdatedAt:    ts(r.UpdatedAt),
		ArtifactType: registryv1.ArtifactType(r.ArtifactType), // domain↔proto parity int32
	}
}

// toProtoTag конвертирует domain.Tag → registryv1.Tag.
func toProtoTag(t *domain.Tag) *registryv1.Tag {
	if t == nil {
		return nil
	}
	return &registryv1.Tag{
		RegistryId:   t.RegistryID,
		Repository:   t.Repository,
		Tag:          t.Tag,
		Digest:       t.Digest,
		SizeBytes:    t.SizeBytes,
		MediaType:    t.MediaType,
		CreatedAt:    ts(t.CreatedAt),
		Architecture: t.Architecture,
	}
}

// toProtoStats конвертирует domain.RegistryStats → registryv1.RegistryStats.
func toProtoStats(s *domain.RegistryStats) *registryv1.RegistryStats {
	if s == nil {
		return nil
	}
	return &registryv1.RegistryStats{
		RegistryId:      s.RegistryID,
		RepositoryCount: s.RepositoryCount,
		TagCount:        s.TagCount,
		TotalSizeBytes:  s.TotalSizeBytes,
		BlobCount:       s.BlobCount,
		LastGcAt:        ts(s.LastGCAt),
	}
}

func ts(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t.Truncate(time.Second))
}

// operationToProto конвертирует corelib operations.Operation в proto-форму
// (OperationService.Get/мутации возвращают её клиенту). oneof result —
// error|response (заполнен только при done).
func operationToProto(op *operations.Operation) *operationpb.Operation {
	if op == nil {
		return nil
	}
	p := &operationpb.Operation{
		Id:                   op.ID,
		Description:          op.Description,
		CreatedAt:            timestamppb.New(op.CreatedAt),
		CreatedBy:            op.CreatedBy,
		ModifiedAt:           timestamppb.New(op.ModifiedAt),
		Done:                 op.Done,
		Metadata:             op.Metadata,
		PrincipalType:        op.Principal.Type,
		PrincipalId:          op.Principal.ID,
		PrincipalDisplayName: op.Principal.DisplayName,
	}
	if op.Error != nil {
		p.Result = &operationpb.Operation_Error{Error: op.Error}
	} else if op.Response != nil {
		p.Result = &operationpb.Operation_Response{Response: op.Response}
	}
	return p
}
