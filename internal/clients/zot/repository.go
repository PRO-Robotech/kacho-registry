// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package zot

// repository.go — config-overlay Repository (RG-1) engine-операции zot-адаптера:
// per-repo projection (RepositoryProjection), emptiness (RepositoryEmpty), referrer-
// проекция (ListReferrers), engine re-home тегов/манифестов при rename (RenameRepository).
// Все read-проекции — output-only зеркало zot (source of truth = zot). Все HTTP-сбои →
// ErrUnavailable (fail-closed; сырой zot-текст наружу не течёт).

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/PRO-Robotech/kacho-registry/internal/domain"
)

// RepositoryProjection возвращает projection-слой одного repo (tag_count/size/artifact-
// типы/timestamps) через search-ext GraphQL ImageList. Нет тегов (durable-empty / repo
// ещё не пушился) → (nil, nil) — overlay-слой durable пережил пустоту, ephemeral без
// проекции невидим (existence-hiding в use-case/handler). zot недоступен → ErrUnavailable.
func (c *Client) RepositoryProjection(ctx context.Context, registryID, repository string) (*domain.Repository, error) {
	if err := c.ready(); err != nil {
		return nil, err
	}
	fullRepo := registryID + "/" + repository
	var data gqlImageListData
	if err := c.gqlQuery(ctx, imageListQuery(fullRepo), &data); err != nil {
		return nil, err
	}
	results := data.ImageList.Results
	if len(results) == 0 {
		return nil, nil
	}
	// Пустой GlobalSearch-агрегат (rs) → repositoryFromSummaries fallback'ит size/
	// updated_at/download_count из суммы/максимума по тегам.
	return repositoryFromSummaries(registryID, repository, gqlRepoSummary{}, results), nil
}

// RepositoryEmpty сообщает, есть ли у repo ≥1 тег (DeleteRepository reject-if-tags, D-4).
// Читает GET /v2/<full-repo>/tags/list (404 → пустой → true). zot недоступен →
// ErrUnavailable (fail-closed: overlay не сносим, пока не подтвердили пустоту, A14).
func (c *Client) RepositoryEmpty(ctx context.Context, registryID, repository string) (bool, error) {
	if err := c.ready(); err != nil {
		return false, err
	}
	tags, err := c.repoTags(ctx, registryID+"/"+repository)
	if err != nil {
		return false, err
	}
	return len(tags) == 0, nil
}

// ListReferrers возвращает referrer-проекцию subject_digest через OCI referrers-API
// (GET /v2/<full-repo>/referrers/<digest> → OCI image-index descriptor'ов, D-8). Bounded
// full-set (без пагинации — зеркалит OCI single-index). Опциональный artifactType facet
// применяется server-side (query-param) И client-side (defense-in-depth, если движок не
// отфильтровал). Нет referrer'ов / нет index (404) → пустой список (C03, не ошибка).
// Инфра-полей НЕ несёт (X01). zot недоступен → ErrUnavailable.
func (c *Client) ListReferrers(ctx context.Context, registryID, repository, subjectDigest, artifactType string) ([]*domain.Referrer, error) {
	if err := c.ready(); err != nil {
		return nil, err
	}
	fullRepo := registryID + "/" + repository
	path := "/v2/" + repoPath(fullRepo) + "/referrers/" + url.PathEscape(subjectDigest)
	if artifactType != "" {
		path += "?artifactType=" + url.QueryEscape(artifactType)
	}
	var idx ociReferrersIndex
	if err := c.getJSON(ctx, path, &idx); err != nil {
		if errors.Is(err, errNotFound) {
			return []*domain.Referrer{}, nil // subject без referrer'ов → пусто (C03)
		}
		return nil, err
	}
	out := make([]*domain.Referrer, 0, len(idx.Manifests))
	for _, m := range idx.Manifests {
		if artifactType != "" && m.ArtifactType != artifactType {
			continue // client-side facet (движок мог не отфильтровать)
		}
		out = append(out, &domain.Referrer{
			RegistryID:    registryID,
			Repository:    repository,
			SubjectDigest: subjectDigest,
			Digest:        m.Digest,
			ArtifactType:  m.ArtifactType,
			SizeBytes:     m.Size,
			Annotations:   m.Annotations,
			CreatedAt:     referrerCreatedAt(m.Annotations),
		})
	}
	return out, nil
}

// RenameRepository re-home'ит теги/манифесты repo old→new в движке (многошаговая
// НЕ-атомарная OCI-операция, D-5): для каждого тега — raw-manifest GET(old) → PUT(new)
// (блобы шарятся по digest в storage zot — манифест PUT с существующими digest'ами
// резолвится), затем DELETE(old). Копирование ВСЕХ тегов в new ПРЕДШЕСТВУЕТ удалению old
// — на любом сбое движка возвращаем ErrUnavailable fail-closed, а старое имя по-прежнему
// резолвится (A21: НЕ бывает состояния «не адресуем ни под старым, ни под новым»).
// Целевое имя занято на уровне overlay/проекции — арбитрит use-case pre-check + DB PK.
func (c *Client) RenameRepository(ctx context.Context, registryID, oldName, newName string) error {
	if err := c.ready(); err != nil {
		return err
	}
	oldRepo := registryID + "/" + oldName
	tags, err := c.repoTags(ctx, oldRepo)
	if err != nil {
		return err
	}
	newRepo := registryID + "/" + newName
	// Фаза 1: копируем все теги old→new (оба адресуемы во время копирования).
	for _, tag := range tags {
		raw, contentType, gerr := c.rawManifest(ctx, oldRepo, tag)
		if gerr != nil {
			return gerr // fail-closed: old ещё цел
		}
		if perr := c.putManifest(ctx, newRepo, tag, raw, contentType); perr != nil {
			return perr // fail-closed: old ещё цел, new частично — overlay НЕ rekey'ится
		}
	}
	// Фаза 2: снимаем old (последним) — теперь new полностью населён, old→404.
	for _, tag := range tags {
		if derr := c.DeleteTag(ctx, registryID, oldName, tag); derr != nil {
			return derr
		}
	}
	return nil
}

// ---- OCI referrers/manifest типы + низкоуровневые helpers ----

// ociDescriptor — дескриптор OCI image-index (referrers-API элемент).
type ociDescriptor struct {
	Digest       string            `json:"digest"`
	MediaType    string            `json:"mediaType"`
	ArtifactType string            `json:"artifactType"`
	Size         int64             `json:"size"`
	Annotations  map[string]string `json:"annotations"`
}

// ociReferrersIndex — тело GET /v2/<repo>/referrers/<digest> (OCI image-index).
type ociReferrersIndex struct {
	Manifests []ociDescriptor `json:"manifests"`
}

// annotationCreated — OCI-аннотация момента создания артефакта (RFC3339).
const annotationCreated = "org.opencontainers.image.created"

// referrerCreatedAt извлекает created_at referrer'а из OCI-аннотаций
// (org.opencontainers.image.created, RFC3339). Отсутствует/невалидна → нулевой time
// (proto-truncate отдаст пусто на wire).
func referrerCreatedAt(annotations map[string]string) time.Time {
	if annotations == nil {
		return time.Time{}
	}
	return parseZotTS(annotations[annotationCreated])
}

// rawManifest читает сырое тело манифеста (bytes + Content-Type) — нужно для точного
// re-home при rename (getManifest декодирует в структуру, теряя байты/тип). 404/не-2xx/
// транспорт → ErrUnavailable (fail-closed). Тело под LimitReader(maxManifestBytes).
func (c *Client) rawManifest(ctx context.Context, fullRepo, ref string) ([]byte, string, error) {
	req, rerr := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+"/v2/"+repoPath(fullRepo)+"/manifests/"+url.PathEscape(ref), nil)
	if rerr != nil {
		return nil, "", failClosed("raw manifest request build", "err", rerr)
	}
	req.Header.Set("Accept", acceptManifests)
	resp, derr := c.http.Do(req)
	if derr != nil {
		return nil, "", failClosed("raw manifest transport", "err", derr)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, "", failClosed("raw manifest non-2xx", "status", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestBytes))
	if err != nil {
		return nil, "", failClosed("raw manifest read", "err", err)
	}
	return raw, resp.Header.Get("Content-Type"), nil
}

// putManifest публикует манифест raw (bytes + Content-Type) под ref в fullRepo (re-home
// шаг rename). не-2xx/транспорт → ErrUnavailable (fail-closed).
func (c *Client) putManifest(ctx context.Context, fullRepo, ref string, raw []byte, contentType string) error {
	req, rerr := http.NewRequestWithContext(ctx, http.MethodPut,
		c.baseURL+"/v2/"+repoPath(fullRepo)+"/manifests/"+url.PathEscape(ref), bytes.NewReader(raw))
	if rerr != nil {
		return failClosed("put manifest request build", "err", rerr)
	}
	if contentType == "" {
		contentType = "application/vnd.oci.image.manifest.v1+json"
	}
	req.Header.Set("Content-Type", contentType)
	resp, derr := c.http.Do(req)
	if derr != nil {
		return failClosed("put manifest transport", "err", derr)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return failClosed("put manifest non-2xx", "status", resp.StatusCode)
	}
	return nil
}
