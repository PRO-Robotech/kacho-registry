// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package zot

// httpclient.go — низкоуровневые HTTP-помощники zot-адаптера: do/getJSON/
// headManifest/getManifest + repoPath-кодирование + разбор тела манифеста. Сырой
// zot-текст наружу не течёт — любой не-2xx/транспортный сбой маппится в фиксированный
// sentinel (fail-closed), 404 → внутренний errNotFound.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// acceptManifests — Accept-заголовок манифест-запросов (OCI + Docker media-types),
// чтобы zot вернул конкретный манифест, а не index по умолчанию.
const acceptManifests = "application/vnd.oci.image.manifest.v1+json," +
	"application/vnd.docker.distribution.manifest.v2+json," +
	"application/vnd.oci.image.index.v1+json," +
	"application/vnd.docker.distribution.manifest.list.v2+json"

// manifestBody — минимальный разбор OCI/Docker image-манифеста: top-level mediaType
// (index/manifest-list для multi-arch), config (mediaType — дискриминатор типа
// артефакта; size/digest — для расчёта размеров) и layers. manifest-index не несёт
// layers — вклад в размер/блобы 0 (best-effort), но top-level mediaType несёт.
type manifestBody struct {
	MediaType string       `json:"mediaType"`
	Config    descriptor   `json:"config"`
	Layers    []descriptor `json:"layers"`
	// Manifests — дочерние манифесты multi-arch index/list (config/layers у самого
	// index нет; размер образа = сумма их size).
	Manifests []descriptor `json:"manifests"`
}

type descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

// errNotFound — внутренний sentinel: zot ответил 404 (тег/манифест/repo отсутствует).
// Маппится caller-методом в идемпотентный success либо пустую проекцию.
var errNotFound = fmt.Errorf("zot: not found")

// repoPath url-кодирует сегменты полного repo-пути (multi-segment), сохраняя '/'.
func repoPath(fullRepo string) string {
	segs := strings.Split(fullRepo, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}

// getJSON выполняет GET и декодирует JSON-тело. 404 → errNotFound; прочий не-2xx или
// транспортный сбой → ErrUnavailable (fail-closed, сырой zot-текст наружу не течёт).
func (c *Client) getJSON(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, out)
}

// headManifest резолвит digest/size/media-type манифеста по ref (тег или digest)
// через HEAD /manifests/<ref>. 404 → errNotFound.
func (c *Client) headManifest(ctx context.Context, fullRepo, ref string) (digest string, size int64, mediaType string, err error) {
	req, rerr := http.NewRequestWithContext(ctx, http.MethodHead,
		c.baseURL+"/v2/"+repoPath(fullRepo)+"/manifests/"+url.PathEscape(ref), nil)
	if rerr != nil {
		return "", 0, "", failClosed("HEAD manifest request build", "err", rerr)
	}
	req.Header.Set("Accept", acceptManifests)
	resp, derr := c.http.Do(req)
	if derr != nil {
		return "", 0, "", failClosed("HEAD manifest transport", "err", derr)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return "", 0, "", errNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", 0, "", failClosed("HEAD manifest non-2xx", "status", resp.StatusCode)
	}
	return resp.Header.Get("Docker-Content-Digest"), resp.ContentLength, resp.Header.Get("Content-Type"), nil
}

// getManifest читает и разбирает тело манифеста (config + layers). 404 → errNotFound.
func (c *Client) getManifest(ctx context.Context, fullRepo, ref string) (manifestBody, error) {
	req, rerr := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+"/v2/"+repoPath(fullRepo)+"/manifests/"+url.PathEscape(ref), nil)
	if rerr != nil {
		return manifestBody{}, failClosed("GET manifest request build", "err", rerr)
	}
	req.Header.Set("Accept", acceptManifests)
	resp, derr := c.http.Do(req)
	if derr != nil {
		return manifestBody{}, failClosed("GET manifest transport", "err", derr)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return manifestBody{}, errNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return manifestBody{}, failClosed("GET manifest non-2xx", "status", resp.StatusCode)
	}
	var mb manifestBody
	if err := json.NewDecoder(resp.Body).Decode(&mb); err != nil {
		return manifestBody{}, failClosed("GET manifest decode", "err", err)
	}
	return mb, nil
}

// do выполняет запрос method+path; при out != nil декодирует JSON-тело. 404 →
// errNotFound; прочий не-2xx или транспортный сбой → ErrUnavailable. Сырой zot-текст
// наружу не течёт (fail-closed фиксированный sentinel).
func (c *Client) do(ctx context.Context, method, path string, body io.Reader, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return failClosed("request build", "method", method, "path", path, "err", err)
	}
	if out != nil {
		req.Header.Set("Accept", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return failClosed("transport", "method", method, "path", path, "err", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return failClosed("non-2xx", "method", method, "path", path, "status", resp.StatusCode)
	}
	if out != nil {
		if derr := json.NewDecoder(resp.Body).Decode(out); derr != nil {
			return failClosed("decode", "method", method, "path", path, "err", derr)
		}
	} else {
		_, _ = io.Copy(io.Discard, resp.Body)
	}
	return nil
}
