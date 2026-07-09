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

// manifestBody — минимальный разбор OCI/Docker image-манифеста: config (mediaType —
// дискриминатор типа артефакта; size/digest — для расчёта размеров) и layers. Только
// эти два поля читаются consumer'ами (manifestHasDigest / Stats). manifest-index не
// несёт config/layers → вклад в размер/блобы 0 (best-effort, index-child-агрегация не
// реализована).
type manifestBody struct {
	Config descriptor   `json:"config"`
	Layers []descriptor `json:"layers"`
}

type descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

// errNotFound — внутренний sentinel: zot ответил 404 (тег/манифест/repo отсутствует).
// Маппится caller-методом в идемпотентный success либо пустую проекцию.
var errNotFound = fmt.Errorf("zot: not found")

// maxManifestBytes — верхняя граница тела манифеста, читаемого getManifest под
// io.LimitReader. Манифест OCI/Docker — компактный список дескрипторов (config +
// layers), не blob-контент; реальные манифесты — килобайты, спека/реестры клампят их
// единицами МБ. LimitReader — defense-in-depth (CWE-770): скомпрометированный/битый
// zot не должен OOM'ить декодер безразмерным телом. Тело сверх лимита → усечённый
// JSON → decode error → failClosed ErrUnavailable.
const maxManifestBytes = 16 << 20 // 16 MiB

// maxJSONBytes — верхняя граница тела getJSON/do()-ответа (Distribution-API: кросс-
// тенантный /v2/_catalog, per-repo tags/list), читаемого под io.LimitReader перед
// json.Decode. _catalog не пагинируется server-side, а tags/list несёт все теги repo —
// tenant-controlled count иначе материализуется в память целиком на каждый вызов
// (CWE-770). LimitReader — defense-in-depth (паритет с decodeManifest / maxManifestBytes):
// оверсайз-ответ деградирует в fail-closed ErrUnavailable, не в безразмерную аллокацию.
const maxJSONBytes = 16 << 20 // 16 MiB

// decodeManifest разбирает тело манифеста (config + layers) под io.LimitReader(limit).
// Ошибка декода (в т.ч. усечение сверх лимита) → failClosed ErrUnavailable (сырой
// zot-текст наружу не течёт).
func decodeManifest(body io.Reader, limit int64) (manifestBody, error) {
	var mb manifestBody
	if err := json.NewDecoder(io.LimitReader(body, limit)).Decode(&mb); err != nil {
		return manifestBody{}, failClosed("GET manifest decode", "err", err)
	}
	return mb, nil
}

// decodeJSONBody декодирует JSON-тело из body под io.LimitReader(limit) в out. Ошибка
// декода (в т.ч. усечение тела сверх лимита) → failClosed ErrUnavailable (сырой zot-текст
// наружу не течёт; оверсайз-ответ деградирует в fail-closed, не в безразмерную аллокацию).
func decodeJSONBody(body io.Reader, limit int64, out any) error {
	if err := json.NewDecoder(io.LimitReader(body, limit)).Decode(out); err != nil {
		return failClosed("json decode", "err", err)
	}
	return nil
}

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

// headManifest резолвит digest манифеста по ref (тег или digest) через
// HEAD /manifests/<ref>. 404 → errNotFound. Единственный caller (DeleteTag) читает
// только digest — size/media-type не проецируются.
func (c *Client) headManifest(ctx context.Context, fullRepo, ref string) (digest string, err error) {
	req, rerr := http.NewRequestWithContext(ctx, http.MethodHead,
		c.baseURL+"/v2/"+repoPath(fullRepo)+"/manifests/"+url.PathEscape(ref), nil)
	if rerr != nil {
		return "", failClosed("HEAD manifest request build", "err", rerr)
	}
	req.Header.Set("Accept", acceptManifests)
	resp, derr := c.http.Do(req)
	if derr != nil {
		return "", failClosed("HEAD manifest transport", "err", derr)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return "", errNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", failClosed("HEAD manifest non-2xx", "status", resp.StatusCode)
	}
	return resp.Header.Get("Docker-Content-Digest"), nil
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
		_, _ = io.Copy(io.Discard, resp.Body)
		return manifestBody{}, errNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return manifestBody{}, failClosed("GET manifest non-2xx", "status", resp.StatusCode)
	}
	mb, err := decodeManifest(resp.Body, maxManifestBytes)
	if err != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return manifestBody{}, err
	}
	// decodeManifest останавливается на первом значении под LimitReader, не доходя до
	// io.EOF — дренируем остаток тела, чтобы net/http вернул соединение в пул
	// (keepalive к zot на hot manifest-fan-out пути), как в error-ветках выше.
	_, _ = io.Copy(io.Discard, resp.Body)
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
		if derr := decodeJSONBody(resp.Body, maxJSONBytes, out); derr != nil {
			return derr
		}
		// json.Decoder останавливается на первом значении, не доходя до io.EOF —
		// без дренажа net/http не вернёт persistent-соединение в пул на Body.Close
		// (свежий TCP+TLS handshake на каждый introspection-вызов к zot). Дренируем,
		// как в non-2xx/404-ветках выше, чтобы сохранить keepalive.
		_, _ = io.Copy(io.Discard, resp.Body)
	} else {
		_, _ = io.Copy(io.Discard, resp.Body)
	}
	return nil
}
