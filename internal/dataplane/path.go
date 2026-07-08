// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package dataplane

import (
	"errors"
	"net/url"
	"strings"

	"github.com/PRO-Robotech/kacho-corelib/ids"
	corevalidate "github.com/PRO-Robotech/kacho-corelib/validate"
)

// route — распознанный вид OCI-пути (метод определяет verb/действие отдельно).
type route int

const (
	routeInvalid   route = iota // нераспознанный путь → 404
	routePing                   // GET /v2/
	routeCatalog                // GET /v2/_catalog
	routeManifest               // /v2/<reg>/<repo>/manifests/<ref>
	routeBlob                   // /v2/<reg>/<repo>/blobs/<digest>
	routeUpload                 // /v2/<reg>/<repo>/blobs/uploads[/<uuid>]
	routeTagsList               // /v2/<reg>/<repo>/tags/list
	routeReferrers              // /v2/<reg>/<repo>/referrers/<digest>
)

// parsed — результат разбора пути: namespace/repo + reference (manifest ref /
// blob digest / referrers digest).
type parsed struct {
	route      route
	registryID string
	repo       string // repo-path внутри namespace (может быть multi-segment)
	reference  string
}

// errTraversal — path traversal (raw ".."/"." или URL-encoded "%2e%2e") либо
// encoded-slash в сегменте. Отклоняется 400 ДО обращения к zot.
var errTraversal = errors.New("path traversal rejected")

// parsePath разбирает escaped OCI-path (r.URL.EscapedPath()). Инвариант REG-19
// (split-then-decode): СНАЧАЛА сегментация ещё-escaped пути по '/' (strings.Split),
// ПОТОМ url-decode каждого сегмента по отдельности — и декодированный сегмент
// отвергается, если он "."/".." либо содержит разделитель пути ('/'/'\\'). Порядок
// именно такой: декодируй мы ДО сегментации, `%2f`/`%2e%2e` развернулись бы в
// разделители и `..` вырвались бы из namespace-префикса (path-traversal). Неизвестный
// registry-prefix / отсутствие repo → routeInvalid.
func parsePath(escapedPath string) (parsed, error) {
	if escapedPath == "/v2" || escapedPath == "/v2/" {
		return parsed{route: routePing}, nil
	}
	trimmed, ok := strings.CutPrefix(escapedPath, "/v2/")
	if !ok {
		return parsed{route: routeInvalid}, nil
	}

	segs := make([]string, 0, 8)
	for _, raw := range strings.Split(trimmed, "/") {
		if raw == "" {
			continue // ведущий/замыкающий/двойной слэш (напр. "blobs/uploads/")
		}
		dec, err := url.PathUnescape(raw)
		if err != nil {
			return parsed{}, errTraversal
		}
		// traversal и encoded-slash: сегмент после декодирования не должен быть
		// "."/".." и не должен содержать разделитель пути (иначе вырвется из namespace).
		if dec == "." || dec == ".." || strings.ContainsAny(dec, "/\\") {
			return parsed{}, errTraversal
		}
		segs = append(segs, dec)
	}

	if len(segs) == 1 && segs[0] == "_catalog" {
		return parsed{route: routeCatalog}, nil
	}

	n := len(segs)
	switch {
	case n >= 3 && segs[n-2] == "tags" && segs[n-1] == "list":
		return finishName(segs[:n-2], routeTagsList, "")
	case n >= 3 && segs[n-2] == "blobs" && segs[n-1] == "uploads":
		return finishName(segs[:n-2], routeUpload, "")
	case n >= 4 && segs[n-3] == "blobs" && segs[n-2] == "uploads":
		// upload-session-uuid (segs[n-1]) не используется authz-логикой (push
		// адресует repo, не reference) — не переносим в reference.
		return finishName(segs[:n-3], routeUpload, "")
	case n >= 3 && segs[n-2] == "manifests":
		return finishName(segs[:n-2], routeManifest, segs[n-1])
	case n >= 3 && segs[n-2] == "referrers":
		return finishName(segs[:n-2], routeReferrers, segs[n-1])
	case n >= 3 && segs[n-2] == "blobs":
		return finishName(segs[:n-2], routeBlob, segs[n-1])
	default:
		return parsed{route: routeInvalid}, nil
	}
}

// finishName выделяет <registryID>/<repo> из name-сегментов (первый — registryID,
// остальные — repo-path). Требует ≥2 сегмента; registryID обязан нести известный
// Kachō-prefix (иначе routeInvalid → 404, REG-19 «без валидного registry-prefix»).
func finishName(nameSegs []string, rt route, ref string) (parsed, error) {
	if len(nameSegs) < 2 {
		return parsed{route: routeInvalid}, nil
	}
	registryID := nameSegs[0]
	if err := corevalidate.ResourceID("registry", ids.PrefixRegistry, registryID); err != nil {
		return parsed{route: routeInvalid}, nil
	}
	return parsed{
		route:      rt,
		registryID: registryID,
		repo:       strings.Join(nameSegs[1:], "/"),
		reference:  ref,
	}, nil
}
