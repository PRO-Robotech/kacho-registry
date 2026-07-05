// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package dataplane

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// REG-19 — path-parser: сегментация OCI-путей, url-decode ДО сегментации,
// traversal (raw ".." и URL-encoded "%2e%2e") → ошибка; неизвестный registry-prefix
// / отсутствие repo → routeInvalid.
func TestDataplane_ParsePath(t *testing.T) {
	cases := []struct {
		name       string
		path       string
		wantRoute  route
		registryID string
		repo       string
		reference  string
		wantErr    bool
	}{
		{name: "ping_slash", path: "/v2/", wantRoute: routePing},
		{name: "ping_bare", path: "/v2", wantRoute: routePing},
		{name: "catalog", path: "/v2/_catalog", wantRoute: routeCatalog},
		{name: "manifest_by_tag", path: "/v2/reg-A/app/manifests/v1", wantRoute: routeManifest, registryID: "reg-A", repo: "app", reference: "v1"},
		{name: "manifest_multiseg_repo", path: "/v2/reg-A/team/app/manifests/v1", wantRoute: routeManifest, registryID: "reg-A", repo: "team/app", reference: "v1"},
		{name: "blob_by_digest", path: "/v2/reg-A/app/blobs/sha256:abcdef", wantRoute: routeBlob, registryID: "reg-A", repo: "app", reference: "sha256:abcdef"},
		{name: "upload_initiate", path: "/v2/reg-A/app/blobs/uploads/", wantRoute: routeUpload, registryID: "reg-A", repo: "app"},
		{name: "upload_with_uuid", path: "/v2/reg-A/app/blobs/uploads/uuid-123", wantRoute: routeUpload, registryID: "reg-A", repo: "app"},
		{name: "tags_list", path: "/v2/reg-A/app/tags/list", wantRoute: routeTagsList, registryID: "reg-A", repo: "app"},
		{name: "referrers", path: "/v2/reg-A/app/referrers/sha256:dd", wantRoute: routeReferrers, registryID: "reg-A", repo: "app", reference: "sha256:dd"},
		// name без repo-сегмента → invalid (нет <registryID>/<repo>).
		{name: "no_repo", path: "/v2/app/manifests/v1", wantRoute: routeInvalid},
		// неизвестный registry-prefix → invalid.
		{name: "bad_prefix", path: "/v2/xyz/app/manifests/v1", wantRoute: routeInvalid},
		// traversal raw "..".
		{name: "traversal_raw", path: "/v2/reg-A/../reg-B/app/manifests/v1", wantErr: true},
		// traversal URL-encoded "%2e%2e".
		{name: "traversal_encoded", path: "/v2/reg-A/%2e%2e/reg-B/app/manifests/v1", wantErr: true},
		// encoded-slash в сегменте → отклонить.
		{name: "encoded_slash", path: "/v2/reg-A/app%2fevil/manifests/v1", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := parsePath(tc.path)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantRoute, p.route, "route")
			if tc.wantRoute != routeInvalid {
				require.Equal(t, tc.registryID, p.registryID, "registryID")
				require.Equal(t, tc.repo, p.repo, "repo")
				require.Equal(t, tc.reference, p.reference, "reference")
			}
		})
	}
}
