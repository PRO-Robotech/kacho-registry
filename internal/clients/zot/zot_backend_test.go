// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package zot_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	zotclient "github.com/PRO-Robotech/kacho-registry/internal/clients/zot"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// RepoExists — repo «существует» (push-existing) если несёт ≥1 тег; иначе новый
// (push-new). Отсутствующий repo → false; zot недоступен → ErrUnavailable
// (fail-closed — не решаем new/existing вслепую).
func TestZot_Backend_RepoExists(t *testing.T) {
	fz := newFakeZot()
	fz.put("reg-A/app", "v1", "sha256:app1", 10, 100)
	srv := fz.server(t)
	cli := zotclient.New(srv.URL)

	exists, err := cli.RepoExists(t.Context(), "reg-A", "app")
	require.NoError(t, err)
	require.True(t, exists, "repo with a tag exists")

	missing, err := cli.RepoExists(t.Context(), "reg-A", "nope")
	require.NoError(t, err)
	require.False(t, missing, "repo without tags is new")

	// zot недоступен → fail-closed.
	broken := zotclient.New("")
	_, err = broken.RepoExists(t.Context(), "reg-A", "app")
	require.ErrorIs(t, err, regerrors.ErrUnavailable)
}

// CatalogRepoNames — полный zot-каталог (все namespace'ы) для per-repo listauthz
// фильтрации _catalog в data-plane.
func TestZot_Backend_CatalogRepoNames(t *testing.T) {
	fz := newFakeZot()
	fz.put("reg-A/app", "v1", "sha256:app1", 10, 100)
	fz.put("reg-A/web", "v1", "sha256:web1", 10, 50)
	fz.put("reg-B/secret", "v1", "sha256:sec1", 10, 500)
	srv := fz.server(t)
	cli := zotclient.New(srv.URL)

	names, err := cli.CatalogRepoNames(t.Context())
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"reg-A/app", "reg-A/web", "reg-B/secret"}, names)
}

// BlobInRepo — per-repo blob-scope: <digest> достижим только если входит в
// config/layers манифеста(ов) repo (REG-37). Чужой блоб → false.
func TestZot_Backend_BlobInRepo(t *testing.T) {
	fz := newFakeZot()
	// config digest = "sha256:cfg"+digest; layer digests = "sha256:l"+digest+<letter>.
	fz.put("reg-A/app", "v1", "sha256:app1", 10, 100, 200)
	srv := fz.server(t)
	cli := zotclient.New(srv.URL)

	// легитимный слой repo → true.
	in, err := cli.BlobInRepo(t.Context(), "reg-A", "app", "sha256:lsha256:app1a")
	require.NoError(t, err)
	require.True(t, in, "layer of repo manifest is in-scope")

	// config-блоб repo → true.
	inCfg, err := cli.BlobInRepo(t.Context(), "reg-A", "app", "sha256:cfgsha256:app1")
	require.NoError(t, err)
	require.True(t, inCfg)

	// чужой/несуществующий digest → false (existence-hiding на blob-уровне).
	out, err := cli.BlobInRepo(t.Context(), "reg-A", "app", "sha256:foreign")
	require.NoError(t, err)
	require.False(t, out, "foreign digest not in repo manifests")
}
