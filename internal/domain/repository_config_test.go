// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-registry/internal/domain"
)

// RG-1-A05/A19 — ValidateRepositoryName: пусто → "repository is required";
// malformed (OCI repo-name grammar) → "invalid repository name '<X>'".
// Валидные path-имена с `/` проходят.
func TestRepositoryName_RG1A05_ValidateGrammar(t *testing.T) {
	t.Parallel()
	valid := []string{"backend/api", "legacy/app", "svc/x", "img/app", "a", "a1", "team-core/svc.v2", "deep/nested/path"}
	for _, name := range valid {
		require.NoErrorf(t, domain.ValidateRepositoryName("repository", name), "expected %q valid", name)
	}

	t.Run("empty_is_required", func(t *testing.T) {
		err := domain.ValidateRepositoryName("repository", "")
		require.Error(t, err)
		require.Equal(t, "repository is required", err.Error())
	})

	malformed := []string{"Bad Name!", "UPPER/case", "trailing/", "/leading", "double//slash", "has space", "sym$bol"}
	for _, name := range malformed {
		t.Run("malformed_"+name, func(t *testing.T) {
			err := domain.ValidateRepositoryName("repository", name)
			require.Error(t, err)
			require.Equal(t, "invalid repository name '"+name+"'", err.Error(),
				"malformed-first exact text (api-conventions.md)")
		})
	}
}

// RG-1-A22 (name-length BVA) — 255-символьный путь проходит; 256 → invalid.
func TestRepositoryName_RG1A22_LengthBoundary(t *testing.T) {
	t.Parallel()
	atLimit := strings.Repeat("a", 255)
	require.NoError(t, domain.ValidateRepositoryName("repository", atLimit), "255-char at limit passes")
	over := strings.Repeat("a", 256)
	require.Error(t, domain.ValidateRepositoryName("repository", over), "256-char over limit rejected")
	require.Equal(t, "invalid repository name '"+over+"'", domain.ValidateRepositoryName("repository", over).Error())
}

// RG-1-D6 — Visibility round-trip domain↔DB-string; fail-safe: UNSPECIFIED/unknown → PRIVATE.
func TestVisibility_RG1D6_RoundTripFailSafe(t *testing.T) {
	t.Parallel()
	require.Equal(t, "PRIVATE", domain.VisibilityPrivate.String())
	require.Equal(t, "PUBLIC", domain.VisibilityPublic.String())
	// fail-safe: UNSPECIFIED и out-of-range НЕ протекают как PUBLIC.
	require.Equal(t, "PRIVATE", domain.VisibilityUnspecified.String())
	require.Equal(t, "PRIVATE", domain.Visibility(99).String())

	require.Equal(t, domain.VisibilityPublic, domain.VisibilityFromString("PUBLIC"))
	require.Equal(t, domain.VisibilityPrivate, domain.VisibilityFromString("PRIVATE"))
	// fail-safe parse: неизвестная строка → PRIVATE (не PUBLIC).
	require.Equal(t, domain.VisibilityPrivate, domain.VisibilityFromString("garbage"))
	require.Equal(t, domain.VisibilityPrivate, domain.VisibilityFromString(""))

	require.NoError(t, domain.VisibilityPrivate.Validate())
	require.NoError(t, domain.VisibilityPublic.Validate())
	require.Error(t, domain.VisibilityUnspecified.Validate(), "UNSPECIFIED not persist-valid")
	require.Error(t, domain.Visibility(99).Validate())
}

// RG-1 — RepositoryConfig.Validate: registry_id обязателен, name — валидное OCI-имя,
// visibility — конкретное PRIVATE|PUBLIC.
func TestRepositoryConfig_Validate(t *testing.T) {
	t.Parallel()
	ok := domain.RepositoryConfig{RegistryID: "reg1", Name: "backend/api", Visibility: domain.VisibilityPrivate}
	require.NoError(t, ok.Validate())

	noReg := domain.RepositoryConfig{Name: "backend/api", Visibility: domain.VisibilityPrivate}
	require.EqualError(t, noReg.Validate(), "registry_id is required")

	badName := domain.RepositoryConfig{RegistryID: "reg1", Name: "Bad Name!", Visibility: domain.VisibilityPrivate}
	require.EqualError(t, badName.Validate(), "invalid repository name 'Bad Name!'")

	badVis := domain.RepositoryConfig{RegistryID: "reg1", Name: "backend/api", Visibility: domain.VisibilityUnspecified}
	require.Error(t, badVis.Validate())
}
