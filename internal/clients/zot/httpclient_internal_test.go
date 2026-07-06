// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package zot

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// TestDecodeManifest_LimitReader — тело манифеста декодируется под io.LimitReader
// (defense-in-depth, CWE-770): манифест в пределах лимита разбирается штатно, а
// одиночное JSON-значение сверх лимита усекается LimitReader'ом → decode рвётся →
// fail-closed ErrUnavailable (скомпрометированный/битый zot не OOM'ит декодер
// безразмерным телом; сырой zot-текст наружу не течёт).
func TestDecodeManifest_LimitReader(t *testing.T) {
	// В пределах лимита — разбирается штатно (config.size/digest проецируются).
	mb, err := decodeManifest(strings.NewReader(`{"config":{"digest":"sha256:x","size":7}}`), 1<<20)
	require.NoError(t, err)
	require.Equal(t, int64(7), mb.Config.Size)
	require.Equal(t, "sha256:x", mb.Config.Digest)

	// Одиночное JSON-значение (гигантский digest-string) сверх лимита → LimitReader
	// усекает → json.Decode падает (unexpected EOF) → failClosed ErrUnavailable.
	oversized := `{"config":{"digest":"` + strings.Repeat("a", 500) + `"}}`
	_, err = decodeManifest(strings.NewReader(oversized), 50)
	require.ErrorIs(t, err, regerrors.ErrUnavailable)
}
