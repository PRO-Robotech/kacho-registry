// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package zot

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// TestDecodeGraphQL_LimitReader — envelope search-ext GraphQL (ImageList/GlobalSearch)
// декодируется под io.LimitReader (defense-in-depth, CWE-770): ответ в пределах лимита
// разбирается штатно, а тело сверх лимита усекается LimitReader'ом → decode рвётся →
// fail-closed ErrUnavailable. Иначе tenant-controlled tag/repo-count материализуется в
// память целиком на каждый ListTags/ListRepositories (zot ImageList не поддерживает
// server-side tag-пагинацию); паритет с decodeManifest / maxManifestBytes. Сырой
// zot-текст наружу не течёт.
func TestDecodeGraphQL_LimitReader(t *testing.T) {
	// В пределах лимита — разбирается штатно.
	var out gqlImageListData
	require.NoError(t, decodeGraphQL(
		strings.NewReader(`{"data":{"ImageList":{"Results":[{"Tag":"v1"}]}}}`), 1<<20, &out))
	require.Len(t, out.ImageList.Results, 1)
	require.Equal(t, "v1", out.ImageList.Results[0].Tag)

	// Тело сверх лимита → LimitReader усекает → decode падает → failClosed ErrUnavailable.
	oversized := `{"data":{"ImageList":{"Results":[{"Tag":"` + strings.Repeat("a", 500) + `"}]}}}`
	var out2 gqlImageListData
	err := decodeGraphQL(strings.NewReader(oversized), 50, &out2)
	require.ErrorIs(t, err, regerrors.ErrUnavailable)
}

// TestDecodeGraphQL_ErrorsAndUnmarshal — errors-массив в envelope и оборачивание data
// сохраняют прежнюю семантику после экстракта из gqlQuery: непустой errors → fail-closed
// (наружу только sentinel), валидный data → unmarshal в out.
func TestDecodeGraphQL_ErrorsAndUnmarshal(t *testing.T) {
	var out gqlImageListData
	err := decodeGraphQL(
		strings.NewReader(`{"errors":[{"message":"cannot query field ImageList"}]}`), 1<<20, &out)
	require.ErrorIs(t, err, regerrors.ErrUnavailable)
}
