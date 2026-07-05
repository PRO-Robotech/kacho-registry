// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package namepage_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/shared/namepage"
	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

func id(s string) string { return s }

// Window режет страницу, отдаёт курсор последнего имени, продолжает без пропусков и
// без дублей; хвост → next="".
func TestWindow_PaginatesMonotonically(t *testing.T) {
	items := []string{"a", "b", "c", "d", "e"}

	p1, n1, err := namepage.Window(items, id, 2, "")
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b"}, p1)
	require.NotEmpty(t, n1)

	p2, n2, err := namepage.Window(items, id, 2, n1)
	require.NoError(t, err)
	require.Equal(t, []string{"c", "d"}, p2)
	require.NotEmpty(t, n2)

	p3, n3, err := namepage.Window(items, id, 2, n2)
	require.NoError(t, err)
	require.Equal(t, []string{"e"}, p3)
	require.Empty(t, n3, "хвост → next пуст")
}

// page_size==0 → default; курсор за концом → пусто.
func TestWindow_DefaultSizeAndPastEnd(t *testing.T) {
	items := []string{"a", "b"}
	p, next, err := namepage.Window(items, id, 0, "")
	require.NoError(t, err)
	require.Equal(t, items, p)
	require.Empty(t, next)

	past, next2, err := namepage.Window(items, id, 2, namepage.Encode("z"))
	require.NoError(t, err)
	require.Empty(t, past)
	require.Empty(t, next2)
}

// Мусорный page_token → ErrInvalidArg-sentinel (маппинг в gRPC — на границе serviceerr).
func TestWindow_GarbageToken_SentinelInvalidArg(t *testing.T) {
	_, _, err := namepage.Window([]string{"a"}, id, 2, "!!!not-base64!!!")
	require.ErrorIs(t, err, regerrors.ErrInvalidArg)
}

// page_size вне [0..1000] → ошибка (corevalidate.PageSize).
func TestWindow_PageSizeOutOfRange(t *testing.T) {
	_, _, err := namepage.Window([]string{"a"}, id, 5000, "")
	require.Error(t, err)
}
