// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package dataplane

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

// catalog_pagination_test.go — TEST-ONLY (ban #13): BVA/equivalence unit-тесты чистых
// catalog-pagination хелперов (parseCatalogPageSize / catalogWindow / decode-encode
// cursor). Локают клампинг page-size к [1..max] (CWE-770 bound Check-count), опаковость
// offset-курсора и fail-safe разбор битого/вне-диапазона курсора (без leak/паники).
// Прод-код не трогается.

// TestCatalog_parseCatalogPageSize_ClampsToBounds — BVA на `n=`: пусто/битое/≤0/>max →
// потолок catalogMaxPageSize; валидное в [1..max] → как есть. Кламп не даёт клиенту снять
// границу числа per-repo authz-Check (self-amplifying DoS).
func TestCatalog_parseCatalogPageSize_ClampsToBounds(t *testing.T) {
	cases := []struct {
		name, in string
		want     int
	}{
		{"empty → max", "", catalogMaxPageSize},
		{"one", "1", 1},
		{"mid", "2", 2},
		{"max exact", "1000", catalogMaxPageSize},
		{"over max → max", "1001", catalogMaxPageSize},
		{"far over → max", "1000000", catalogMaxPageSize},
		{"zero → max", "0", catalogMaxPageSize},
		{"negative → max", "-5", catalogMaxPageSize},
		{"garbage → max", "abc", catalogMaxPageSize},
		{"float garbage → max", "1.5", catalogMaxPageSize},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseCatalogPageSize(c.in)
			require.Equal(t, c.want, got)
			require.GreaterOrEqual(t, got, 1, "результат всегда ≥1")
			require.LessOrEqual(t, got, catalogMaxPageSize, "результат всегда ≤ потолка")
		})
	}
}

// TestCatalog_catalogWindow_Slicing — окно из отсортированных имён по offset-курсору:
// первая страница, средняя (nextOffset), и хвост (more=false).
func TestCatalog_catalogWindow_Slicing(t *testing.T) {
	names := []string{"a", "b", "c", "d", "e"}

	win, next, more := catalogWindow(names, "", 2)
	require.Equal(t, []string{"a", "b"}, win, "первая страница = первые n")
	require.Equal(t, 2, next, "nextOffset = позиция после окна")
	require.True(t, more, "за окном есть ещё имена")

	win, next, more = catalogWindow(names, encodeCatalogCursor(2), 2)
	require.Equal(t, []string{"c", "d"}, win, "следующая страница продолжает с offset")
	require.Equal(t, 4, next)
	require.True(t, more)

	win, _, more = catalogWindow(names, encodeCatalogCursor(4), 2)
	require.Equal(t, []string{"e"}, win, "хвост короче pageSize")
	require.False(t, more, "хвост каталога → more=false")
}

// TestCatalog_catalogWindow_CursorClampsFailSafe — вне-диапазона offset-курсор
// клампится в [0..len] (fail-safe рестарт, без паники/leak): отрицательный → с начала,
// сверх длины → пустое окно, more=false.
func TestCatalog_catalogWindow_CursorClampsFailSafe(t *testing.T) {
	names := []string{"a", "b", "c"}

	// отрицательный offset → clamp к 0 (start<0 ветка).
	win, _, more := catalogWindow(names, encodeCatalogCursor(-1), 2)
	require.Equal(t, []string{"a", "b"}, win, "отрицательный курсор → рестарт с начала")
	require.True(t, more)

	// offset за длиной → clamp к len → пустое окно (start>len ветка).
	win, next, more := catalogWindow(names, encodeCatalogCursor(999), 2)
	require.Empty(t, win, "offset сверх длины → пустое окно")
	require.Equal(t, len(names), next, "nextOffset клампится к len")
	require.False(t, more, "за концом каталога больше нет страниц")
}

// TestCatalog_decodeCursor_FailSafe — разбор опакового offset-курсора: валидный
// round-trip; пусто/битый-base64/не-число → 0 (безопасный рестарт с начала, без паники).
func TestCatalog_decodeCursor_FailSafe(t *testing.T) {
	// round-trip нескольких значений (encode→decode идемпотентен).
	for _, n := range []int{0, 1, 7, 42, 1000} {
		require.Equal(t, n, decodeCatalogCursor(encodeCatalogCursor(n)), "encode/decode round-trip offset=%d", n)
	}

	require.Equal(t, 0, decodeCatalogCursor(""), "пустой курсор → 0")
	require.Equal(t, 0, decodeCatalogCursor("!!!not-base64!!!"), "битый base64 → 0 (fail-safe)")
	// валидный base64, но декодированное содержимое — не число → 0.
	nonNumeric := base64.RawURLEncoding.EncodeToString([]byte("not-a-number"))
	require.Equal(t, 0, decodeCatalogCursor(nonNumeric), "base64 не-числа → 0 (fail-safe)")
}

// TestCatalog_encodeCursor_IsOpaqueOffset — курсор кодирует ТОЛЬКО позицию (offset),
// не несёт сырых имён репо (existence-oracle guard): для двух разных каталогов с одним
// offset курсор идентичен, и в нём нет ни одного repo-имени.
func TestCatalog_encodeCursor_IsOpaqueOffset(t *testing.T) {
	c := encodeCatalogCursor(2)
	require.NotContains(t, c, "reg-", "курсор не эхает registry-префикс")
	require.NotContains(t, c, "/", "курсор не несёт repo-путь")
	require.Equal(t, c, encodeCatalogCursor(2), "один offset → один курсор (зависит только от позиции)")
	require.NotEqual(t, encodeCatalogCursor(2), encodeCatalogCursor(3), "разные offset → разные курсоры")
}
