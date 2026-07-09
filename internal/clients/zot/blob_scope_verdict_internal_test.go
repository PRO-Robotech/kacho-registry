// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// blob_scope_verdict_internal_test.go — итоговый вердикт per-repo blob-scope скана
// (blobScopeVerdict). Регрессия REG-37: НЕПОЛНЫЙ скан (parent-ctx отменён до просмотра
// всех тегов, но ни один уже-запущенный fetch не вернул ошибки → g.Wait()==nil) обязан
// быть fail-closed ErrUnavailable и НЕ кэшироваться — иначе TTL-кэш отравляется ложным
// not-in-repo, и легитимный pull присутствующего слоя ловит 404 на всё TTL-окно.
// Internal-тест (package zot) — ссылается на unexported blobScopeVerdict.
package zot

import (
	"errors"
	"testing"

	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

func TestBlobScopeVerdict(t *testing.T) {
	sibErr := regerrors.ErrUnavailable
	cases := []struct {
		name          string
		found         bool
		werr          error
		scannedAll    bool
		wantIn        bool
		wantErr       error
		wantCacheable bool
	}{
		{
			// Найден — ответ известен из ЧАСТИЧНОГО скана, единственный вердикт, безопасный
			// для кэша, даже если сосед блипнул.
			name: "found is authoritative and cacheable", found: true, werr: sibErr, scannedAll: false,
			wantIn: true, wantErr: nil, wantCacheable: true,
		},
		{
			// Сосед блипнул (werr!=nil), ответ неизвестен → fail-closed, НЕ кэшируем.
			name: "sibling error fails closed, not cached", found: false, werr: sibErr, scannedAll: false,
			wantIn: false, wantErr: sibErr, wantCacheable: false,
		},
		{
			// РЕГРЕССИЯ REG-37: скан НЕПОЛНЫЙ (ctx отменён, но werr==nil), блоб не найден —
			// ответ НЕ известен. Обязан fail-closed ErrUnavailable и НЕ кэшировать ложный
			// not-in-repo. До фикса возвращал (false,nil,cacheable) → отравление кэша.
			name: "incomplete scan fails closed, not cached", found: false, werr: nil, scannedAll: false,
			wantIn: false, wantErr: regerrors.ErrUnavailable, wantCacheable: false,
		},
		{
			// Полный скан без совпадения — достоверный not-in-repo, кэшируемо.
			name: "complete negative scan is cacheable", found: false, werr: nil, scannedAll: true,
			wantIn: false, wantErr: nil, wantCacheable: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in, err, cacheable := blobScopeVerdict(tc.found, tc.werr, tc.scannedAll)
			if in != tc.wantIn {
				t.Fatalf("in = %v, want %v", in, tc.wantIn)
			}
			if cacheable != tc.wantCacheable {
				t.Fatalf("cacheable = %v, want %v", cacheable, tc.wantCacheable)
			}
			if tc.wantErr == nil && err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}
