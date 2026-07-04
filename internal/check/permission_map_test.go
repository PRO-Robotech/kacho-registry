// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package check

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPermissionMap_ScopeFiltered — List/ListRepositories/ListTags/DeleteTag
// авторизуются В ХЕНДЛЕРЕ (call-gate + row-filter + existence-hiding NOT_FOUND),
// поэтому per-RPC interceptor-Check для них ПРОПУСКАЕТСЯ (ScopeFiltered): единичный
// Check отдал бы PermissionDenied (а для List коллекции — «empty object id» вовсе,
// т.к. collection не несёт single object), а нужен row-filter и 200+empty/NOT_FOUND.
// REG-06/22/24/25.
func TestPermissionMap_ScopeFiltered(t *testing.T) {
	m := PermissionMap()
	for _, rpc := range []string{
		"/kacho.cloud.registry.v1.RegistryService/List",
		"/kacho.cloud.registry.v1.RegistryService/ListRepositories",
		"/kacho.cloud.registry.v1.RegistryService/ListTags",
		"/kacho.cloud.registry.v1.RegistryService/DeleteTag",
	} {
		e, ok := m[rpc]
		require.True(t, ok, "%s must be mapped (fail-closed)", rpc)
		require.True(t, e.ScopeFiltered, "%s must be ScopeFiltered (handler authorises)", rpc)
	}
}

// TestPermissionMap_List_CatalogRetained — List остаётся ScopeFiltered, но несёт
// v_list Relation как permission-catalog документацию (энфорс — row-filter в
// хендлере по registry_registry v_list, non-member → 200+empty). REG-06.
func TestPermissionMap_List_CatalogRetained(t *testing.T) {
	m := PermissionMap()
	e, ok := m["/kacho.cloud.registry.v1.RegistryService/List"]
	require.True(t, ok, "List must be mapped")
	require.True(t, e.ScopeFiltered, "List must be ScopeFiltered (handler row-filter, not per-object Check)")
	require.Equal(t, relVList, e.Relation, "List keeps v_list as permission-catalog doc")
}

// TestPermissionMap_CRUD_InterceptorGated — стандартный CRUD registry-namespace
// (кроме List — она ScopeFiltered) остаётся под per-RPC interceptor-Check (НЕ
// ScopeFiltered) — тир-based gate на single object registry_registry:<id>.
func TestPermissionMap_CRUD_InterceptorGated(t *testing.T) {
	m := PermissionMap()
	for _, rpc := range []string{
		"/kacho.cloud.registry.v1.RegistryService/Get",
		"/kacho.cloud.registry.v1.RegistryService/Create",
		"/kacho.cloud.registry.v1.RegistryService/Update",
		"/kacho.cloud.registry.v1.RegistryService/Delete",
	} {
		e, ok := m[rpc]
		require.True(t, ok, "%s must be mapped", rpc)
		require.False(t, e.ScopeFiltered, "%s must be interceptor-gated", rpc)
		require.NotEmpty(t, e.Relation)
	}
}

// TestPermissionMap_Internal — InternalRegistryService (:9091) под per-RPC Check
// (internal НЕ освобождён, security.md): Stats read-tier (v_get), GC mutation-tier
// (v_delete). REG-38.
func TestPermissionMap_Internal(t *testing.T) {
	m := PermissionMap()

	stats, ok := m["/kacho.cloud.registry.v1.InternalRegistryService/GetRegistryStats"]
	require.True(t, ok)
	require.False(t, stats.ScopeFiltered, "internal Stats interceptor-gated")
	require.Equal(t, relVGet, stats.Relation, "Stats viewer-gated (v_get)")

	gc, ok := m["/kacho.cloud.registry.v1.InternalRegistryService/TriggerGarbageCollection"]
	require.True(t, ok)
	require.Equal(t, relVDelete, gc.Relation, "GC mutation-tier (v_delete)")
}
