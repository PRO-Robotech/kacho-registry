// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// baseEnv — минимальный набор env для успешного LoadInto (DB_PASSWORD required:true).
func baseEnv() map[string]string {
	return map[string]string{
		"KACHO_REGISTRY_DB_PASSWORD": "s3cr3t",
	}
}

// TestConfig_IAMProjectEdge_DefaultAndDistinctFromAuthz фиксирует раздельность двух
// registry→iam рёбер: ProjectService.Get идёт на iam PUBLIC :9090
// (IAMProjectGRPCAddr), а Check/RegisterResource — на iam INTERNAL :9091
// (AuthZIAMGRPCAddr). Единый conn на :9091 давал Unimplemented на ProjectService.Get
// → фикс. INTERNAL на Create; два раздельных addr'а это исключают.
func TestConfig_IAMProjectEdge_DefaultAndDistinctFromAuthz(t *testing.T) {
	env := baseEnv()
	// AuthZ edge (internal :9091) как в helm-профиле.
	env["KACHO_REGISTRY_AUTHZ_IAM_GRPC_ADDR"] = "kacho-iam-internal.kacho.svc.cluster.local:9091"

	var c Config
	require.NoError(t, LoadInto(&c, env))

	// Дефолт project-ребра — iam public :9090.
	assert.Equal(t, "kacho-iam.kacho.svc.cluster.local:9090", c.IAMProjectGRPCAddr,
		"ProjectService.Get edge must default to iam PUBLIC :9090")
	// Два ребра обязаны быть разными endpoint'ами (public :9090 ≠ internal :9091).
	assert.NotEqual(t, c.AuthZIAMGRPCAddr, c.IAMProjectGRPCAddr,
		"project (public :9090) and authz (internal :9091) edges must be distinct conns")
}

// TestConfig_IAMProjectEdge_Override — env-override addr + отдельные mTLS-creds ребра.
func TestConfig_IAMProjectEdge_Override(t *testing.T) {
	env := baseEnv()
	env["KACHO_REGISTRY_IAM_PROJECT_GRPC_ADDR"] = "iam.example.local:9090"
	env["KACHO_REGISTRY_IAM_PROJECT_MTLS_ENABLE"] = "true"
	env["KACHO_REGISTRY_IAM_PROJECT_MTLS_SERVERNAME"] = "kacho-iam.kacho.svc.cluster.local"

	var c Config
	require.NoError(t, LoadInto(&c, env))

	assert.Equal(t, "iam.example.local:9090", c.IAMProjectGRPCAddr)
	assert.True(t, c.IAMProjectMTLS.Enable, "IAM_PROJECT_MTLS_ENABLE must bind to the project edge creds")
	assert.Equal(t, "kacho-iam.kacho.svc.cluster.local", c.IAMProjectMTLS.ServerName,
		"project edge ServerName = iam PUBLIC SAN (distinct from authz edge internal SAN)")
}
