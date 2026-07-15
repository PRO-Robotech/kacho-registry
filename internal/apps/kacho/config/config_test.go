// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"net/url"
	"strings"
	"testing"
	"time"

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

// TestConfig_PushGrantTTL_DefaultBridge_60s фиксирует revoke-safe дефолт TTL push-ownership
// моста (registry_push_grant, REG-33 immediate-pull). Мост живёт ТОЛЬКО окно материализации
// per-repo authz (эмпирически ~10-15s); прежний дефолт 1h позволял отозванному (revoked)
// субъекту тянуть repo до 1h после revoke (v_get denies, но свежий push-grant раскрывает →
// stale-access leak). Дефолт = 60s: щедрый буфер над материализацией, но худший обход revoke
// ограничен ≤60s (а delete-on-materialized схлопывает его к ~0 на первом же allowed-pull).
func TestConfig_PushGrantTTL_DefaultBridge_60s(t *testing.T) {
	env := baseEnv()

	var c Config
	require.NoError(t, LoadInto(&c, env))

	assert.Equal(t, 60*time.Second, c.PushGrantTTL,
		"push-grant TTL default must be a short 60s bridge (bounds revoke-bypass), not 1h")
}

// TestConfig_PushGrantTTL_Override — TTL остаётся env-настраиваемым (KACHO_REGISTRY_PUSH_GRANT_TTL).
func TestConfig_PushGrantTTL_Override(t *testing.T) {
	env := baseEnv()
	env["KACHO_REGISTRY_PUSH_GRANT_TTL"] = "90s"

	var c Config
	require.NoError(t, LoadInto(&c, env))

	assert.Equal(t, 90*time.Second, c.PushGrantTTL,
		"push-grant TTL must stay env-configurable")
}

// TestConfig_IAMJWKS_Defaults (RJU-14) фиксирует контракт data-plane authN после
// unify: JWKS-источник верификации identity-JWT по умолчанию — cluster-internal
// iam JWKS-proxy (https :9097), а НЕ Hydra напрямую (data-plane больше не звонит в
// Hydra). Hydra issuer по-прежнему НЕ задан по умолчанию (iss проверяется только
// когда сконфигурен) — issuer-pin остаётся раздельным knob'ом от JWKS-URL. realm
// WWW-Authenticate остаётся token-шимом (docker идёт в шим, шим ходит в Hydra).
func TestConfig_IAMJWKS_Defaults(t *testing.T) {
	env := baseEnv()

	var c Config
	require.NoError(t, LoadInto(&c, env))

	assert.Equal(t,
		"https://kacho-iam-internal.kacho.svc.cluster.local:9097/.well-known/jwks.json",
		c.IAMJWKSURL,
		"data-plane JWKS source must default to the cluster-internal iam JWKS proxy (https), not Hydra")
	assert.Equal(t, "", c.HydraIssuer,
		"Hydra issuer unset by default (verified only when configured); issuer-pin decoupled from JWKS-URL")
	assert.Equal(t, "https://api.kacho.local/iam/token", c.TokenRealm,
		"WWW-Authenticate realm stays the token-shim")
	assert.Equal(t, "registry.kacho.local", c.ServiceAud)
}

// TestConfig_AnonymousSubject_DefaultDisabled (RG-1 D-7) — anonymous public pull is
// OFF by default (secure-by-default): KACHO_REGISTRY_ANONYMOUS_SUBJECT_ID unset ⇒
// empty ⇒ the data-plane resolves no token to the FGA wildcard user:* (anon disabled).
func TestConfig_AnonymousSubject_DefaultDisabled(t *testing.T) {
	var c Config
	require.NoError(t, LoadInto(&c, baseEnv()))

	assert.Equal(t, "", c.AnonymousSubjectID,
		"anonymous pull must be DISABLED by default (empty anon subject id, secure-by-default)")
}

// TestConfig_AnonymousSubject_Override (RG-1 D-7) — the anon principal id is
// env-configurable (KACHO_REGISTRY_ANONYMOUS_SUBJECT_ID) and MUST match kacho-iam's
// AnonymousClientID; the data-plane resolves a token with this sub to user:*.
func TestConfig_AnonymousSubject_Override(t *testing.T) {
	env := baseEnv()
	env["KACHO_REGISTRY_ANONYMOUS_SUBJECT_ID"] = "cid-registry-anon"

	var c Config
	require.NoError(t, LoadInto(&c, env))

	assert.Equal(t, "cid-registry-anon", c.AnonymousSubjectID,
		"anon principal id must be env-configurable (matches iam AnonymousClientID)")
}

// TestConfig_IAMJWKS_Override_OldEnvIgnored (RJU-14) — новый env
// KACHO_REGISTRY_IAM_JWKS_URL читается в IAMJWKSURL; старый
// KACHO_REGISTRY_HYDRA_JWKS_URL БОЛЬШЕ НЕ КОНСУЛЬТИРУЕТСЯ (снят с контракта):
// выставление старого имени не влияет на IAMJWKSURL. Hydra issuer по-прежнему
// пиннится своим собственным env (issuer-pin остаётся на Hydra, отдельный knob).
func TestConfig_IAMJWKS_Override_OldEnvIgnored(t *testing.T) {
	env := baseEnv()
	env["KACHO_REGISTRY_IAM_JWKS_URL"] = "https://kacho-iam-internal.example:9097/.well-known/jwks.json"
	// Старый env — умышленно выставлен на другое значение: он не должен ничего менять.
	env["KACHO_REGISTRY_HYDRA_JWKS_URL"] = "http://hydra.example:4444/.well-known/jwks.json"
	env["KACHO_REGISTRY_HYDRA_ISSUER"] = "https://hydra.api.kacho.cloud"

	var c Config
	require.NoError(t, LoadInto(&c, env))

	assert.Equal(t, "https://kacho-iam-internal.example:9097/.well-known/jwks.json", c.IAMJWKSURL,
		"IAMJWKSURL must come from KACHO_REGISTRY_IAM_JWKS_URL")
	assert.NotEqual(t, "http://hydra.example:4444/.well-known/jwks.json", c.IAMJWKSURL,
		"the old KACHO_REGISTRY_HYDRA_JWKS_URL must no longer be consulted")
	assert.Equal(t, "https://hydra.api.kacho.cloud", c.HydraIssuer,
		"issuer-pin stays on Hydra via its own KACHO_REGISTRY_HYDRA_ISSUER env")
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

// TestConfig_DSN_PasswordPercentEncoded — пароль с URL-значимыми символами
// (@ / : ? #) обязан percent-энкодиться в userinfo, иначе pgx/libpq-парсер
// раскусит DSN не так: 'postgres://registry:p@ss.host@dbhost/...' → host
// 'ss.host', выдернутый ИЗ секрета (CWE-116; коннект в чужой хост + leak
// фрагмента пароля в error-строке). Проверяем через тот же url-парсинг, что
// применяет pgx.
func TestConfig_DSN_PasswordPercentEncoded(t *testing.T) {
	const rawPassword = "p@ss/w:rd?x#y one"
	env := baseEnv()
	env["KACHO_REGISTRY_DB_PASSWORD"] = rawPassword
	env["KACHO_REGISTRY_DB_USER"] = "registry"
	env["KACHO_REGISTRY_DB_HOST"] = "dbhost.internal"
	env["KACHO_REGISTRY_DB_PORT"] = "6432"
	env["KACHO_REGISTRY_DB_NAME"] = "kacho_registry"

	var c Config
	require.NoError(t, LoadInto(&c, env))

	for _, dsn := range []string{c.DSN(), c.MigrateDSN()} {
		u, err := url.Parse(dsn)
		require.NoErrorf(t, err, "DSN must parse as a URL: %q", dsn)
		require.Equal(t, "postgres", u.Scheme)
		require.Equal(t, "registry", u.User.Username())
		gotPw, hasPw := u.User.Password()
		require.True(t, hasPw, "password present in userinfo")
		require.Equal(t, rawPassword, gotPw, "raw password must round-trip exactly")
		// host НЕ должен вытечь из пароля.
		require.Equal(t, "dbhost.internal", u.Hostname(), "host must not be parsed out of the secret")
		require.Equal(t, "6432", u.Port())
		require.Equal(t, "/kacho_registry", u.Path)
		require.Equal(t, "disable", u.Query().Get("sslmode"))
		require.Contains(t, u.Query().Get("options"), "search_path=kacho_registry,public",
			"search_path option preserved")
	}
}

// TestConfig_DSN_StatementTimeout — pool-DSN несёт server-side statement_timeout
// backstop (иначе runaway-запрос держит pooled-conn весь client-контролируемый
// срок → saturation; CWE-770). Значение конфигурируемо; "0" отключает.
func TestConfig_DSN_StatementTimeout(t *testing.T) {
	t.Run("default_present_on_pool_dsn", func(t *testing.T) {
		var c Config
		require.NoError(t, LoadInto(&c, baseEnv()))
		u, err := url.Parse(c.DSN())
		require.NoError(t, err)
		require.Contains(t, u.Query().Get("options"), "-c statement_timeout=30s",
			"pool DSN must carry a statement_timeout backstop by default")
	})
	t.Run("override", func(t *testing.T) {
		env := baseEnv()
		env["KACHO_REGISTRY_DB_STATEMENT_TIMEOUT"] = "45s"
		var c Config
		require.NoError(t, LoadInto(&c, env))
		require.Contains(t, u_options(t, c.DSN()), "-c statement_timeout=45s")
	})
	t.Run("zero_disables", func(t *testing.T) {
		env := baseEnv()
		env["KACHO_REGISTRY_DB_STATEMENT_TIMEOUT"] = "0"
		var c Config
		require.NoError(t, LoadInto(&c, env))
		require.NotContains(t, u_options(t, c.DSN()), "statement_timeout",
			"statement_timeout=0 disables the backstop")
	})
	t.Run("migrate_dsn_has_no_statement_timeout", func(t *testing.T) {
		var c Config
		require.NoError(t, LoadInto(&c, baseEnv()))
		require.NotContains(t, u_options(t, c.MigrateDSN()), "statement_timeout",
			"migrator DSN must not clamp long-running DDL")
	})
}

// u_options — helper: извлекает decoded libpq `options` из DSN.
func u_options(t *testing.T, dsn string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	require.NoError(t, err)
	return u.Query().Get("options")
}

// TestConfig_DSN_PoolMaxConns — pool_max_conns остаётся pgx-специфичным параметром
// pool-DSN и НЕ протекает в migrator-DSN (database/sql → FATAL на неизвестном
// параметре).
func TestConfig_DSN_PoolMaxConns(t *testing.T) {
	env := baseEnv()
	env["KACHO_REGISTRY_DB_MAX_CONNS"] = "12"
	var c Config
	require.NoError(t, LoadInto(&c, env))
	assert.Contains(t, c.DSN(), "pool_max_conns=12")
	assert.False(t, strings.Contains(c.MigrateDSN(), "pool_max_conns"),
		"pool_max_conns must not leak into the database/sql migrator DSN")
}
