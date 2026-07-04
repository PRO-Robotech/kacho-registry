// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package config — конфигурация kacho-registry, загружается из переменных
// окружения через corelib config.LoadPrefixed("KACHO_REGISTRY"). Поля с
// абсолютным тегом читаются как есть; вложенные per-edge TLS-структуры
// (grpcclient.TLSClient / grpcsrv.TLSServer) получают независимые имена
// KACHO_REGISTRY_<EDGE>_<NAME> — префикс на каждое ребро, без общего TLS-синглтона.
package config

import (
	"fmt"
	"os"

	"google.golang.org/grpc"

	corecfg "github.com/PRO-Robotech/kacho-corelib/config"
	"github.com/PRO-Robotech/kacho-corelib/grpcclient"
	"github.com/PRO-Robotech/kacho-corelib/grpcsrv"
)

// envPrefix — корневой сегмент env-имён kacho-registry (KACHO_<DOMAIN>).
const envPrefix = "KACHO_REGISTRY"

// Config — конфигурация kacho-registry.
type Config struct {
	DBHost     string `envconfig:"KACHO_REGISTRY_DB_HOST" default:"localhost"`
	DBPort     string `envconfig:"KACHO_REGISTRY_DB_PORT" default:"5432"`
	DBUser     string `envconfig:"KACHO_REGISTRY_DB_USER" default:"registry"`
	DBPassword string `envconfig:"KACHO_REGISTRY_DB_PASSWORD" required:"true"`
	DBName     string `envconfig:"KACHO_REGISTRY_DB_NAME" default:"kacho_registry"`
	// DBSSLMode — sslmode для DSN. dev по умолчанию `disable`; в проде обязателен
	// require|verify-ca|verify-full.
	DBSSLMode string `envconfig:"KACHO_REGISTRY_DB_SSLMODE" default:"disable"`
	// DBMaxConns — лимит pgx-пула (0 = дефолт pgx max(4, NumCPU)).
	DBMaxConns int `envconfig:"KACHO_REGISTRY_DB_MAX_CONNS" default:"0"`

	// GrpcPort — публичный control-plane листенер (RegistryService).
	GrpcPort string `envconfig:"KACHO_REGISTRY_GRPC_PORT" default:"9090"`
	// InternalGrpcPort — cluster-internal листенер (InternalRegistryService).
	// Не выставляется на внешнем endpoint api-gateway — только cluster-internal.
	InternalGrpcPort string `envconfig:"KACHO_REGISTRY_INTERNAL_PORT" default:"9091"`

	// AuthMode — fail-closed режим: dev | production | production-strict.
	AuthMode string `envconfig:"KACHO_REGISTRY_AUTH_MODE" default:"dev"`

	// AuthZIAMGRPCAddr — internal endpoint kacho-iam (:9091) для per-RPC Check
	// (ребро registry→iam authz) И для fga-proxy RegisterResource/UnregisterResource
	// (Internal-only). Пусто + Breakglass=false → интерсептор НЕ подключается.
	AuthZIAMGRPCAddr string `envconfig:"KACHO_REGISTRY_AUTHZ_IAM_GRPC_ADDR" default:""`

	// IAMProjectGRPCAddr — PUBLIC endpoint kacho-iam (:9090) для ProjectService.Get
	// (existence-валидация project на Create). ProjectService зарегистрирован ТОЛЬКО
	// на public :9090; на internal :9091 (AuthZIAMGRPCAddr) его НЕТ — вызов там
	// возвращает Unimplemented. Поэтому project-ребро держит СОБСТВЕННЫЙ conn на :9090,
	// отдельный от authz/register-ребра на :9091 (единый conn на :9091 давал
	// Unimplemented на Get → фикс. INTERNAL на Create ещё до insert'а).
	IAMProjectGRPCAddr string `envconfig:"KACHO_REGISTRY_IAM_PROJECT_GRPC_ADDR" default:"kacho-iam.kacho.svc.cluster.local:9090"`
	// AuthZBreakglass — аварийный режим: пропускать все RPC без Check + WARN
	// (только dev / break-glass).
	AuthZBreakglass bool `envconfig:"KACHO_REGISTRY_AUTHZ_BREAKGLASS" default:"false"`

	// ZotAddr — internal HTTP-endpoint zot-бэкенда (data/registry-API). zot
	// никогда не публично достижим; клиент ходит на cluster-internal endpoint.
	ZotAddr string `envconfig:"KACHO_REGISTRY_ZOT_ADDR" default:""`

	// ===== data-plane OCI auth-proxy (registry.kacho.local) =====

	// DataplaneAddr — адрес data-plane HTTP-листенера (Docker Registry v2 / OCI).
	// Отдельный порт от gRPC :9090/:9091. Пусто → data-plane не поднимается.
	DataplaneAddr string `envconfig:"KACHO_REGISTRY_DATAPLANE_ADDR" default:":8080"`
	// IAMJWKSURL — IAM JWKS-endpoint для верификации identity-JWT data-plane
	// (RS256). Пусто + не breakglass → data-plane fail-closed на старте.
	IAMJWKSURL string `envconfig:"KACHO_REGISTRY_IAM_JWKS_URL" default:""`
	// TokenRealm — realm для WWW-Authenticate (IAM /token auth-server); docker
	// сам идёт туда за Bearer-токеном.
	TokenRealm string `envconfig:"KACHO_REGISTRY_TOKEN_REALM" default:"https://api.kacho.local/iam/token"`
	// ServiceAud — expected audience identity-JWT (наш service) + значение service=
	// в WWW-Authenticate.
	ServiceAud string `envconfig:"KACHO_REGISTRY_SERVICE_AUD" default:"registry.kacho.local"`
	// TokenIssuer — expected issuer identity-JWT (пусто → iss не проверяется).
	TokenIssuer string `envconfig:"KACHO_REGISTRY_TOKEN_ISSUER" default:""`

	// EndpointBase — tenant-facing base OCI-endpoint namespace. Output-only поле
	// Registry.endpoint = "<EndpointBase>/<id>". Это tenant-facing ingress-host;
	// инфра-адрес zot наружу не раскрывается (security.md §инфра-данные).
	EndpointBase string `envconfig:"KACHO_REGISTRY_ENDPOINT_BASE" default:"registry.kacho.local"`

	// ===== per-edge mTLS =====

	// IAMAuthzMTLS — client-creds для ребра registry→iam internal (:9091): Check + fga-proxy.
	// ServerName = kacho-iam-internal.* (реальный dial-host :9091).
	IAMAuthzMTLS grpcclient.TLSClient `envconfig:"IAM_AUTHZ_MTLS"`

	// IAMProjectMTLS — client-creds для ребра registry→iam public (:9090): ProjectService.Get.
	// Отдельное поле от IAMAuthzMTLS, потому что ServerName public dial-host'а
	// (kacho-iam.*) ≠ internal (kacho-iam-internal.*): единый ServerName некорректен
	// для обоих листенеров под RequireAndVerifyClientCert.
	IAMProjectMTLS grpcclient.TLSClient `envconfig:"IAM_PROJECT_MTLS"`

	// PublicServerMTLS — server-creds для публичного листенера (:9090).
	PublicServerMTLS grpcsrv.TLSServer `envconfig:"PUBLIC_SERVER_MTLS"`

	// InternalServerMTLS — server-creds для cluster-internal листенера (:9091).
	InternalServerMTLS grpcsrv.TLSServer `envconfig:"INTERNAL_SERVER_MTLS"`
}

// PublicServerCreds возвращает grpc.ServerOption для публичного листенера (:9090).
func (c Config) PublicServerCreds() (grpc.ServerOption, error) {
	return grpcsrv.TLSServerCreds(c.PublicServerMTLS)
}

// InternalServerCreds возвращает grpc.ServerOption для internal-листенера (:9091).
func (c Config) InternalServerCreds() (grpc.ServerOption, error) {
	return grpcsrv.TLSServerCreds(c.InternalServerMTLS)
}

// schemaOptionsParam — URL-encoded libpq `options=-c search_path=kacho_registry,public`.
// Каждое соединение (pgxpool + goose database/sql) видит схему kacho_registry без
// отдельного SET search_path на каждый стейтмент.
const schemaOptionsParam = "options=-c%20search_path%3Dkacho_registry%2Cpublic"

// baseDSN — стандартный postgres DSN (годится и для pgxpool, и для database/sql),
// несёт search_path kacho_registry через libpq options.
func (c Config) baseDSN() string {
	mode := c.DBSSLMode
	if mode == "" {
		mode = "disable"
	}
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=%s&%s",
		c.DBUser, c.DBPassword, c.DBHost, c.DBPort, c.DBName, mode, schemaOptionsParam,
	)
}

// DSN — строка подключения для pgxpool (поддерживает pool_max_conns). НЕ для
// database/sql (pool_max_conns → неизвестный PG-параметр → FATAL).
func (c Config) DSN() string {
	dsn := c.baseDSN()
	if c.DBMaxConns > 0 {
		dsn += fmt.Sprintf("&pool_max_conns=%d", c.DBMaxConns)
	}
	return dsn
}

// MigrateDSN — строка подключения для goose/database/sql (без pgxpool-параметров).
func (c Config) MigrateDSN() string {
	return c.baseDSN()
}

// Load загружает конфигурацию из переменных окружения.
func Load() (Config, error) {
	var c Config
	err := corecfg.LoadPrefixed(envPrefix, &c)
	return c, err
}

// LoadInto — test-хелпер: выставляет переданные env-переменные на время вызова
// и грузит тем же путём LoadPrefixed, что и Load (по выходу восстанавливает env).
func LoadInto(c *Config, env map[string]string) error {
	saved := make(map[string]*string, len(env))
	for k, v := range env {
		if prev, ok := os.LookupEnv(k); ok {
			saved[k] = &prev
		} else {
			saved[k] = nil
		}
		_ = os.Setenv(k, v)
	}
	defer func() {
		for k, prev := range saved {
			if prev == nil {
				_ = os.Unsetenv(k)
			} else {
				_ = os.Setenv(k, *prev)
			}
		}
	}()
	return corecfg.LoadPrefixed(envPrefix, c)
}
