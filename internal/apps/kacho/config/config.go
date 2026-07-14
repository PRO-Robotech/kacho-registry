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
	"net"
	"net/url"
	"time"

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
	// DBStatementTimeout — server-side statement_timeout для pool-соединений (libpq
	// value: "30s" / "30000"). Backstop против runaway-запроса, держащего pooled-conn
	// весь client-контролируемый срок (CWE-770; pool-saturation soft-DoS). "0"/"" —
	// backstop отключён. Ставится ТОЛЬКО на pool-DSN, не на migrator-DSN (DDL не
	// клампится). Все read-пути keyset-пагинированы и индексированы, поэтому 30s с
	// запасом.
	DBStatementTimeout string `envconfig:"KACHO_REGISTRY_DB_STATEMENT_TIMEOUT" default:"30s"`

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

	// AuthZCacheTTL — TTL positive-кеша authz-Check gRPC-интерсептора (ОБА
	// листенера). Ограничивает окно, в течение которого отозванный (revoked)
	// субъект держит закешированный allow ПОСЛЕ удаления AccessBinding: registry НЕ
	// подписан на IAM cache-invalidation (InternalAuthzCacheService.InvalidateSubject
	// бьёт только api-gateway) и db-per-service ⇒ LISTEN/NOTIFY от iam сюда не доходит →
	// revoke-окно = этот TTL + async fga-drain. Короткий дефолт (2s) держит окно
	// узким; 0 → positive-кеш выключен (каждый gRPC-RPC — живой IAM Check,
	// немедленный revoke). data-plane /v2/ (OCI-proxy) authz НЕ кеширует (прямой
	// per-request Check), поэтому этот knob влияет только на control-plane gRPC. См. #33.
	AuthZCacheTTL time.Duration `envconfig:"KACHO_REGISTRY_AUTHZ_CACHE_TTL" default:"2s"`

	// ZotAddr — internal HTTP-endpoint zot-бэкенда (data/registry-API). zot
	// никогда не публично достижим; клиент ходит на cluster-internal endpoint.
	ZotAddr string `envconfig:"KACHO_REGISTRY_ZOT_ADDR" default:""`

	// PendingBlobTTL — freshness-окно durable per-repo учёта загруженных блобов
	// (registry_pending_blob, REG-33 Defect A). На blob PUT-finalize пишется строка
	// (registry_id, repo, digest); push-time blob HEAD/GET раскрывает блоб, если он
	// загружен в ЭТОТ repo не старше этого TTL (до появления в манифесте — там
	// BlobInRepo уже true). Достаточно пережить одно push-окно (обычно секунды-минуты);
	// дефолт 1h щедр даже для больших образов по медленному каналу. Строки старше TTL
	// подметает sweeper (интервал = TTL). 0 → трекинг фактически выключен (не задавать
	// в проде — REG-33 не закрыт).
	PendingBlobTTL time.Duration `envconfig:"KACHO_REGISTRY_PENDING_BLOB_TTL" default:"1h"`

	// ===== data-plane OCI auth-proxy (registry.kacho.local) =====

	// DataplaneAddr — адрес data-plane HTTP-листенера (Docker Registry v2 / OCI).
	// Отдельный порт от gRPC :9090/:9091. Пусто → data-plane не поднимается.
	DataplaneAddr string `envconfig:"KACHO_REGISTRY_DATAPLANE_ADDR" default:":8080"`
	// HydraJWKSURL — Hydra-public JWKS-endpoint для верификации identity-JWT
	// data-plane. Токен теперь Hydra-issued (client_credentials для docker,
	// jwt-bearer для k8s); подпись — RS256 (Ory default) либо ES256. Пусто + не
	// breakglass → data-plane fail-closed на старте.
	HydraJWKSURL string `envconfig:"KACHO_REGISTRY_HYDRA_JWKS_URL" default:"http://kacho-umbrella-hydra-public.kacho.svc:4444/.well-known/jwks.json"`
	// TokenRealm — realm для WWW-Authenticate; docker сам идёт туда за Bearer-токеном.
	// Остаётся token-шимом (kacho-iam /iam/token): docker предъявляет SA-key шиму,
	// шим брокерит токен у Hydra. Для data-plane realm — непрозрачный указатель на
	// auth-сервер клиента, поэтому Hydra-переключение его не меняет.
	TokenRealm string `envconfig:"KACHO_REGISTRY_TOKEN_REALM" default:"https://api.kacho.local/iam/token"`
	// ServiceAud — expected audience identity-JWT (наш service) + значение service=
	// в WWW-Authenticate. Токен обязан нести aud ⊇ ServiceAud (federation-out на
	// другие RP registry-доступа не даёт).
	ServiceAud string `envconfig:"KACHO_REGISTRY_SERVICE_AUD" default:"registry.kacho.local"`
	// DataplaneTLSTerminatedExternally — оператор подтверждает, что data-plane
	// OCI-листенер (открытый HTTP, DataplaneAddr) стоит за внешней TLS-терминацией
	// (ingress/mesh). В production/production-strict обязателен true — иначе
	// buildDataplaneHandler (requireDataplaneTLSAck) отклоняет старт: bearer
	// identity-JWT (реплеябельные в пределах TTL) не должны транзитить открытым текстом
	// (CWE-319). Параллель requireSecureJWKSURL/requireIssuerPinned. В dev игнорируется.
	DataplaneTLSTerminatedExternally bool `envconfig:"KACHO_REGISTRY_DATAPLANE_TLS_TERMINATED_EXTERNALLY" default:"false"`

	// HydraIssuer — expected issuer identity-JWT (external Hydra issuer, напр.
	// https://hydra.api.kacho.cloud). Пусто → iss не проверяется (dev-only). В
	// production/production-strict issuer-pinning ОБЯЗАТЕЛЕН — buildDataplaneHandler
	// (requireIssuerPinned) отклоняет старт при пустом значении, иначе data-plane принял
	// бы токен любого RP, разделяющего JWKS+aud (federation-out).
	HydraIssuer string `envconfig:"KACHO_REGISTRY_HYDRA_ISSUER" default:""`

	// EndpointBase — tenant-facing base OCI-endpoint namespace. Output-only поле
	// Registry.endpoint = "<EndpointBase>/<id>". Это tenant-facing ingress-host;
	// инфра-адрес zot наружу не раскрывается (infra-sensitive, не на публичной поверхности).
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

// searchPathOption — libpq `-c` startup-опция: каждое соединение видит схему
// kacho_registry без отдельного SET search_path на каждый стейтмент.
const searchPathOption = "-c search_path=kacho_registry,public"

// baseDSN — стандартный postgres DSN (годится и для pgxpool, и для database/sql).
// userinfo/host собираются через net/url (url.UserPassword + net.JoinHostPort) —
// пароль/пользователь percent-энкодятся, поэтому URL-значимые символы (@ / : ? #)
// в секрете не «раскусывают» DSN (CWE-116). extraOptions добавляются к libpq
// `options` (несколько `-c`-флагов в одной опции — второй `options=` перезаписал бы
// первый).
func (c Config) baseDSN(extraOptions ...string) string {
	mode := c.DBSSLMode
	if mode == "" {
		mode = "disable"
	}
	options := searchPathOption
	for _, o := range extraOptions {
		if o != "" {
			options += " " + o
		}
	}
	q := url.Values{}
	q.Set("sslmode", mode)
	q.Set("options", options)
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(c.DBUser, c.DBPassword),
		Host:     net.JoinHostPort(c.DBHost, c.DBPort),
		Path:     "/" + c.DBName,
		RawQuery: q.Encode(),
	}
	return u.String()
}

// DSN — строка подключения для pgxpool (поддерживает pool_max_conns +
// statement_timeout backstop). НЕ для database/sql (pool_max_conns → неизвестный
// PG-параметр → FATAL).
func (c Config) DSN() string {
	var extra []string
	if c.DBStatementTimeout != "" && c.DBStatementTimeout != "0" {
		// Каждый GUC в libpq `options` — отдельный `-c key=value` флаг.
		extra = append(extra, "-c statement_timeout="+c.DBStatementTimeout)
	}
	dsn := c.baseDSN(extra...)
	if c.DBMaxConns > 0 {
		dsn += fmt.Sprintf("&pool_max_conns=%d", c.DBMaxConns)
	}
	return dsn
}

// MigrateDSN — строка подключения для goose/database/sql (без pgxpool-параметров и
// без statement_timeout — долгий DDL не клампится).
func (c Config) MigrateDSN() string {
	return c.baseDSN()
}

// Load загружает конфигурацию из переменных окружения.
func Load() (Config, error) {
	var c Config
	err := corecfg.LoadPrefixed(envPrefix, &c)
	return c, err
}
