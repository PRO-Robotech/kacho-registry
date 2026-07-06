// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"

	coredb "github.com/PRO-Robotech/kacho-corelib/db"
	"github.com/PRO-Robotech/kacho-corelib/grpcclient"
	"github.com/PRO-Robotech/kacho-corelib/grpcsrv"
	"github.com/PRO-Robotech/kacho-corelib/observability"
	"github.com/PRO-Robotech/kacho-corelib/operations"
	"github.com/PRO-Robotech/kacho-corelib/outbox/drainer"
	operationpb "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/operation"

	registryv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/registry/v1"

	registry "github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/api/registry"
	"github.com/PRO-Robotech/kacho-registry/internal/apps/kacho/config"
	"github.com/PRO-Robotech/kacho-registry/internal/check"
	iamclient "github.com/PRO-Robotech/kacho-registry/internal/clients/iam"
	"github.com/PRO-Robotech/kacho-registry/internal/clients/jwks"
	zotclient "github.com/PRO-Robotech/kacho-registry/internal/clients/zot"
	"github.com/PRO-Robotech/kacho-registry/internal/dataplane"
	"github.com/PRO-Robotech/kacho-registry/internal/domain"
	"github.com/PRO-Robotech/kacho-registry/internal/handler"
	"github.com/PRO-Robotech/kacho-registry/internal/repo/kacho/pg"
)

// runServe — composition root: единственное место wiring, без глобальных синглтонов.
func runServe(cfg config.Config) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	logger := observability.NewSlogger(os.Stdout)
	slog.SetDefault(logger)

	if err := validateAuthMode(cfg, logger); err != nil {
		return err
	}
	// Secure-by-default: per-RPC authz Check и mTLS на ОБОИХ листенерах
	// обязательны. Единственный способ запустить без авторизации и mTLS —
	// аварийный KACHO_REGISTRY_AUTHZ_BREAKGLASS=true.
	if err := validateSecurityConfig(cfg); err != nil {
		return err
	}

	pool, err := coredb.NewPool(ctx, cfg.DSN())
	if err != nil {
		return err
	}
	defer pool.Close()

	// ── LRO-стек: общая operations-таблица (corelib) каталога kacho_registry.
	opsRepo := operations.NewRepo(pool, "kacho_registry")

	// ── ребро registry→iam INTERNAL (:9091, mTLS): per-RPC authz Check +
	// fga-proxy RegisterResource/UnregisterResource (Internal-only). При breakglass
	// conn может быть nil (интерсептор пропускает всё; клиенты отвечают Unavailable).
	var authzConn *grpc.ClientConn
	if cfg.AuthZIAMGRPCAddr != "" {
		authzCreds, cerr := grpcclient.TLSClientTransportCreds(cfg.IAMAuthzMTLS)
		if cerr != nil {
			return fmt.Errorf("registry→iam authz mTLS creds: %w", cerr)
		}
		authzConn, err = grpc.NewClient(cfg.AuthZIAMGRPCAddr,
			grpc.WithTransportCredentials(authzCreds),
			grpcclient.KeepaliveDialOption(true))
		if err != nil {
			return fmt.Errorf("dial kacho-iam internal: %w", err)
		}
		defer func() { _ = authzConn.Close() }()
	}

	// ── ребро registry→iam PUBLIC (:9090, mTLS): ProjectService.Get (existence-
	// валидация project на Create). ОТДЕЛЬНЫЙ conn — ProjectService зарегистрирован
	// только на public :9090; вызов на :9091 (authzConn) вернул бы Unimplemented →
	// фикс. INTERNAL на Create. ServerName public dial-host'а (kacho-iam.*) ≠ internal,
	// поэтому раздельные mTLS-creds (IAMProjectMTLS vs IAMAuthzMTLS) обязательны.
	var projectConn *grpc.ClientConn
	if cfg.IAMProjectGRPCAddr != "" {
		projectCreds, cerr := grpcclient.TLSClientTransportCreds(cfg.IAMProjectMTLS)
		if cerr != nil {
			return fmt.Errorf("registry→iam project mTLS creds: %w", cerr)
		}
		projectConn, err = grpc.NewClient(cfg.IAMProjectGRPCAddr,
			grpc.WithTransportCredentials(projectCreds),
			grpcclient.KeepaliveDialOption(true))
		if err != nil {
			return fmt.Errorf("dial kacho-iam project: %w", err)
		}
		defer func() { _ = projectConn.Close() }()
	}
	logger.Info("registry→iam edges wired",
		"authz_addr", cfg.AuthZIAMGRPCAddr, "authz_mtls", cfg.IAMAuthzMTLS.Enable,
		"project_addr", cfg.IAMProjectGRPCAddr, "project_mtls", cfg.IAMProjectMTLS.Enable)

	// ── adapters (порты use-case): pgx-repo, zot data/registry-API, iam-клиент ──
	// iamConn — internal :9091 (Check-интерсептор + fga-proxy register-drainer).
	// projectIAMConn — public :9090 (ProjectService.Get). Их conn'ы РАЗДЕЛЬНЫ.
	var iamConn grpc.ClientConnInterface
	if authzConn != nil {
		iamConn = authzConn
	}
	var projectIAMConn grpc.ClientConnInterface
	if projectConn != nil {
		projectIAMConn = projectConn
	}
	registryRepo := pg.NewRegistryRepo(pool)
	zotAdapter := zotclient.New(cfg.ZotAddr)
	iamAdapter := iamclient.New(projectIAMConn)

	// ── use-case (CQRS repo + zot + iam + repo-registrar + LRO) ──
	registryUC := registry.New(registryRepo, registryRepo, zotAdapter, iamAdapter, registryRepo, opsRepo, cfg.EndpointBase)

	// ── register-drainer: owner-tuple register/unregister intent из registry_outbox
	// применяется через kacho-iam fga-proxy (:9091, mTLS, идемпотентно, at-least-once,
	// exactly-once claim FOR UPDATE SKIP LOCKED между репликами). iam недоступен →
	// intent durable + retry (owner-tuple не теряется). Без него созданные реестры не
	// получат owner/project-tuple → невидимы в authz-filtered List.
	regDrainer, derr := drainer.New[domain.RegisterIntent](
		pool,
		drainer.Config{Table: "kacho_registry.registry_outbox", Channel: "kacho_registry_outbox"},
		iamclient.DecodeRegisterIntent,
		iamclient.NewRegisterApplier(iamclient.NewRegisterResourceClient(iamConn)),
		logger,
	)
	if derr != nil {
		return fmt.Errorf("build register-drainer: %w", derr)
	}
	go func() {
		if rerr := regDrainer.Run(ctx); rerr != nil && !errors.Is(rerr, context.Canceled) {
			logger.Error("register-drainer stopped", "err", rerr)
		}
	}()

	// ── authz: per-RPC OpenFGA Check на ОБОИХ листенерах (AuthN+AuthZ везде —
	// internal :9091 НЕ освобождён, security.md). Check обязателен —
	// validateSecurityConfig уже гарантировал наличие адреса kacho-iam без breakglass.
	authzIntr, aerr := check.NewInterceptor(check.Options{
		ServiceName: "kacho-registry",
		IAMConn:     authzConn,
		Breakglass:  cfg.AuthZBreakglass,
		Logger:      logger,
	})

	// ── цепочки интерсепторов ──
	// Public (:9090): principal-extract → authz Check.
	publicUnary := []grpc.UnaryServerInterceptor{grpcsrv.UnaryPrincipalExtract()}
	publicStream := []grpc.StreamServerInterceptor{grpcsrv.StreamPrincipalExtract()}
	// Internal (:9091): cert-identity → trusted-principal (anti-spoof) → authz Check.
	// ТОТ ЖЕ per-RPC authz, что и на public — internal не доверенный.
	internalUnary := []grpc.UnaryServerInterceptor{
		grpcsrv.UnaryCertIdentityExtract(),
		grpcsrv.UnaryTrustedPrincipalExtract(),
	}
	internalStream := []grpc.StreamServerInterceptor{
		grpcsrv.StreamCertIdentityExtract(),
		grpcsrv.StreamTrustedPrincipalExtract(),
	}

	switch {
	case aerr == nil && authzIntr != nil:
		publicUnary = append(publicUnary, authzIntr.Unary())
		publicStream = append(publicStream, authzIntr.Stream())
		internalUnary = append(internalUnary, authzIntr.Unary())
		internalStream = append(internalStream, authzIntr.Stream())
		if cfg.AuthZBreakglass {
			logger.Warn("BREAKGLASS active: per-RPC authz Check bypassed on BOTH listeners (emergency mode)")
		} else {
			logger.Info("authz interceptor enabled",
				"iam_endpoint", cfg.AuthZIAMGRPCAddr,
				"listeners", "public+internal")
		}
	case errors.Is(aerr, check.ErrIAMConnNotConfigured):
		// Недостижимо при штатной конфигурации: validateSecurityConfig уже отказал
		// бы старту. Defensive fail-closed.
		return errors.New("authz Check required: set KACHO_REGISTRY_AUTHZ_IAM_GRPC_ADDR (or KACHO_REGISTRY_AUTHZ_BREAKGLASS=true to bypass)")
	case aerr != nil:
		return fmt.Errorf("build authz interceptor: %w", aerr)
	}

	// ── server-creds (mTLS обязателен на обоих листенерах, кроме breakglass) ──
	publicCreds, err := cfg.PublicServerCreds()
	if err != nil {
		return fmt.Errorf("public listener tls creds: %w", err)
	}
	internalCreds, err := cfg.InternalServerCreds()
	if err != nil {
		return fmt.Errorf("internal listener tls creds: %w", err)
	}

	grpcSrv := grpcsrv.NewServer(
		publicCreds,
		grpc.ChainUnaryInterceptor(publicUnary...),
		grpc.ChainStreamInterceptor(publicStream...),
	)
	internalSrv := grpcsrv.NewServer(
		internalCreds,
		grpc.ChainUnaryInterceptor(internalUnary...),
		grpc.ChainStreamInterceptor(internalStream...),
	)

	// per-repo authz-Check для ScopeFiltered RPC (ListRepositories/ListTags/DeleteTag):
	// interceptor их пропускает, handler сам Check'ает (call-gate + row-filter +
	// existence-hiding). Тот же conn к iam :9091, что и per-RPC interceptor.
	// authzConn==nil (breakglass) → nil authorizer → handler bypass (как interceptor).
	var listAuthz handler.Authorizer
	if authzConn != nil {
		listAuthz = check.NewIAMCheckClient(authzConn)
	}

	// Публичный control-plane RegistryService на :9090.
	registryv1.RegisterRegistryServiceServer(grpcSrv, handler.NewRegistryHandler(registryUC, listAuthz))
	// Admin InternalRegistryService ТОЛЬКО на cluster-internal :9091.
	registryv1.RegisterInternalRegistryServiceServer(internalSrv, handler.NewInternalRegistryHandler(registryUC))
	// OperationService (LRO poll) на ОБОИХ листенерах: async-мутации идут на public
	// и internal, клиент поллит результат через тот же mux. Read-RPC гейтятся authz.
	opHandler := handler.NewOperationHandler(opsRepo)
	operationpb.RegisterOperationServiceServer(grpcSrv, opHandler)
	operationpb.RegisterOperationServiceServer(internalSrv, opHandler)

	// ── data-plane OCI auth-proxy (registry.kacho.local): отдельный HTTP-листенер,
	// Docker Registry v2 / OCI token-auth flow перед zot. per-request JWKS-verify +
	// InternalIAMService.Check + existence-hiding + stream-proxy. Отдельно от gRPC.
	var dpServer *http.Server
	if cfg.DataplaneAddr != "" {
		dpHandler, dperr := buildDataplaneHandler(cfg, authzConn, registryRepo, zotAdapter, registryRepo, logger)
		if dperr != nil {
			return fmt.Errorf("build data-plane proxy: %w", dperr)
		}
		dpServer = &http.Server{
			Addr:              cfg.DataplaneAddr,
			Handler:           dpHandler,
			ReadHeaderTimeout: 15 * time.Second,
		}
	}

	listener, err := net.Listen("tcp", ":"+cfg.GrpcPort)
	if err != nil {
		return err
	}
	internalListener, err := net.Listen("tcp", ":"+cfg.InternalGrpcPort)
	if err != nil {
		_ = listener.Close()
		return err
	}
	logger.Info("kacho-registry listening",
		"public_mtls", cfg.PublicServerMTLS.Enable,
		"internal_mtls", cfg.InternalServerMTLS.Enable,
		"public_port", cfg.GrpcPort,
		"internal_port", cfg.InternalGrpcPort,
		"dataplane_addr", cfg.DataplaneAddr,
		"zot_addr", cfg.ZotAddr)

	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		internalSrv.GracefulStop()
		grpcSrv.GracefulStop()
		// Graceful drain data-plane HTTP: перестаёт принимать новые, дожидается
		// in-flight docker push/pull в пределах bounded-таймаута.
		if dpServer != nil {
			dpCtx, cancelDP := context.WithTimeout(context.Background(), 15*time.Second)
			if serr := dpServer.Shutdown(dpCtx); serr != nil {
				logger.Warn("data-plane proxy shutdown", "err", serr)
			}
			cancelDP()
		}
		// Дренируем in-flight LRO-worker'ы: SIGTERM не должен оставить async-мутацию
		// done=false навсегда (клиент завис бы в polling). Свежий ctx — request-ctx
		// уже отменён возвратом Operation клиенту.
		drainCtx, cancelDrain := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancelDrain()
		if werr := operations.Wait(drainCtx); werr != nil {
			logger.Warn("LRO workers did not finish before shutdown timeout",
				"err", werr, "active", operations.Active())
		}
	}()

	go func() {
		if serr := internalSrv.Serve(internalListener); serr != nil && !errors.Is(serr, grpc.ErrServerStopped) {
			logger.Error("internal grpc server stopped", "err", serr)
		}
	}()

	if dpServer != nil {
		go func() {
			if serr := dpServer.ListenAndServe(); serr != nil && !errors.Is(serr, http.ErrServerClosed) {
				logger.Error("data-plane proxy stopped", "err", serr)
			}
		}()
	}

	serveErr := grpcSrv.Serve(listener)
	cancel()
	<-shutdownDone
	return serveErr
}

// buildDataplaneHandler собирает data-plane OCI auth-proxy (fail-closed). Штатно:
// JWKS-verify Hydra-issued identity-JWT (RS256/ES256) + per-request
// InternalIAMService.Check + zot stream-proxy. breakglass → bypass AuthN+AuthZ
// (аварийный режим, как gRPC-листенеры).
func buildDataplaneHandler(cfg config.Config, authzConn *grpc.ClientConn, repoReg dataplane.RepoRegistrar, backend dataplane.Backend, regLookup dataplane.RegistryLookup, logger *slog.Logger) (http.Handler, error) {
	forwarder, err := dataplane.NewZotForwarder(cfg.ZotAddr, logger)
	if err != nil {
		return nil, err
	}

	var verifier dataplane.TokenVerifier
	var authorizer dataplane.Authorizer
	if cfg.AuthZBreakglass {
		logger.Warn("BREAKGLASS active: data-plane AuthN+AuthZ bypassed (emergency mode)")
	} else {
		if cfg.HydraJWKSURL == "" {
			return nil, errors.New("data-plane requires KACHO_REGISTRY_HYDRA_JWKS_URL (or KACHO_REGISTRY_AUTHZ_BREAKGLASS=true to bypass)")
		}
		if err := requireSecureJWKSURL(cfg.AuthMode, cfg.HydraJWKSURL); err != nil {
			return nil, err
		}
		if err := requireIssuerPinned(cfg.AuthMode, cfg.HydraIssuer); err != nil {
			return nil, err
		}
		if authzConn == nil {
			return nil, errors.New("data-plane requires authz IAM conn (KACHO_REGISTRY_AUTHZ_IAM_GRPC_ADDR)")
		}
		verifier = jwks.New(cfg.HydraJWKSURL, cfg.ServiceAud, cfg.HydraIssuer)
		authorizer = check.NewIAMCheckClient(authzConn)
	}

	return dataplane.New(verifier, authorizer, backend, forwarder, repoReg, regLookup,
		cfg.TokenRealm, cfg.ServiceAud, logger), nil
}

// requireSecureJWKSURL — в production/production-strict JWKS-endpoint (единственный
// trust-anchor верификации identity-JWT data-plane: jwks.Verifier тянет из него
// публичные ключи) обязан быть https://. Plaintext-HTTP допускает MITM-подмену
// JWKS-документа на пути к Hydra → forge-токен под любой subject → полный обход
// data-plane AuthN. В dev (и breakglass — там verifier не поднимается) http://
// допустим, симметрично DB sslmode=disable.
func requireSecureJWKSURL(authMode, jwksURL string) error {
	switch authMode {
	case "production", "production-strict":
		u, err := url.Parse(jwksURL)
		if err != nil {
			return fmt.Errorf("invalid KACHO_REGISTRY_HYDRA_JWKS_URL %q: %w", jwksURL, err)
		}
		if !strings.EqualFold(u.Scheme, "https") {
			return fmt.Errorf("AuthMode=%s requires https:// KACHO_REGISTRY_HYDRA_JWKS_URL "+
				"(JWKS trust anchor must not be fetched over plaintext; got scheme %q)", authMode, u.Scheme)
		}
	}
	return nil
}

// requireIssuerPinned — в production/production-strict issuer (iss) identity-JWT
// обязан быть закреплён (KACHO_REGISTRY_HYDRA_ISSUER непустой). jwks.Verifier пропускает
// iss-проверку при пустом issuer (issuer-pinning опционален) — тогда data-plane принял бы
// любой токен, подписанный ключом из того же JWKS и несущий aud ⊇ ServiceAud, независимо
// от того, КТО его выпустил (federation-out на другой RP, разделяющий Hydra/JWKS, дал бы
// доступ к OCI data-plane). В проде issuer-pinning не должен молча отсутствовать — параллель
// requireSecureJWKSURL. В dev (и breakglass — verifier не поднимается) пустой iss допустим.
func requireIssuerPinned(authMode, issuer string) error {
	switch authMode {
	case "production", "production-strict":
		if issuer == "" {
			return fmt.Errorf("AuthMode=%s requires KACHO_REGISTRY_HYDRA_ISSUER "+
				"(issuer pinning must not be silently omitted; a token from any relying "+
				"party sharing the JWKS+aud would otherwise authenticate)", authMode)
		}
	}
	return nil
}

// validateAuthMode разбирает KACHO_REGISTRY_AUTH_MODE (whitelist) и строгость
// DB-SSL. Режим не управляет authz/mTLS — ими управляет breakglass (см.
// validateSecurityConfig). `production-strict` дополнительно требует SSL до БД.
func validateAuthMode(cfg config.Config, logger *slog.Logger) error {
	switch cfg.AuthMode {
	case "dev":
		if cfg.DBSSLMode == "" || cfg.DBSSLMode == "disable" {
			logger.Warn("KACHO_REGISTRY_DB_SSLMODE=disable — DB plaintext (dev only)")
		}
		return nil
	case "production":
		return nil
	case "production-strict":
		switch cfg.DBSSLMode {
		case "require", "verify-ca", "verify-full":
		default:
			return fmt.Errorf("production-strict mode: KACHO_REGISTRY_DB_SSLMODE must be one of require|verify-ca|verify-full (got %q)", cfg.DBSSLMode)
		}
		logger.Warn("AuthMode=production-strict: DB SSL strictly validated")
		return nil
	default:
		return fmt.Errorf("unknown KACHO_REGISTRY_AUTH_MODE=%q (allowed: dev, production, production-strict)", cfg.AuthMode)
	}
}

// validateSecurityConfig — secure-by-default: операции без авторизации и mTLS
// запрещены. Per-RPC authz Check (адрес kacho-iam) и mTLS на ОБОИХ листенерах
// обязательны; единственный способ запустить без них — аварийный
// KACHO_REGISTRY_AUTHZ_BREAKGLASS=true.
//
// ⚠ ВНИМАНИЕ: breakglass=true — ПОЛНЫЙ обход authz+mTLS (emergency-only). Включать
// ТОЛЬКО при инциденте.
func validateSecurityConfig(cfg config.Config) error {
	if cfg.AuthZBreakglass {
		return nil
	}
	if cfg.AuthZIAMGRPCAddr == "" {
		return errors.New("authz Check required on both listeners: set KACHO_REGISTRY_AUTHZ_IAM_GRPC_ADDR (or KACHO_REGISTRY_AUTHZ_BREAKGLASS=true to bypass)")
	}
	if !cfg.PublicServerMTLS.Enable || !cfg.InternalServerMTLS.Enable {
		return errors.New("mTLS required on both listeners: set KACHO_REGISTRY_PUBLIC_SERVER_MTLS_ENABLE and KACHO_REGISTRY_INTERNAL_SERVER_MTLS_ENABLE=true (or KACHO_REGISTRY_AUTHZ_BREAKGLASS=true to bypass)")
	}
	return nil
}
