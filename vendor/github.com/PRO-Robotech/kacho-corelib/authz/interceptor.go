// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package authz

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// InterceptorOptions — конфигурация gRPC interceptor'а.
type InterceptorOptions struct {
	// ServiceName — имя сервиса для метрик / логов: "kacho-vpc" / "kacho-compute" / etc.
	ServiceName string

	// Map — RPCMap.
	Map RPCMap

	// Client — implements CheckClient (gRPC client к InternalIAMService.Check).
	Client CheckClient

	// Cache — Cache instance (must be non-nil; используется shared с
	// listen_invalidate.go).
	Cache *Cache

	// Logger — slog logger.
	Logger *slog.Logger

	// Breakglass — если true, interceptor пропускает все RPC без Check + WARN.
	// Source: env `KACHO_<SVC>_AUTHZ__BREAKGLASS=true` (читать в composition root).
	Breakglass bool

	// DenyRateLimitPerSec — token-bucket per-Principal на denied storm.
	// 0 / negative → disabled (default 100/s — см. KACHO_<SVC>_AUTHZ__DENY_RATE_LIMIT).
	DenyRateLimitPerSec float64

	// CheckTimeout — таймаут на один Check-call.
	// Default 2*time.Second (если ≤0).
	CheckTimeout time.Duration

	// SubjectExtractor — функция, извлекающая (subject string, ok bool) из
	// ctx. По умолчанию — `defaultSubjectExtractor` использует
	// `operations.PrincipalFromContext(ctx)`. Можно переопределить
	// для тестов.
	SubjectExtractor func(ctx context.Context) (subjectFGA string, principalID string, ok bool)

	// AllowSystemPrincipal — если true, system-principal (Type="system",
	// ID="bootstrap") пропускается без Check. Используется для bootstrap'а /
	// миграции / фоновых job'ов, которым нет смысла Check'аться. Default false.
	AllowSystemPrincipal bool
}

// Interceptor реализует gRPC unary + stream interceptor'ы.
//
// Использование (composition root, напр `kacho-vpc/cmd/kacho-vpc/main.go`):
//
//	authzIntr := authz.NewInterceptor(authz.InterceptorOptions{...})
//	grpc.NewServer(
//	    grpc.ChainUnaryInterceptor(... , authzIntr.Unary()),
//	    grpc.ChainStreamInterceptor(... , authzIntr.Stream()),
//	)
type Interceptor struct {
	opts        InterceptorOptions
	rateLimiter *rateLimiter

	// counters (lock-free atomic для observability).
	allowedTotal     uint64
	deniedTotal      uint64
	unavailableTotal uint64
	cacheHitsTotal   uint64
	breakglassTotal  uint64
	unmappedTotal    uint64
	rateLimitedTotal uint64
}

// NewInterceptor конструктор. Panics при invalid options.
func NewInterceptor(opts InterceptorOptions) *Interceptor {
	if opts.Map == nil {
		panic("authz: InterceptorOptions.Map is nil")
	}
	if opts.Client == nil && !opts.Breakglass {
		panic("authz: InterceptorOptions.Client is nil and Breakglass=false")
	}
	if opts.Cache == nil {
		opts.Cache = NewCache(0)
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.CheckTimeout <= 0 {
		opts.CheckTimeout = 2 * time.Second
	}
	if opts.SubjectExtractor == nil {
		opts.SubjectExtractor = defaultSubjectExtractor
	}
	if opts.ServiceName == "" {
		opts.ServiceName = "kacho"
	}
	return &Interceptor{
		opts:        opts,
		rateLimiter: newRateLimiter(opts.DenyRateLimitPerSec),
	}
}

// Unary возвращает grpc.UnaryServerInterceptor.
func (i *Interceptor) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		dec, err := i.authorize(ctx, info.FullMethod, req)
		switch dec {
		case DecisionAllowed, DecisionNoPath:
			return handler(ctx, req)
		case DecisionHideExistence:
			// Existence-hiding: объект есть, но caller не вправе видеть → NOT_FOUND
			// (handler НЕ вызывается, чтобы не слить ресурс).
			return nil, status.Error(codes.NotFound, "not found")
		case DecisionDenied:
			return nil, status.Error(codes.PermissionDenied, "permission denied")
		case DecisionUnavailable:
			// Fail-closed.
			return nil, status.Error(codes.PermissionDenied, "authorization service unavailable")
		case DecisionUnmapped:
			// Fail-closed для не-mapped RPC.
			return nil, status.Error(codes.PermissionDenied, "permission denied (rpc not mapped)")
		case DecisionInternal:
			// internal RPC — пропустить без Check.
			return handler(ctx, req)
		case DecisionRateLimited:
			return nil, status.Error(codes.ResourceExhausted, "too many denied checks; retry later")
		}
		// Unknown decision — fail-closed.
		if err != nil {
			return nil, status.Errorf(codes.PermissionDenied, "%v", err)
		}
		return nil, status.Error(codes.PermissionDenied, "permission denied (unknown decision)")
	}
}

// Stream возвращает grpc.StreamServerInterceptor.
//
// На stream-RPC interceptor извлекает Authorization decision до открытия
// stream'а. Дальше идет обычный wrapping.
//
// NOTE: для stream-RPC `req` недоступен в interceptor'е до первого Recv() —
// поэтому StaticExtractor должен либо использовать пустой request (если
// RPCEntry knows fixed object_id вне request'а), либо stream-RPC не покрыт
// этим interceptor'ом (пометка Public=true в RPCMap для известных stream'ов
// типа `InternalResourceLifecycleService.Subscribe`).
//
// На MVP — все public stream-RPC должны помечать ObjectExtractor как
// возвращающий статичный object (e.g. project-scope из SubscribeRequest).
func (i *Interceptor) Stream() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		// Stream req не доступен до первого Recv → для stream-RPC передаем nil как req.
		// Это работает для типичных Watch / Subscribe streams, где либо метод public
		// (e.g. InternalResourceLifecycleService.Subscribe — Public=true), либо
		// extractor явно проектирует request'-less проверку.
		dec, err := i.authorize(ss.Context(), info.FullMethod, nil)
		switch dec {
		case DecisionAllowed, DecisionInternal, DecisionNoPath:
			return handler(srv, ss)
		case DecisionHideExistence:
			return status.Error(codes.NotFound, "not found")
		case DecisionDenied:
			return status.Error(codes.PermissionDenied, "permission denied")
		case DecisionUnavailable:
			return status.Error(codes.PermissionDenied, "authorization service unavailable")
		case DecisionUnmapped:
			return status.Error(codes.PermissionDenied, "permission denied (rpc not mapped)")
		case DecisionRateLimited:
			return status.Error(codes.ResourceExhausted, "too many denied checks; retry later")
		}
		if err != nil {
			return status.Errorf(codes.PermissionDenied, "%v", err)
		}
		return status.Error(codes.PermissionDenied, "permission denied (unknown decision)")
	}
}

// authorize — основная логика (вне зависимости от unary/stream).
func (i *Interceptor) authorize(ctx context.Context, fullMethod string, req any) (Decision, error) {
	logger := i.opts.Logger.With(
		slog.String("rpc", fullMethod),
		slog.String("service", i.opts.ServiceName),
	)

	// 1. Break-glass — обходит authz-Check, но **anonymous все равно denied**.
	// breakglass=true НЕ должен пускать anonymous'а создавать VPC/Compute
	// ресурсы — он лишь эмулирует "all authenticated users allowed", не
	// "everyone allowed".
	if i.opts.Breakglass {
		if isAnonymousSubject(i.opts.SubjectExtractor, ctx) {
			atomic.AddUint64(&i.deniedTotal, 1)
			logger.Warn("authz_breakglass_anonymous_denied")
			return DecisionDenied, nil
		}
		atomic.AddUint64(&i.breakglassTotal, 1)
		logger.Warn("authz_breakglass_used")
		return DecisionAllowed, nil
	}

	// 2. Lookup RPC. Любой не-замапленный RPC fail-closed — без name-based
	// исключений. Internal RPC, который должен быть exempt, обязан явно стоять в
	// RPCMap (Relation для Check либо Public=true): per-RPC authz-Check
	// обязателен на ОБОИХ listener'ах (public и :9091), а молчаливое исключение
	// по имени "Internal*" было fail-open вектором на internal-периметре.
	entry, ok := i.opts.Map.Lookup(fullMethod)
	if !ok {
		atomic.AddUint64(&i.unmappedTotal, 1)
		logger.Warn("authz_unmapped_rpc")
		return DecisionUnmapped, ErrUnmapped
	}
	if entry.Public {
		return DecisionInternal, nil
	}
	if entry.ScopeFiltered {
		// scope-filtered List RPC — the handler authorises at the data level
		// (ListObjects-filtered result, 200 + filtered/EMPTY). Skip the per-RPC
		// Check; a single-object Check would reject the whole call `no path` 403
		// before the scope-filter could run.
		return DecisionInternal, nil
	}

	// 3. Subject extract.
	subjectFGA, principalID, ok := i.opts.SubjectExtractor(ctx)
	if !ok {
		// Нет Principal'а в ctx → fail-closed.
		logger.Warn("authz_no_principal")
		atomic.AddUint64(&i.deniedTotal, 1)
		return DecisionDenied, nil
	}
	if i.opts.AllowSystemPrincipal && principalID == "bootstrap" {
		return DecisionAllowed, nil
	}

	// 4. Object extract.
	objectType, objectID, err := entry.Extract(req)
	if err != nil {
		logger.Warn("authz_object_extract_failed", slog.String("err", err.Error()))
		atomic.AddUint64(&i.deniedTotal, 1)
		return DecisionDenied, fmt.Errorf("object extract: %w", err)
	}
	object, err := FormatObject(objectType, objectID)
	if err != nil {
		logger.Warn("authz_object_format_failed", slog.String("err", err.Error()))
		atomic.AddUint64(&i.deniedTotal, 1)
		return DecisionDenied, err
	}

	// 5. Cache lookup.
	if allowed, hit := i.opts.Cache.Get(subjectFGA, entry.Relation, objectType, objectID); hit {
		atomic.AddUint64(&i.cacheHitsTotal, 1)
		if allowed {
			atomic.AddUint64(&i.allowedTotal, 1)
			return DecisionAllowed, nil
		}
		// Negative never cached — defensive branch для future use.
		atomic.AddUint64(&i.deniedTotal, 1)
		return DecisionDenied, nil
	}

	// 6. Rate-limit denied-storm: применяется ДО Check call, иначе
	// flooding обходит cache and загружает kacho-iam. Bucket per-Principal.
	if !i.rateLimiter.Allow(principalID) {
		atomic.AddUint64(&i.rateLimitedTotal, 1)
		logger.Warn("authz_rate_limited",
			slog.String("principal_id", principalID))
		return DecisionRateLimited, nil
	}

	// 7. Check call.
	cctx, cancel := context.WithTimeout(ctx, i.opts.CheckTimeout)
	defer cancel()
	allowed, err := i.opts.Client.Check(cctx, subjectFGA, entry.Relation, object)
	if err != nil {
		if errors.Is(err, ErrNoPath) {
			// No FGA hierarchy tuple for this object → resource likely does not
			// exist. Let the handler run: it will return NOT_FOUND from the DB.
			// This prevents authz from masking NOT_FOUND as 403 PermissionDenied.
			atomic.AddUint64(&i.allowedTotal, 1)
			logger.Info("authz_no_path_passthrough",
				slog.String("subject", subjectFGA),
				slog.String("relation", entry.Relation),
				slog.String("object", object))
			return DecisionNoPath, nil
		}
		if errors.Is(err, ErrHideExistence) {
			// Объект существует, но caller не вправе видеть → existence-hiding:
			// блокируем handler и отдаём NOT_FOUND (не PermissionDenied), чтобы
			// «есть-но-не-твой» было неотличимо от «нет такого».
			atomic.AddUint64(&i.deniedTotal, 1)
			logger.Warn("authz_hide_existence",
				slog.String("subject", subjectFGA),
				slog.String("relation", entry.Relation),
				slog.String("object", object))
			return DecisionHideExistence, nil
		}
		atomic.AddUint64(&i.unavailableTotal, 1)
		logger.Error("authz_check_unavailable",
			slog.String("subject", subjectFGA),
			slog.String("relation", entry.Relation),
			slog.String("object", object),
			slog.String("err", err.Error()))
		return DecisionUnavailable, errors.Join(ErrUnavailable, err)
	}
	if !allowed {
		atomic.AddUint64(&i.deniedTotal, 1)
		logger.Warn("authz_denied",
			slog.String("subject", subjectFGA),
			slog.String("relation", entry.Relation),
			slog.String("object", object))
		return DecisionDenied, nil
	}

	// 8. Cache positive.
	i.opts.Cache.SetAllowed(subjectFGA, entry.Relation, objectType, objectID)
	atomic.AddUint64(&i.allowedTotal, 1)
	return DecisionAllowed, nil
}

// Metrics — счетчики для Prometheus / тестов. Lock-free.
type Metrics struct {
	Allowed     uint64
	Denied      uint64
	Unavailable uint64
	CacheHits   uint64
	Breakglass  uint64
	Unmapped    uint64
	RateLimited uint64
}

// Metrics возвращает snapshot счетчиков.
func (i *Interceptor) Metrics() Metrics {
	return Metrics{
		Allowed:     atomic.LoadUint64(&i.allowedTotal),
		Denied:      atomic.LoadUint64(&i.deniedTotal),
		Unavailable: atomic.LoadUint64(&i.unavailableTotal),
		CacheHits:   atomic.LoadUint64(&i.cacheHitsTotal),
		Breakglass:  atomic.LoadUint64(&i.breakglassTotal),
		Unmapped:    atomic.LoadUint64(&i.unmappedTotal),
		RateLimited: atomic.LoadUint64(&i.rateLimitedTotal),
	}
}

// EvictInactiveSubjects — для periodic background job; удаляет rate-limiter
// buckets, у которых lastSeen старше maxAge. Вернет кол-во удаленных.
func (i *Interceptor) EvictInactiveSubjects(maxAge time.Duration) int {
	return i.rateLimiter.EvictInactive(maxAge)
}
