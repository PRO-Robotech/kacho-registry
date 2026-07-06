// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package authz реализует REBAC-based authorization для backend-сервисов
// Kachō (kacho-vpc / kacho-compute / kacho-loadbalancer / kacho-iam).
//
// # Архитектура
//
//	┌──────────────┐     unary/stream     ┌──────────────────────────┐
//	│   client     │ ───── gRPC ─────────►│  authz.Interceptor       │
//	└──────────────┘                       │  (per-service)           │
//	                                       │                          │
//	                                       │  1. lookup PermissionMap │
//	                                       │     RPC → {object_type,  │
//	                                       │            relation,     │
//	                                       │            extractor}    │
//	                                       │  2. cache.Get (≤0.5ms)   │
//	                                       │  3. (cache miss) call    │
//	                                       │     CheckClient.Check    │
//	                                       │  4. cache.Set positive   │
//	                                       │  5. allow / DENY         │
//	                                       └──────────────────────────┘
//	                                                  │
//	                                                  ▼ Check(subj, rel, obj)
//	                                       ┌──────────────────────────┐
//	                                       │  kacho-iam :9091         │
//	                                       │  InternalIAMService.Check│
//	                                       └──────────────────────────┘
//	                                                  │
//	                                                  ▼ openfga.Check
//	                                       ┌──────────────────────────┐
//	                                       │  OpenFGA                 │
//	                                       └──────────────────────────┘
//
// # Cache invalidation (≤10s revoke propagation; NFR-5)
//
//   - Cache TTL = 5s positive-only (negative not cached).
//   - Push-invalidation через `pg_notify('kacho_iam_subjects', subject_id)`:
//     dedicated pgx-conn в каждом backend (LISTEN-loop), на NOTIFY вызывает
//     `Cache.InvalidateBySubject(subject_id)`.
//   - Worst-case revoke: TTL=5s + NOTIFY≤1s + outbox-drain≤2s = ≤10s.
//
// # Fail modes
//
//   - OpenFGA / kacho-iam.Check unavailable → fail-closed `PermissionDenied`.
//   - `KACHO_<SVC>_AUTHZ__BREAKGLASS=true` env (dev/break-glass) → bypass Check
//   - WARN log (rate-limited) + Prometheus alert.
//
// # Decoupling от kacho-proto
//
// Пакет НЕ импортирует kacho-proto stubs (см. corelib go.mod — нет ребра
// build-зависимости). Вместо этого определяет узкий port-интерфейс CheckClient:
//
//	type CheckClient interface {
//	    Check(ctx context.Context, subjectID, relation, object string) (allowed bool, err error)
//	}
//
// Реализация (gRPC client к InternalIAMService.Check) живет в кliente-side
// adapter'е (например `kacho-vpc/internal/clients/iam_authz_client.go`),
// который импортирует kacho-proto stubs и реализует authz.CheckClient.
//
// # Файлы пакета
//
//   - types.go            — RPCMap / Decision / типы
//   - cache.go            — TTL=5s positive-only кэш + LISTEN-invalidate hook
//   - interceptor.go      — gRPC unary/stream interceptor
//   - check_client.go     — port-интерфейс CheckClient + composition helper
//   - rate_limiter.go     — token-bucket per-Principal на denied-storm
//   - listen_invalidate.go — pgx LISTEN-loop, инвалидирующий cache на NOTIFY
package authz
