// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// PendingBlobRepo — Postgres-adapter durable per-repo учёта загруженных блобов
// (registry_pending_blob, REG-33 Defect A). Реализует порт dataplane.UploadRecorder
// (структурно; compile-check даёт composition root): blob PUT-finalize пишет строку
// (registryID, repo, digest), а push-time blob HEAD/GET консультируется с ней, чтобы
// раскрыть только-что-загруженный слой ДО появления манифеста — не пере-открывая
// cross-tenant blob-leak (см. миграцию 0003).
//
// ttl — freshness-окно: BlobUploaded учитывает только строки моложе ttl, SweepStale
// удаляет более старые. Инжектируется composition root'ом (config.PendingBlobTTL).
type PendingBlobRepo struct {
	pool *pgxpool.Pool
	ttl  time.Duration
}

// NewPendingBlobRepo создаёт PendingBlobRepo поверх pgxpool с freshness-TTL.
func NewPendingBlobRepo(pool *pgxpool.Pool, ttl time.Duration) *PendingBlobRepo {
	return &PendingBlobRepo{pool: pool, ttl: ttl}
}

// ready — pool обязан быть подан composition root'ом (иначе Unavailable, не паника).
func (r *PendingBlobRepo) ready() error {
	if r.pool == nil {
		return regerrors.ErrUnavailable
	}
	return nil
}

// RecordUploadedBlob идемпотентно (upsert) фиксирует факт аплоада <digest> в
// <registryID>/<repo>. ON CONFLICT DO UPDATE освежает uploaded_at на повторном аплоаде
// того же слоя (retry/re-push держит строку свежей всё push-окно). Одиночный
// INSERT-стейтмент атомарен на DB-уровне — software check-then-act не нужен.
func (r *PendingBlobRepo) RecordUploadedBlob(ctx context.Context, registryID, repo, digest string) error {
	if err := r.ready(); err != nil {
		return err
	}
	q := fmt.Sprintf(`
		INSERT INTO %s.registry_pending_blob (registry_id, repo, digest)
		VALUES ($1, $2, $3)
		ON CONFLICT (registry_id, repo, digest) DO UPDATE SET uploaded_at = now()`, schema)
	if _, err := r.pool.Exec(ctx, q, registryID, repo, digest); err != nil {
		return wrapPgErr(err, "registry_pending_blob", registryID+"/"+repo)
	}
	return nil
}

// BlobUploaded сообщает, был ли <digest> загружен в <registryID>/<repo> в пределах ttl.
// cutoff = now-ttl вычисляется в Go и передаётся параметром (без interval-строки в SQL).
func (r *PendingBlobRepo) BlobUploaded(ctx context.Context, registryID, repo, digest string) (bool, error) {
	if err := r.ready(); err != nil {
		return false, err
	}
	cutoff := time.Now().Add(-r.ttl)
	q := fmt.Sprintf(`
		SELECT EXISTS (
			SELECT 1 FROM %s.registry_pending_blob
			 WHERE registry_id = $1 AND repo = $2 AND digest = $3 AND uploaded_at > $4
		)`, schema)
	var exists bool
	if err := r.pool.QueryRow(ctx, q, registryID, repo, digest, cutoff).Scan(&exists); err != nil {
		return false, wrapPgErr(err, "registry_pending_blob", registryID+"/"+repo)
	}
	return exists, nil
}

// SweepStale удаляет pending-строки старше ttl (гигиена: после появления блоба в
// манифесте строка избыточна; без sweep таблица росла бы неограниченно). Возвращает
// число удалённых строк. Идемпотентна, безопасна к параллельному запуску реплик.
func (r *PendingBlobRepo) SweepStale(ctx context.Context) (int64, error) {
	if err := r.ready(); err != nil {
		return 0, err
	}
	cutoff := time.Now().Add(-r.ttl)
	q := fmt.Sprintf(`DELETE FROM %s.registry_pending_blob WHERE uploaded_at <= $1`, schema)
	tag, err := r.pool.Exec(ctx, q, cutoff)
	if err != nil {
		return 0, wrapPgErr(err, "registry_pending_blob", "")
	}
	return tag.RowsAffected(), nil
}
