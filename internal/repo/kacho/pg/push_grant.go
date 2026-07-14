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

// PushGrantRepo — Postgres-adapter durable per-subject учёта push-ownership репозитория
// (registry_push_grant, REG-33 immediate-pull). Реализует порт dataplane.PushGrantRecorder
// (структурно; compile-check даёт composition root): успешный manifest-PUT пишет строку
// (registryID, repo, subject), а pull-path консультируется с ней как fallback, чтобы
// раскрыть репо ИМЕННО толкавшему, пока async register-on-first-push не материализовал
// per-repo v_get в FGA — не пере-открывая cross-tenant leak (ключ по subject; см.
// миграцию 0004).
//
// ttl — freshness-окно: PushGranted учитывает только строки моложе ttl, SweepStale
// удаляет более старые. Инжектируется composition root'ом (config.PushGrantTTL).
type PushGrantRepo struct {
	pool *pgxpool.Pool
	ttl  time.Duration
}

// NewPushGrantRepo создаёт PushGrantRepo поверх pgxpool с freshness-TTL.
func NewPushGrantRepo(pool *pgxpool.Pool, ttl time.Duration) *PushGrantRepo {
	return &PushGrantRepo{pool: pool, ttl: ttl}
}

// ready — pool обязан быть подан composition root'ом (иначе Unavailable, не паника).
func (r *PushGrantRepo) ready() error {
	if r.pool == nil {
		return regerrors.ErrUnavailable
	}
	return nil
}

// RecordPushGrant идемпотентно (upsert) фиксирует, что <subject> запушил
// <registryID>/<repo>. ON CONFLICT DO UPDATE освежает granted_at на повторном push того же
// субъекта в тот же repo (re-push держит запись свежей всё push-окно). Одиночный
// INSERT-стейтмент атомарен на DB-уровне — software check-then-act не нужен.
func (r *PushGrantRepo) RecordPushGrant(ctx context.Context, registryID, repo, subject string) error {
	if err := r.ready(); err != nil {
		return err
	}
	q := fmt.Sprintf(`
		INSERT INTO %s.registry_push_grant (registry_id, repo, subject)
		VALUES ($1, $2, $3)
		ON CONFLICT (registry_id, repo, subject) DO UPDATE SET granted_at = now()`, schema)
	if _, err := r.pool.Exec(ctx, q, registryID, repo, subject); err != nil {
		return wrapPgErr(err, "registry_push_grant", registryID+"/"+repo)
	}
	return nil
}

// PushGranted сообщает, держит ли <subject> свежий push-grant на <registryID>/<repo> в
// пределах ttl. cutoff = now-ttl вычисляется в Go и передаётся параметром (без
// interval-строки в SQL).
func (r *PushGrantRepo) PushGranted(ctx context.Context, registryID, repo, subject string) (bool, error) {
	if err := r.ready(); err != nil {
		return false, err
	}
	cutoff := time.Now().Add(-r.ttl)
	q := fmt.Sprintf(`
		SELECT EXISTS (
			SELECT 1 FROM %s.registry_push_grant
			 WHERE registry_id = $1 AND repo = $2 AND subject = $3 AND granted_at > $4
		)`, schema)
	var exists bool
	if err := r.pool.QueryRow(ctx, q, registryID, repo, subject, cutoff).Scan(&exists); err != nil {
		return false, wrapPgErr(err, "registry_push_grant", registryID+"/"+repo)
	}
	return exists, nil
}

// SweepStale удаляет push-grant-строки старше ttl (гигиена: после FGA-материализации v_get
// строка избыточна; без sweep таблица росла бы неограниченно). Возвращает число удалённых
// строк. Идемпотентна, безопасна к параллельному запуску реплик.
func (r *PushGrantRepo) SweepStale(ctx context.Context) (int64, error) {
	if err := r.ready(); err != nil {
		return 0, err
	}
	cutoff := time.Now().Add(-r.ttl)
	q := fmt.Sprintf(`DELETE FROM %s.registry_push_grant WHERE granted_at <= $1`, schema)
	tag, err := r.pool.Exec(ctx, q, cutoff)
	if err != nil {
		return 0, wrapPgErr(err, "registry_push_grant", "")
	}
	return tag.RowsAffected(), nil
}
