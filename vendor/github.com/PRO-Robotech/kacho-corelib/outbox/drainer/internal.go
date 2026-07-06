// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package drainer

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/jackc/pgx/v5"
)

// shutdownCtx returns a bounded context that survives parent ctx cancellation
// (for finalising in-flight work during graceful shutdown) but won't hang
// forever if the DB is unreachable. ApplyTimeout (default 5s) is the bound.
//
// Use for tx.Commit / tx.Rollback / conn.Close — operations that must run to
// completion even after parent ctx cancel, but whose synchronous calls on a
// dead Postgres backend would otherwise block forever and defeat graceful
// shutdown.
func (d *Drainer[T]) shutdownCtx(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), d.cfg.ApplyTimeout)
}

// listenLoop держит dedicated LISTEN-connection (hijacked из pool),
// слушает NOTIFY и сигналит wakeup-channel на каждое сообщение.
// При conn-drop — переоткрывает с exp-backoff (1s → 30s cap).
// Сразу после reconnect — non-blocking signal на wakeup, чтобы processLoop
// сделал catch-up (NOTIFY мог быть потерян во время disconnect-window).
func (d *Drainer[T]) listenLoop(ctx context.Context, wakeup chan<- struct{}) {
	backoff := 1 * time.Second
	const maxBackoff = 30 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		err := d.listenOnce(ctx, wakeup)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			d.logger.Warn("listen_conn_drop",
				slog.String("err", err.Error()),
				slog.Duration("backoff", backoff))
			// Pool-conns to the same Postgres backend могут также быть мертвы
			// (FATAL admin-shutdown часто бьет по всем conn'ам этого процесса).
			// pgxpool's ShouldPing-default ждет IdleDuration > 1s, что слишком
			// долго — Reset() форсит destroy всех idle conn'ов сейчас, fresh
			// conn'ы будут созданы на следующем Acquire.
			d.pool.Reset()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
		// После reconnect — сигналим wakeup, чтобы processLoop сделал
		// catch-up (мог пропустить NOTIFY-и во время disconnect).
		signalWakeup(wakeup)
	}
}

// listenOnce — один цикл «подключиться, LISTEN, обрабатывать NOTIFY до conn-drop».
// Возвращает err при потере connection.
func (d *Drainer[T]) listenOnce(ctx context.Context, wakeup chan<- struct{}) error {
	// Hijack — берем conn из pool и забираем владение (pool больше его не recycle'ит).
	// Это нужно потому, что LISTEN живет на одном connection и его нельзя
	// возвращать в pool (idle-connection-reset уничтожит state LISTEN-а).
	pconn, err := d.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("pool.Acquire: %w", err)
	}
	conn := pconn.Hijack()
	defer func() {
		// parent is context.Background() (not the live ctx) because Run's ctx
		// may already be Done when this defer fires — we still want the close
		// attempt to have a real deadline, not block forever on a dead backend.
		closeCtx, cancel := d.shutdownCtx(context.Background())
		defer cancel()
		if err := conn.Close(closeCtx); err != nil {
			// Close-failure on a hijacked conn means the backend didn't
			// terminate cleanly — may leak a PG backend until
			// idle_in_transaction_session_timeout fires server-side.
			d.logger.Debug("listen_conn_close_failed", slog.String("err", err.Error()))
		}
	}()

	if _, err := conn.Exec(ctx, "LISTEN "+d.cfg.Channel); err != nil {
		return fmt.Errorf("LISTEN: %w", err)
	}
	d.logger.Debug("listen_connected")

	// После каждого свежего connect — будим processLoop (catch-up safety).
	signalWakeup(wakeup)

	for {
		notif, err := conn.WaitForNotification(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if notif == nil {
			continue
		}
		// Payload игнорируем (id-конкретного row) — processLoop сделает
		// атомарный claim по всему батчу. Мы только сигналим «есть работа».
		signalWakeup(wakeup)
	}
}

// signalWakeup — non-blocking send на wakeup-channel.
// Если канал уже имеет один pending signal — игнорируем (processLoop еще не
// проснулся, все равно увидит «есть работа»).
func signalWakeup(c chan<- struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}

// claimedRow — то, что drainer получил из атомарного claim'а.
// Поле tx — открытая транзакция, которая держит row-lock (`FOR UPDATE SKIP LOCKED`)
// на время apply. После apply + mark — tx коммитится; на crash drainer'а —
// rollback и row становится доступной для re-claim другой репликой.
type claimedRow struct {
	id           int64
	eventType    string
	payload      []byte
	attemptCount int
	// Note: the pgx.Tx that holds the row-lock is returned by claimRows
	// alongside the []claimedRow batch (whole batch shares one tx). We don't
	// store tx per-row because that would suggest per-row independence.
}

// claimRows — атомарный pre-claim до `limit` pending rows.
// Открывает одну транзакцию, в ней `SELECT … FOR UPDATE SKIP LOCKED`,
// `UPDATE attempt_count` через RETURNING. Транзакция возвращается caller'у —
// он держит row-lock на время apply и КОММИТИТ/ROLLBACK'ит по результату.
//
// FOR UPDATE SKIP LOCKED + транзакция-держит-lock-на-время-apply — обеспечивает
// exactly-once across concurrent drainer replicas без race-window «claim →
// apply, но еще не markSuccess».
//
// На crash drainer'а conn drops → PG автоматически rollback'ит tx → row снова
// доступна для другого drainer'а. attempt_count инкрементнут в этом claim
// останется (увидится в логах), но это OK — attempt_count это «попытки», не
// «успехи».
//
// CAS-условие: sent_at IS NULL AND attempt_count < MaxAttempts (poisoned-skip).
//
// Возвращает (rows, tx, err). На err == nil И len(rows) > 0 — caller ОБЯЗАН
// finishClaim(tx, ...) после apply.
func (d *Drainer[T]) claimRows(ctx context.Context, limit int) ([]claimedRow, pgx.Tx, error) {
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("begin claim tx: %w", err)
	}

	// rollback closure — bounded shutdown-tolerant ctx so a dead Postgres
	// backend cannot hang error paths indefinitely (graceful-shutdown safety).
	rollback := func() {
		rbCtx, cancel := d.shutdownCtx(ctx)
		defer cancel()
		_ = tx.Rollback(rbCtx)
	}

	// ORDER BY (attempt_count, id): fairness against transient head-of-line
	// starvation. The transient handling caps a persistently-transient-failing
	// row's attempt_count at MaxAttempts-1 so it stays claimable forever — under a
	// plain `ORDER BY id` a backlog of such stuck low-id rows would permanently
	// shadow a freshly enqueued higher-id intent (the small per-claim LIMIT never
	// advances past them) and the new intent would never be delivered, breaking
	// at-least-once under a sustained outage. Ordering by attempt_count first
	// makes a fresh row (attempt_count=0) sort ahead of capped rows, so new
	// intents are always claimed promptly. FIFO for the happy path is preserved:
	// rows with equal attempt_count fall back to id order.
	q := fmt.Sprintf(`
		UPDATE %s
		   SET attempt_count = attempt_count + 1
		 WHERE id IN (
		     SELECT id FROM %s
		      WHERE sent_at IS NULL AND attempt_count < $1
		      ORDER BY attempt_count, id
		      FOR UPDATE SKIP LOCKED
		      LIMIT $2
		 )
		RETURNING id, event_type, payload, attempt_count
	`, d.cfg.Table, d.cfg.Table)

	rows, err := tx.Query(ctx, q, d.cfg.MaxAttempts, limit)
	if err != nil {
		rollback()
		return nil, nil, fmt.Errorf("claim query: %w", err)
	}

	var out []claimedRow
	for rows.Next() {
		var r claimedRow
		if err := rows.Scan(&r.id, &r.eventType, &r.payload, &r.attemptCount); err != nil {
			rows.Close()
			rollback()
			return nil, nil, fmt.Errorf("claim scan: %w", err)
		}
		out = append(out, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		rollback()
		return nil, nil, fmt.Errorf("claim rows: %w", err)
	}

	if len(out) == 0 {
		// Пусто — закрываем tx сразу, никакого row-lock не держим.
		rollback()
		return nil, nil, nil
	}
	return out, tx, nil
}

// markSuccess отмечает row как успешно примененную (sent_at = now(), last_error = NULL)
// в переданной транзакции (которая держит row-lock с момента claim'а).
func (d *Drainer[T]) markSuccess(ctx context.Context, tx pgx.Tx, id int64) error {
	q := fmt.Sprintf(
		`UPDATE %s SET sent_at = now(), last_error = NULL WHERE id = $1`,
		d.cfg.Table,
	)
	_, err := tx.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("mark success id=%d: %w", id, err)
	}
	return nil
}

// markPoisoned форсит attempt_count = MaxAttempts (drainer больше не переклеймит)
// и сохраняет last_error. Используется для permanent-errors (ErrPermanent) и
// decoder-fail. Выполняется в переданной транзакции.
func (d *Drainer[T]) markPoisoned(ctx context.Context, tx pgx.Tx, id int64, errMsg string) error {
	q := fmt.Sprintf(
		`UPDATE %s SET last_error = $1, attempt_count = $2 WHERE id = $3`,
		d.cfg.Table,
	)
	_, err := tx.Exec(ctx, q, truncErr(errMsg), d.cfg.MaxAttempts, id)
	if err != nil {
		return fmt.Errorf("mark poisoned id=%d: %w", id, err)
	}
	return nil
}

// markTransientFailure сохраняет last_error И гарантирует, что transient-класс
// НИКОГДА не отравит строку: attempt_count кап'ится ниже
// MaxAttempts (MaxAttempts-1), поэтому CAS-claim-условие `attempt_count <
// MaxAttempts` остается истинным сколько угодно долго — затяжной IAM-outage
// (Unavailable/timeout) ретраится unbounded с backoff, intent не теряется.
// attempt_count при этом продолжает расти до cap'а (питает exp-backoff и
// остается видимым в логах как «число попыток»). Выполняется в переданной tx.
func (d *Drainer[T]) markTransientFailure(ctx context.Context, tx pgx.Tx, id int64, errMsg string) error {
	// Cap at MaxAttempts-1 so the poison-gate (attempt_count < MaxAttempts) never
	// trips for a transient error. LEAST(...) keeps the existing increment for
	// rows still below the cap (backoff continues to grow), and clamps any row
	// that the claim pushed up to / past the cap back to MaxAttempts-1.
	capAttempt := d.cfg.MaxAttempts - 1
	if capAttempt < 0 {
		capAttempt = 0
	}
	q := fmt.Sprintf(
		`UPDATE %s SET last_error = $1, attempt_count = LEAST(attempt_count, $2) WHERE id = $3`,
		d.cfg.Table,
	)
	_, err := tx.Exec(ctx, q, truncErr(errMsg), capAttempt, id)
	if err != nil {
		return fmt.Errorf("mark transient id=%d: %w", id, err)
	}
	return nil
}

// truncErr ограничивает длину error-сообщения (хранить простыни stack-trace в
// last_error смысла нет; для debugging есть logger).
func truncErr(s string) string {
	const max = 2000
	if len(s) > max {
		return s[:max] + "...(truncated)"
	}
	return s
}

// drainBatch — один цикл «получить batch → обработать → отдать управление».
//
// Алгоритм:
//  1. Random small-batch limit [1, min(4, BatchSize)] на каждый claim для HA-fairness:
//     при HA-running две реплики не должны сгреб одной волны за один шот.
//  2. Обрабатываем claim'd rows в транзакции, которая держит row-lock на
//     время apply (FOR UPDATE SKIP LOCKED) — exactly-once guarantee
//     (другой drainer SKIP'нет lock'нутые rows до commit'а).
//  3. После commit — короткий jitter (0-10ms) перед следующим claim,
//     дает другому drainer'у шанс на следующую волну.
//  4. Если claim вернул 0 rows — выходим (вернемся в select main-loop ждать
//     NOTIFY/tick).
//  5. На ctx.Done() — корректно прерываемся, но in-flight Apply защищен
//     ApplyTimeout-grace (см. processRowInTx).
//
// Все ошибки логируются; функция не возвращает err — drainer-loop устойчив.
func (d *Drainer[T]) drainBatch(ctx context.Context) {
	iter := 0
	for {
		if ctx.Err() != nil {
			return
		}

		// Random small batch (1..4) per claim. Single-drainer overhead
		// negligible (5 iterations vs 1 на 20-row catch-up, ~5ms total
		// при 1ms per row); HA-fairness гарантирована.
		limit := 1 + rand.IntN(haFairnessLimit(d.cfg.BatchSize))

		rows, tx, err := d.claimRows(ctx, limit)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			d.logger.Warn("claim_batch_failed", slog.String("err", err.Error()))
			return
		}
		if len(rows) == 0 {
			return // tx уже rollback'нут в claimRows
		}

		// Обрабатываем batch внутри одной транзакции (держит row-lock).
		needsRetryAfter := false
		for _, r := range rows {
			retryThisRow := d.processRowInTx(ctx, tx, r)
			if retryThisRow {
				needsRetryAfter = true
			}
		}
		// Bounded shutdown-tolerant ctx for commit: survives parent ctx cancel
		// (we must finalise the in-flight batch) but won't hang forever if the
		// Postgres backend is dead.
		commitCtx, commitCancel := d.shutdownCtx(ctx)
		if err := tx.Commit(commitCtx); err != nil {
			// Commit fail — все sent_at-mark'и потеряны → row'ы остаются
			// pending (attempt_count уже инкрементнут). Будут переклейм'ены.
			d.logger.Warn("commit_batch_failed", slog.String("err", err.Error()))
		}
		commitCancel()

		// Если транзитные ошибки — sleep backoff чтобы не загрузить FGA
		// серией мгновенных retry-ев. Используем attempt_count первой row.
		if needsRetryAfter {
			sleep := expBackoff(rows[0].attemptCount, d.cfg.BackoffMin, d.cfg.BackoffMax)
			select {
			case <-time.After(sleep):
			case <-ctx.Done():
				return
			}
		} else if iter > 0 {
			// Tiny inter-batch jitter (0-5ms) дает другой реплике шанс
			// claim'нуть следующий batch. Применяется только после первой
			// итерации чтобы не задерживать первую обработку single-drainer.
			yieldJitter := time.Duration(rand.IntN(5)) * time.Millisecond
			if yieldJitter > 0 {
				select {
				case <-time.After(yieldJitter):
				case <-ctx.Done():
					return
				}
			}
		}
		iter++
	}
}

// haFairnessLimit returns max(1, min(4, batchSize)) — upper bound для random
// per-claim LIMIT. Меньше = лучше HA-fairness; больше = выше catch-up throughput.
// 4 — компромисс: 32 BatchSize / 4 = 8 claim-итераций для дренажа полной волны,
// при HA две реплики получают шанс взять каждый claim.
func haFairnessLimit(batchSize int) int {
	if batchSize <= 1 {
		return 1
	}
	if batchSize < 4 {
		return batchSize
	}
	return 4
}

// processRowInTx обрабатывает одну claim'ed row внутри claim-batch transaction.
//
//	decode → apply(с inner-ctx WithoutCancel + ApplyTimeout) → markSuccess/Failure/Poisoned (в tx).
//
// Apply вызывается с inner-ctx отвязанным от parent — это дает graceful-shutdown
// guarantee: даже если parent ctx cancel'ится в момент in-flight apply, applier
// дозавершается в пределах ApplyTimeout, mark делается корректно.
//
// DB-операции (mark*) используют переданную tx, которая держит row-lock с
// момента claim'а — exactly-once guarantee: другой drainer SKIP'нет row пока tx
// не commit'нется.
//
// Returns true если эта row нуждается в retry-backoff (transient error) — caller
// агрегирует это решение по всему batch.
func (d *Drainer[T]) processRowInTx(parentCtx context.Context, tx pgx.Tx, r claimedRow) bool {
	// Detached ctx для самого Apply: грейс при shutdown.
	applyCtx, applyCancel := context.WithTimeout(
		context.WithoutCancel(parentCtx),
		d.cfg.ApplyTimeout,
	)
	defer applyCancel()

	// Для tx-DB-операций (mark*) тоже используем detached ctx — иначе при
	// shutdown row останется с inc'd attempt_count но без mark'а success
	// (после rollback все откатится, но при partial commit hazardous).
	dbCtx, dbCancel := context.WithTimeout(
		context.WithoutCancel(parentCtx),
		d.cfg.ApplyTimeout,
	)
	defer dbCancel()

	// 1. Decode. Decoder-fail = permanent (malformed payload, no retry helps).
	payload, derr := d.decoder(r.payload)
	if derr != nil {
		d.logger.Warn("decode_failed_poison",
			slog.Int64("id", r.id),
			slog.String("err", derr.Error()))
		d.poison(dbCtx, tx, r.id, derr.Error())
		return false
	}

	// 2. Apply.
	aerr := d.applier(applyCtx, r.eventType, payload)

	// 3. Classify + mark. The classifier is the single
	//    decision point: transient errors (Unavailable/timeout/conn) NEVER
	//    poison — they retry unbounded with backoff (markTransientFailure caps
	//    attempt_count below the poison gate). Only ErrPermanent / gRPC
	//    InvalidArgument poison; ErrAlreadyApplied is idempotent success.
	switch Classify(aerr) {
	case ClassSuccess, ClassAlreadyApplied:
		if Classify(aerr) == ClassAlreadyApplied {
			d.logger.Debug("target_already_applied",
				slog.Int64("id", r.id), slog.String("event_type", r.eventType))
		}
		if err := d.markSuccess(dbCtx, tx, r.id); err != nil {
			d.logger.Error("mark_success_failed",
				slog.Int64("id", r.id), slog.String("err", err.Error()))
		}
		return false
	case ClassPermanent:
		d.logger.Warn("apply_permanent_poison",
			slog.Int64("id", r.id),
			slog.String("event_type", r.eventType),
			slog.String("err", aerr.Error()))
		d.poison(dbCtx, tx, r.id, aerr.Error())
		return false
	default: // ClassTransient — never poison; retry unbounded with backoff.
		d.logger.Debug("apply_transient_retry",
			slog.Int64("id", r.id),
			slog.Int("attempt", r.attemptCount),
			slog.String("err", aerr.Error()))
		if err := d.markTransientFailure(dbCtx, tx, r.id, aerr.Error()); err != nil {
			d.logger.Error("mark_transient_failed",
				slog.Int64("id", r.id), slog.String("err", err.Error()))
		}
		return true
	}
}

// poison marks the row poisoned (attempt_count = MaxAttempts) and notifies the
// optional poison observer (metrics: outbox_poisoned_total). Used for permanent
// applier errors and decoder failures only — never for transient errors.
func (d *Drainer[T]) poison(ctx context.Context, tx pgx.Tx, id int64, errMsg string) {
	if err := d.markPoisoned(ctx, tx, id, errMsg); err != nil {
		d.logger.Error("mark_poisoned_failed",
			slog.Int64("id", id), slog.String("err", err.Error()))
		return
	}
	if d.onPoison != nil {
		d.onPoison()
	}
}

// expBackoff = min(base * 2^(attempt-1), max). attempt — 1-based.
// attempt=1 → base; attempt=2 → 2*base; attempt=3 → 4*base; clamp на max.
func expBackoff(attempt int, base, max time.Duration) time.Duration {
	if attempt <= 1 {
		return base
	}
	d := base
	for i := 1; i < attempt; i++ {
		d *= 2
		if d >= max {
			return max
		}
	}
	return d
}
