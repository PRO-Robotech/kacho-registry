// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package drainer реализует универсальный outbox-drainer для Kachō outbox-pattern.
//
// Drainer слушает LISTEN/NOTIFY-канал Postgres, дренит pending rows на старте
// (catch-up), декодирует payload через caller-supplied Decoder[T] и применяет
// каждую row через caller-supplied Applier[T] к target-системе.
//
// # Свойства
//
//   - **Идемпотентность**: Applier возвращает [ErrAlreadyApplied] → drainer
//     трактует как success и mark'ит sent_at. Это позволяет at-least-once
//     дренаж быть exactly-once на бизнес-уровне (caller возвращает
//     ErrAlreadyApplied на повторный write existing tuple / HTTP 409).
//   - **Exactly-once across HA replicas**: claim открывает транзакцию с
//     `SELECT … FOR UPDATE SKIP LOCKED` и держит row-lock на время Apply.
//     Другие реплики drainer-а SKIP'нут lock'нутый row до commit'а текущей.
//     within-service-инварианты выражаются на DB-уровне.
//   - **Exp-backoff retry**: transient errors (все, что не [ErrAlreadyApplied]
//     и не [ErrPermanent]) → retry с backoff [BackoffMin..BackoffMax] на
//     каждый attempt; следующий NOTIFY/poll переклеймит row.
//   - **Poisoned-skip**: permanent errors (`errors.Is(err, ErrPermanent)`)
//     или decoder-fail → force attempt_count = MaxAttempts, drainer больше
//     не переклеймит. last_error содержит сообщение для debugging.
//     Operator при необходимости reset вручную (UPDATE … SET attempt_count = 0).
//   - **Graceful shutdown**: ctx.Done() → дозавершает текущий in-flight Apply
//     (использует detached ctx с ApplyTimeout grace), затем exit.
//   - **LISTEN reconnect**: на drop LISTEN-conn'а → reconnect с exp-backoff
//     (1s → 30s cap), pool.Reset() форсит destroy idle pool-conn'ов (могут
//     быть тоже мертвы при общем admin-shutdown / FATAL); после reconnect —
//     catch-up wakeup (NOTIFY могли быть потеряны во время disconnect).
//
// # Архитектура
//
// Drainer параметризован generic-типом T (decoded payload). Один Drainer[T] —
// один outbox-table + один applier. Для двух outbox-таблиц (e.g. fga_outbox +
// subject_change_outbox в kacho-iam) запускайте две независимые Drainer-инстанции.
//
// LISTEN использует dedicated pgx-connection, hijacked из переданного pool'а.
// Hijack необходим, потому что LISTEN-state не выживает pool's idle-conn recycle.
// Conn закрывается при reconnect / shutdown.
//
// Claim/apply/mark идут через pool в одной транзакции на batch (1..4 rows
// random для HA-fairness). Транзакция держит row-lock от claim до mark'а,
// исключая race-window «claim → apply done, но markSuccess не успел» при HA.
//
// # Пример (kacho-iam fga_outbox)
//
//	type FGAOutboxEvent struct {
//	    User, Relation, Object string
//	}
//
//	d, err := drainer.New[FGAOutboxEvent](
//	    pool,
//	    drainer.Config{
//	        Table:        "kacho_iam.fga_outbox",
//	        Channel:      "kacho_iam_fga_outbox",
//	        BatchSize:    32,
//	        PollFallback: 30 * time.Second,
//	        MaxAttempts:  10,
//	        BackoffMin:   1 * time.Second,
//	        BackoffMax:   30 * time.Second,
//	    },
//	    func(p []byte) (FGAOutboxEvent, error) {
//	        var e FGAOutboxEvent
//	        if err := json.Unmarshal(p, &e); err != nil {
//	            return e, errors.Join(drainer.ErrPermanent, err)
//	        }
//	        return e, nil
//	    },
//	    func(ctx context.Context, eventType string, e FGAOutboxEvent) error {
//	        switch eventType {
//	        case "fga.tuple.write":
//	            err := openFGA.WriteTuples(ctx, ...)
//	            if isConflict(err) { return drainer.ErrAlreadyApplied }
//	            return err
//	        case "fga.tuple.delete":
//	            err := openFGA.DeleteTuples(ctx, ...)
//	            if isMissing(err) { return drainer.ErrAlreadyApplied }
//	            return err
//	        default:
//	            return errors.Join(drainer.ErrPermanent,
//	                fmt.Errorf("unknown event_type %q", eventType))
//	        }
//	    },
//	    logger,
//	)
//	if err != nil { return err }
//	return d.Run(ctx) // blocks until ctx.Done()
//
// # См. также
//
//   - Writer-side (Emit / WriteEvent): пакет github.com/PRO-Robotech/kacho-corelib/outbox
package drainer
