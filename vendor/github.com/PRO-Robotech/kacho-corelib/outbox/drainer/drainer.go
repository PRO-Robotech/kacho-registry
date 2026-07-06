// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package drainer

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Config — параметры конкретного экземпляра drainer-а.
type Config struct {
	// Table — полное имя outbox-таблицы (`<schema>.<table>`), e.g. "kacho_iam.fga_outbox".
	Table string
	// Channel — имя LISTEN-канала, e.g. "kacho_iam_fga_outbox".
	Channel string
	// BatchSize — сколько rows клейм'ить за один catch-up SELECT (default 32).
	BatchSize int
	// PollFallback — интервал poll'а на случай missed NOTIFY (default 30s).
	PollFallback time.Duration
	// MaxAttempts — отметка «poisoned», после которой drainer перестает ретраить
	//   (default 10). Permanent-error → force attempt_count = MaxAttempts, drainer пропускает.
	MaxAttempts int
	// BackoffMin/BackoffMax — exp-backoff bounds (default 1s..30s).
	BackoffMin time.Duration
	BackoffMax time.Duration
	// ApplyTimeout — таймаут на один Apply-вызов (default 5s). Используется
	//   также как graceful-grace при shutdown: in-flight Apply имеет
	//   non-cancellable inner ctx с этим deadline, чтобы row не осталась
	//   half-applied при ctx.Cancel parent-loop'а.
	ApplyTimeout time.Duration
}

// withDefaults заполняет нулевые поля конфигом по умолчанию.
func (c Config) withDefaults() Config {
	if c.BatchSize <= 0 {
		c.BatchSize = 32
	}
	if c.PollFallback <= 0 {
		c.PollFallback = 30 * time.Second
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 10
	}
	if c.BackoffMin <= 0 {
		c.BackoffMin = 1 * time.Second
	}
	if c.BackoffMax <= 0 {
		c.BackoffMax = 30 * time.Second
	}
	if c.ApplyTimeout <= 0 {
		c.ApplyTimeout = 5 * time.Second
	}
	return c
}

// Decoder[T] — превращает payload JSONB в типизированный T.
// Ошибка decoder-а трактуется как permanent (poisoned row), drainer не вызывает
// applier и помечает row attempt_count = MaxAttempts + last_error = err.
type Decoder[T any] func(payload []byte) (T, error)

// Applier[T] — применяет T к target-системе.
// Возвращает nil → success (drainer mark'ит sent_at).
// Возвращает ErrAlreadyApplied → idempotent success (drainer mark'ит sent_at).
// Возвращает любую другую error → transient (retry с exp backoff)
//
//	ИЛИ permanent (если errors.Is(err, ErrPermanent)).
type Applier[T any] func(ctx context.Context, eventType string, payload T) error

// ErrAlreadyApplied — applier возвращает, когда target-система сообщила «уже есть»
// (для OpenFGA: HTTP 409 на write existing tuple; HTTP 404 на delete missing tuple).
// Drainer трактует как success.
var ErrAlreadyApplied = errors.New("drainer: target reports already-applied (idempotent)")

// ErrPermanent — applier wrap'ит в это, если retry бессмыслен (HTTP 4xx не-409,
// malformed payload, etc). Drainer mark'ит last_error и пропускает row через
// force attempt_count = MaxAttempts.
var ErrPermanent = errors.New("drainer: permanent error, no retry")

// Drainer[T] — экземпляр drainer-а для одного outbox-table + один applier.
//
// Drainer работает по схеме:
//  1. Слушает LISTEN-канал `cfg.Channel` через dedicated pgx.Conn (hijacked
//     из pool).
//  2. На старте — catch-up: SELECT pending rows (sent_at IS NULL, attempt_count < MaxAttempts)
//     ORDER BY attempt_count, id LIMIT BatchSize → applies each (attempt_count-first
//     ordering предотвращает starvation свежего intent транзитно-залипшим backlog'ом).
//  3. Main loop: wake-up по NOTIFY (payload = row id) ИЛИ tick(PollFallback)
//     → claim → apply → mark.
//  4. Exactly-once: pre-claim атомарный UPDATE … RETURNING с CAS (sent_at IS NULL
//     AND attempt_count < MaxAttempts) — две реплики не возьмут одну row.
//  5. Graceful shutdown: при ctx.Done() — дозавершает текущий in-flight apply
//     (отдельный inner ctx с ApplyTimeout grace), exit.
type Drainer[T any] struct {
	cfg     Config
	pool    *pgxpool.Pool
	decoder Decoder[T]
	applier Applier[T]
	logger  *slog.Logger

	// onPoison, if set, is invoked once each time a row is poisoned (permanent
	// error / decode-fail). Used to drive the outbox_poisoned_total metric
	// without coupling the drainer to the metrics package.
	onPoison func()
}

// Option customises a Drainer at construction (functional-options pattern).
type Option[T any] func(*Drainer[T])

// WithPoisonObserver registers a callback invoked once per poisoned row. Wire it
// to a metrics recorder's IncPoisoned to make poison events observable
// (outbox_poisoned_total). nil is ignored.
func WithPoisonObserver[T any](fn func()) Option[T] {
	return func(d *Drainer[T]) {
		if fn != nil {
			d.onPoison = fn
		}
	}
}

// New создает Drainer; не запускает (вызывайте Run).
//
// pool — *pgxpool.Pool на БД сервиса (тот же pool, что используется для
// бизнес-логики; drainer Acquire().Hijack() один conn для LISTEN, остальные
// операции — через pool как обычно).
//
// decoder/applier — пользовательские функции, см. Decoder[T] / Applier[T].
//
// logger — slog.Logger; nil → slog.Default().
func New[T any](
	pool *pgxpool.Pool,
	cfg Config,
	decoder Decoder[T],
	applier Applier[T],
	logger *slog.Logger,
	opts ...Option[T],
) (*Drainer[T], error) {
	if pool == nil {
		return nil, errors.New("drainer.New: pool is nil")
	}
	if cfg.Table == "" {
		return nil, errors.New("drainer.New: Config.Table required")
	}
	if cfg.Channel == "" {
		return nil, errors.New("drainer.New: Config.Channel required")
	}
	if decoder == nil {
		return nil, errors.New("drainer.New: decoder is nil")
	}
	if applier == nil {
		return nil, errors.New("drainer.New: applier is nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	cfg = cfg.withDefaults()
	logger = logger.With(
		slog.String("component", "outbox_drainer"),
		slog.String("table", cfg.Table),
		slog.String("channel", cfg.Channel),
	)
	d := &Drainer[T]{
		cfg:     cfg,
		pool:    pool,
		decoder: decoder,
		applier: applier,
		logger:  logger,
	}
	for _, opt := range opts {
		opt(d)
	}
	return d, nil
}

// Run — основной loop drainer-а. Блокирует до ctx.Done().
//
// Поведение:
//  1. Запускает LISTEN-loop в goroutine (own conn, reconnect on drop).
//  2. Выполняет startup catch-up (drains all pending rows).
//  3. Основной select: NOTIFY-wake-up ИЛИ PollFallback-tick ИЛИ ctx.Done().
//     Каждое wake-up → drainBatch() (claim + apply + mark, в loop пока не пусто).
//  4. На ctx.Done() — дозавершает текущий drainBatch (с inner ApplyTimeout-grace
//     на in-flight apply), exits.
//
// Возвращает nil при clean shutdown.
func (d *Drainer[T]) Run(ctx context.Context) error {
	// Wake-up signal channel — listenLoop signals on NOTIFY, processLoop consumes.
	// Buffered: один сигнал «есть работа», даже если processLoop в данный
	// момент busy — он перепроверит после возврата.
	wakeup := make(chan struct{}, 1)

	// LISTEN-goroutine: own its own ctx tied to parent. Errors from LISTEN
	// subscription (conn drop, NOTIFY parse) are caught and re-tried with
	// exp-backoff inside listenLoop. Panics propagate to the runtime — drainer
	// is process-fatal on unhandled panic (correct: such panics indicate
	// programmer error, not transient infra failure).
	listenDone := make(chan struct{})
	go func() {
		defer close(listenDone)
		d.listenLoop(ctx, wakeup)
	}()

	// Стартовая попытка катч-апа — выгребаем все накопленное до начала LISTEN.
	// Если в этот момент LISTEN еще не подключился и кто-то INSERTит — мы либо
	// поймаем через NOTIFY (после connect), либо через PollFallback. Race ok.
	d.drainBatch(ctx)

	poll := time.NewTicker(d.cfg.PollFallback)
	defer poll.Stop()

	for {
		select {
		case <-ctx.Done():
			// Wait for listen-goroutine to exit (it will once ctx is done).
			<-listenDone
			return nil
		case <-wakeup:
			d.drainBatch(ctx)
		case <-poll.C:
			d.drainBatch(ctx)
		}
	}
}
