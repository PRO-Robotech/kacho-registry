// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package operations — Long-Running Operations primitive: bounded Worker для
// async-исполнения мутаций + Repo для durable-перехода `done=false → true`.
//
// Operations.Run() — fire-and-trigger pattern: handler возвращает Operation
// клиенту сразу, фоновый worker делает реальную работу и durable-переводит
// строку в терминал.
//
// Bounded worker-pool (Worker type):
//   - Run() / RunWithWorker() кладут задачу в in-memory admission backlog и сразу
//     возвращают управление (async-контракт). Dispatcher-loop разбирает backlog,
//     ограничивая число одновременно ИСПОЛНЯЕМЫХ worker'ов семафором max-inflight
//     (burst не порождает unbounded-горутины). Backlog ограничен max-backlog: при
//     переполнении задача НЕ кладется в память — операция durable в БД и добирается
//     reconciler'ом (backpressure без OOM, без потери данных).
//   - Active() — текущее число исполняемых worker'ов; Wait(ctx) дренирует их на
//     graceful-shutdown; Ready() отражает живость dispatcher-loop (readiness probe).
//   - panic в fn перехватывается recover() → durable MarkError, процесс не падает.
//
// Durable terminal-write:
//   - финальные MarkDone/MarkError идут через retry+backoff (kacho-corelib/backoff)
//     поверх CAS-on-`done`; transient DB-сбой ретраится, метрики retries/failures
//     не проглатываются; при исчерпании budget строка остается done=false и
//     добирается reconciler'ом.
//
// Context-propagation (baggage):
//   - Worker НЕ наследует deadline / cancel callerCtx — request-ctx cancel-ится
//     сразу как handler возвращает Operation, а worker живет независимо.
//   - Worker НАСЛЕДУЕТ observability-values callerCtx (OTel SpanContext,
//     request-id, slog logger) через baggage.Extract — иначе worker-логи и
//     trace-span'ы оторваны от исходного запроса.
//   - Поверх worker-ctx накладывается собственный per-op deadline
//     (WithOperationTimeout, дефолт 4m < OrphanGrace): зависший peer-вынов не
//     удерживает слот семафора бесконечно — по timeout'у fn получает ctx.Done,
//     операция durable-помечается DeadlineExceeded.
package operations

import (
	"context"
	"errors"
	"log/slog"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho-corelib/backoff"
	"github.com/PRO-Robotech/kacho-corelib/baggage"
)

const (
	defaultMaxInflight = 64

	// defaultMaxBacklog — верхняя граница in-memory admission backlog'а. При
	// переполнении новая задача НЕ кладется в память: операция уже durable в БД
	// (создана до Run), поэтому ее добирает reconciler — это backpressure без
	// потери данных и без неограниченного роста памяти под устойчивой перегрузкой.
	defaultMaxBacklog = 10000

	defaultTWInitial  = 50 * time.Millisecond
	defaultTWMax      = 2 * time.Second
	defaultTWElapsed  = 30 * time.Second
	terminalWriteTime = 5 * time.Second // per-attempt timeout терминальной записи

	// defaultOpTimeout — верхняя граница исполнения одной operation-fn. Зависший
	// peer-вызов иначе держал бы слот семафора бесконечно (worker-ctx отрезан от
	// cancel/deadline через baggage.Extract) → исчерпание пула и блок dispatcher/
	// drain. Дефолт СТРОГО меньше Reconciler.OrphanGrace (5m): fn успевает
	// терминально завершиться (success/timeout) раньше, чем reconciler сочтет
	// строку orphan'ом — иначе долгая живая операция помечалась бы ERROR при уже
	// созданном ресурсе (phantom). Кастомный grace < 4m требует и WithOperationTimeout.
	defaultOpTimeout = 4 * time.Minute
)

// defaultRegistry — pkg-level worker tracker для backward-compatible Run()/Wait().
// Dispatcher стартует лениво на первом Run (без goroutine-side-effect при init).
var defaultRegistry = NewWorker()

// TerminalWriteConfig параметризует durable retry-loop терминальной записи.
type TerminalWriteConfig struct {
	InitialInterval time.Duration
	MaxInterval     time.Duration
	MaxElapsed      time.Duration // общий budget на ретраи; после — failure-метрика, done=false
}

func (c TerminalWriteConfig) withDefaults() TerminalWriteConfig {
	if c.InitialInterval <= 0 {
		c.InitialInterval = defaultTWInitial
	}
	if c.MaxInterval <= 0 {
		c.MaxInterval = defaultTWMax
	}
	if c.MaxElapsed <= 0 {
		c.MaxElapsed = defaultTWElapsed
	}
	return c
}

// WorkerOption — функциональная опция конфигурации Worker.
type WorkerOption func(*workerConfig)

type workerConfig struct {
	maxInflight int
	maxBacklog  int
	rec         Recorder
	log         *slog.Logger
	tw          TerminalWriteConfig
	opTimeout   time.Duration
}

// WithMaxInflight ограничивает число одновременно исполняемых worker'ов (burst
// сверх лимита ждет слот в in-memory backlog, ограниченном WithMaxBacklog). Дефолт — 64.
func WithMaxInflight(n int) WorkerOption {
	return func(c *workerConfig) {
		if n > 0 {
			c.maxInflight = n
		}
	}
}

// WithRecorder подключает sink метрик (inflight gauge, terminal-write retries/
// failures). nil → NopRecorder.
func WithRecorder(r Recorder) WorkerOption {
	return func(c *workerConfig) { c.rec = r }
}

// WithLogger подключает структурированный логгер (terminal-write failures, panic).
func WithLogger(l *slog.Logger) WorkerOption {
	return func(c *workerConfig) { c.log = l }
}

// WithTerminalWriteConfig настраивает retry-budget durable терминальной записи.
func WithTerminalWriteConfig(tw TerminalWriteConfig) WorkerOption {
	return func(c *workerConfig) { c.tw = tw }
}

// WithMaxBacklog ограничивает размер in-memory admission backlog'а. При
// переполнении новая задача не enqueue'ится в память (операция остается durable
// в БД и добирается reconciler'ом) — backpressure без OOM под перегрузкой.
// n<=0 → без ограничения. Дефолт — defaultMaxBacklog.
func WithMaxBacklog(n int) WorkerOption {
	return func(c *workerConfig) { c.maxBacklog = n }
}

// WithOperationTimeout задает верхнюю границу исполнения одной operation-fn.
// fn получает ctx с этим deadline; по истечении — DeadlineExceeded → durable
// MarkError, слот семафора освобождается. n<=0 игнорируется (остается дефолт
// defaultOpTimeout). Значение ДОЛЖНО быть строго меньше Reconciler.OrphanGrace
// (см. defaultOpTimeout) — иначе живая долгая операция может быть преждевременно
// помечена reconciler'ом как orphan.
func WithOperationTimeout(d time.Duration) WorkerOption {
	return func(c *workerConfig) {
		if d > 0 {
			c.opTimeout = d
		}
	}
}

// job — единица admission backlog'а.
type job struct {
	callerCtx context.Context
	repo      Repo
	opID      string
	fn        func(context.Context) (*anypb.Any, error)
}

// Worker — bounded координатор async worker-горутин.
//
// Назначение: graceful-shutdown сервиса не должен терять in-flight операции, а
// burst мутаций — не порождать unbounded-горутины. Dispatcher-loop разбирает
// in-memory backlog, ограничивая исполняемые worker'ы семафором max-inflight;
// терминальная запись durable (retry+CAS); readiness отражает живость loop'а.
type Worker struct {
	maxInflight int
	maxBacklog  int
	rec         Recorder
	log         *slog.Logger
	tw          TerminalWriteConfig
	opTimeout   time.Duration

	wg     sync.WaitGroup // outstanding работа (backlog + исполняемые) для Wait/drain
	active atomic.Int64   // число ИСПОЛНЯЕМЫХ worker'ов (Active / inflight gauge)

	mu      sync.Mutex
	backlog []job
	notify  chan struct{} // buffered(1) wake-сигнал dispatcher'у
	sem     chan struct{} // семафор, cap = maxInflight

	startOnce sync.Once
	stopOnce  sync.Once
	stopCh    chan struct{}
	dispDone  chan struct{}
	up        atomic.Bool // dispatcher-loop жив (readiness)

	configMu   sync.Mutex  // сериализует Configure с переходом «стартован»
	startGuard atomic.Bool // dispatcher хоть раз стартовал (Configure после этого запрещен)
}

// NewWorker — новый изолированный Worker. Опции настраивают max-inflight, метрики,
// логгер, retry-budget. Без опций — разумные дефолты (max-inflight 64).
// Dispatcher-loop стартует лениво на первом Run или явно через Start().
func NewWorker(opts ...WorkerOption) *Worker {
	cfg := workerConfig{maxInflight: defaultMaxInflight, maxBacklog: defaultMaxBacklog, opTimeout: defaultOpTimeout}
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.rec == nil {
		cfg.rec = NopRecorder{}
	}
	if cfg.log == nil {
		cfg.log = slog.Default()
	}
	cfg.tw = cfg.tw.withDefaults()
	return &Worker{
		maxInflight: cfg.maxInflight,
		maxBacklog:  cfg.maxBacklog,
		rec:         cfg.rec,
		log:         cfg.log,
		tw:          cfg.tw,
		opTimeout:   cfg.opTimeout,
		notify:      make(chan struct{}, 1),
		sem:         make(chan struct{}, cfg.maxInflight),
		stopCh:      make(chan struct{}),
		dispDone:    make(chan struct{}),
	}
}

// Start явно запускает dispatcher-loop (идемпотентно). Composition root зовет
// Start() на boot и подключает Ready() к readiness probe. Для тестов/back-compat
// первый Run стартует loop сам.
func (w *Worker) Start() { w.ensureStarted() }

// ErrWorkerStarted — Configure вызван после старта dispatcher-loop. Опции
// (Recorder/Logger/MaxInflight/retry-budget) применимы только ДО запуска worker'а:
// после старта dispatcher читает поля Worker без блокировки, поэтому менять их под
// ним — data race.
var ErrWorkerStarted = errors.New("operations: worker already started; configure before Start")

// Configure применяет опции к еще-не-стартованному Worker. Composition root зовет
// Configure ДО Start, чтобы подключить Prometheus-Recorder и логгер к worker'у
// (default-registry создается с NopRecorder — без Configure live-worker метрики
// мертвы). После Start — ErrWorkerStarted. Потокобезопасно: проверка «не стартован»
// и мутация полей идут под configMu, сериализуясь с ensureStarted.
func (w *Worker) Configure(opts ...WorkerOption) error {
	w.configMu.Lock()
	defer w.configMu.Unlock()
	if w.startGuard.Load() {
		return ErrWorkerStarted
	}
	cfg := workerConfig{maxInflight: w.maxInflight, maxBacklog: w.maxBacklog, rec: w.rec, log: w.log, tw: w.tw, opTimeout: w.opTimeout}
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.rec == nil {
		cfg.rec = NopRecorder{}
	}
	if cfg.log == nil {
		cfg.log = slog.Default()
	}
	cfg.tw = cfg.tw.withDefaults()
	w.maxInflight = cfg.maxInflight
	w.maxBacklog = cfg.maxBacklog
	w.rec = cfg.rec
	w.log = cfg.log
	w.tw = cfg.tw
	w.opTimeout = cfg.opTimeout
	// Семафор зависит от maxInflight; dispatcher еще не стартовал — пересоздать безопасно.
	w.sem = make(chan struct{}, cfg.maxInflight)
	return nil
}

func (w *Worker) ensureStarted() {
	w.startOnce.Do(func() {
		// startGuard под configMu сериализует с Configure: после старта dispatcher
		// читает поля без блокировки, поэтому Configure обязан увидеть «уже стартован»
		// и не мутировать поля под живым loop'ом. up выставляется СИНХРОННО (до
		// планирования goroutine), чтобы Ready() сразу после Start() возвращал true.
		w.configMu.Lock()
		w.startGuard.Store(true)
		w.up.Store(true)
		w.configMu.Unlock()
		go w.dispatch()
	})
}

// Active — текущее число исполняемых worker'ов (для observability / drain).
func (w *Worker) Active() int64 { return w.active.Load() }

// Ready отражает живость dispatcher-loop. NotReady, пока loop не запущен или
// остановлен — deployment не должен слать мутирующий трафик на под без живого
// dispatcher'а.
func (w *Worker) Ready() bool { return w.up.Load() }

// Wait блокируется пока вся принятая работа (backlog + исполняемые) не завершится,
// либо ctx истечет. Возвращает nil при штатном drain'е, ctx.Err() при таймауте.
// Задачи, не уложившиеся в окно drain'а, остаются durable (done=false) →
// добираются reconciler'ом на следующем старте.
func (w *Worker) Wait(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		w.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Stop останавливает dispatcher-loop (идемпотентно): новые задачи перестают
// диспетчеризоваться, Ready() → false. Уже исполняемые worker'ы дренируются
// отдельно через Wait(). Backlog не-стартовавших задач durable → reconciler.
func (w *Worker) Stop() {
	w.stopOnce.Do(func() {
		w.ensureStarted()
		close(w.stopCh)
		<-w.dispDone
	})
}

// runOn — постановка задачи в backlog + пробуждение dispatcher'а. Возвращает
// управление немедленно (async-контракт): handler не блокируется.
func (w *Worker) runOn(callerCtx context.Context, repo Repo, opID string, fn func(context.Context) (*anypb.Any, error)) {
	w.ensureStarted()
	w.mu.Lock()
	if w.maxBacklog > 0 && len(w.backlog) >= w.maxBacklog {
		// Backpressure: backlog переполнен. Операция уже durable в БД (создана до
		// Run) — не держим ее в памяти, reconciler добьет. Без потери данных.
		w.mu.Unlock()
		w.log.Warn("operation admission backlog full; deferring to reconciler",
			"op", opID, "max_backlog", w.maxBacklog)
		return
	}
	// wg.Add СИНХРОННО с приемом задачи (до возможного Wait): принятая работа
	// учитывается в drain'е с момента enqueue, а не с момента launch'а — иначе
	// Add из dispatcher-goroutine гонится с Wait (нарушение контракта WaitGroup).
	w.wg.Add(1)
	w.backlog = append(w.backlog, job{callerCtx: callerCtx, repo: repo, opID: opID, fn: fn})
	w.mu.Unlock()
	w.signal()
}

func (w *Worker) signal() {
	select {
	case w.notify <- struct{}{}:
	default: // буфер уже полон — dispatcher все равно дренирует весь backlog
	}
}

func (w *Worker) dequeue() (job, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.backlog) == 0 {
		return job{}, false
	}
	j := w.backlog[0]
	w.backlog[0] = job{} // освобождаем ссылки на ctx/closure
	if len(w.backlog) == 1 {
		w.backlog = nil
	} else {
		w.backlog = w.backlog[1:]
	}
	return j, true
}

// dispatch — единственный loop, разбирающий backlog под семафором max-inflight.
func (w *Worker) dispatch() {
	defer func() {
		w.up.Store(false)
		close(w.dispDone)
	}()
	for {
		for {
			j, ok := w.dequeue()
			if !ok {
				break
			}
			// Захват слота: блокируемся пока слот не освободится либо stop.
			select {
			case w.sem <- struct{}{}:
				w.launch(j)
			case <-w.stopCh:
				return
			}
		}
		select {
		case <-w.notify:
		case <-w.stopCh:
			return
		}
	}
}

// launch — старт исполняемого worker'а под уже захваченным слотом семафора.
// wg.Add сделан в runOn (enqueue); здесь — только inflight-учет и wg.Done в defer.
func (w *Worker) launch(j job) {
	n := w.active.Add(1)
	w.rec.SetInflight(float64(n))
	go func() {
		defer func() {
			n := w.active.Add(-1)
			w.rec.SetInflight(float64(n))
			<-w.sem // освобождаем слот
			w.wg.Done()
		}()
		w.execute(j)
	}()
}

// execute — исполнение fn с baggage-ctx, recover'ом panic и durable терминальной
// записью.
func (w *Worker) execute(j job) {
	// baggage.Extract сохраняет observability-values из callerCtx, но отрезает
	// deadline/cancel — worker автономен. Поверх накладываем собственный per-op
	// deadline: зависший fn иначе держал бы слот семафора бесконечно.
	workerCtx := baggage.Extract(j.callerCtx)
	if w.opTimeout > 0 {
		var cancel context.CancelFunc
		workerCtx, cancel = context.WithTimeout(workerCtx, w.opTimeout)
		defer cancel()
	}
	var resp *anypb.Any
	var err error

	func() {
		defer func() {
			if r := recover(); r != nil {
				w.log.Error("panic in operation worker",
					"op", j.opID, "panic", r, "stack", string(debug.Stack()))
				err = errWorkerPanic
			}
		}()
		resp, err = j.fn(workerCtx)
	}()

	if err != nil {
		st, ok := status.FromError(err)
		switch {
		case w.opTimeout > 0 && workerCtx.Err() == context.DeadlineExceeded && errors.Is(err, context.DeadlineExceeded):
			// Сработал per-op deadline — фиксированный DeadlineExceeded.
			st = status.New(codes.DeadlineExceeded, "operation timed out")
			w.log.Warn("operation timed out", "op", j.opID, "timeout", w.opTimeout)
		case !ok || st.Code() == codes.Unknown:
			// panic / unwrapped — фиксированный INTERNAL, raw-text наружу не течет.
			st = status.New(codes.Internal, "internal worker error")
		}
		w.terminalWrite(j.repo, j.opID, "MarkError", func(ctx context.Context) error {
			return j.repo.MarkError(ctx, j.opID, st.Proto())
		})
		return
	}
	w.terminalWrite(j.repo, j.opID, "MarkDone", func(ctx context.Context) error {
		return j.repo.MarkDone(ctx, j.opID, resp)
	})
}

var errWorkerPanic = errors.New("operations: worker panic")

// terminalWrite — durable терминальная запись: retry+backoff на transient DB-
// сбое, no-swallow при исчерпании budget (метрика + ERROR-лог), идемпотентность
// (ErrAlreadyDone → no-op: строку уже разрешил Cancel/reconciler).
func (w *Worker) terminalWrite(repo Repo, opID, opName string, write func(context.Context) error) {
	bo := backoff.ExponentialBackoffBuilder().
		WithInitialInterval(w.tw.InitialInterval).
		WithMaxInterval(w.tw.MaxInterval).
		WithMaxElapsedThreshold(w.tw.MaxElapsed).
		WithRandomizationFactor(0.2).
		Build()
	// Reset инициализирует startTime бюджета MaxElapsed «сейчас» — без него
	// первый NextBackOff сразу вернет Stop (elapsed считается от zero-time).
	bo.Reset()

	for {
		ctx, cancel := context.WithTimeout(context.Background(), terminalWriteTime)
		err := write(ctx)
		cancel()

		switch {
		case err == nil, errors.Is(err, ErrAlreadyDone):
			// success либо строка уже терминальна (CAS проиграл Cancel/reconciler) — no-op.
			return
		case errors.Is(err, ErrNotFound):
			// На worker-пути строка всегда существует — это не transient. Не ретраим.
			w.rec.IncTerminalWriteFailures(opName)
			w.log.Error("terminal write: operation row missing", "op", opID, "kind", opName)
			return
		}

		d := bo.NextBackOff()
		if d == backoff.Stop {
			w.rec.IncTerminalWriteFailures(opName)
			w.log.Error("terminal write failed after retries; row stays done=false (reconciler backstop)",
				"op", opID, "kind", opName, "err", err)
			return
		}
		w.rec.IncTerminalWriteRetries(opName)
		select {
		case <-time.After(d):
		case <-w.stopCh:
			// shutdown: прекращаем ретраи; durable row done=false → reconciler добьет.
			w.rec.IncTerminalWriteFailures(opName)
			w.log.Warn("terminal write interrupted by shutdown; reconciler will recover",
				"op", opID, "kind", opName)
			return
		}
	}
}

// Run — backward-compatible API: запускает worker в default-registry.
//
// callerCtx — request-context handler-а. Из него извлекаются observability-values
// (OTel SpanContext, request-id, slog logger) через baggage.Extract — они
// propagate'ятся в worker-ctx. worker НЕ наследует deadline/cancel callerCtx.
func Run(callerCtx context.Context, repo Repo, opID string, fn func(context.Context) (*anypb.Any, error)) {
	defaultRegistry.runOn(callerCtx, repo, opID, fn)
}

// RunWithWorker — вариант с явным Worker registry (тесты / явное wiring). Семантика
// callerCtx — как у Run.
func RunWithWorker(w *Worker, callerCtx context.Context, repo Repo, opID string, fn func(context.Context) (*anypb.Any, error)) {
	w.runOn(callerCtx, repo, opID, fn)
}

// ConfigureDefault применяет опции к package-level default-registry ДО старта его
// dispatcher-loop. Composition root зовет ConfigureDefault(WithRecorder(promRec),
// WithLogger(logger)) на boot — это подключает live-worker метрики (terminal-write
// retries/failures, inflight) к Prometheus. Должен предшествовать Start()/первому
// Run; после старта — ErrWorkerStarted. Backward-compat: без вызова ConfigureDefault/
// Start первый Run по-прежнему лениво стартует default-registry с NopRecorder.
func ConfigureDefault(opts ...WorkerOption) error { return defaultRegistry.Configure(opts...) }

// Start явно запускает dispatcher-loop default-registry (идемпотентно). Composition
// root зовет Start() на boot ПОСЛЕ ConfigureDefault и подключает Ready() к readiness
// probe — тогда readiness lro-worker зеленый до первого трафика (нет boot-deadlock
// «NotReady → нет Run → worker не стартует → NotReady навсегда»).
func Start() { defaultRegistry.Start() }

// Wait — pkg-level: дренирует исполняемые workers default-registry.
func Wait(ctx context.Context) error { return defaultRegistry.Wait(ctx) }

// Active — pkg-level: число исполняемых workers default-registry.
func Active() int64 { return defaultRegistry.Active() }

// Ready — pkg-level: живость dispatcher-loop default-registry.
func Ready() bool { return defaultRegistry.Ready() }

// ErrShutdownTimeout sentinel для caller'ов, отличающих "drain ok" vs "timeout".
var ErrShutdownTimeout = errors.New("operations: workers did not finish before shutdown timeout")
