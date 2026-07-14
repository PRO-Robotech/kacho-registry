// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package dataplane

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/PRO-Robotech/kacho-registry/internal/domain"
)

// Handler — data-plane HTTP-обработчик Docker Registry v2 / OCI Distribution:
// AuthN (Bearer-JWT по JWKS) → parse path → per-request Check → reverse-proxy в zot.
type Handler struct {
	verifier  TokenVerifier
	authz     Authorizer
	backend   Backend
	forwarder Forwarder
	repoReg   RepoRegistrar
	regLookup RegistryLookup
	uploads   UploadRecorder
	realm     string // IAM /token realm для WWW-Authenticate
	service   string // service-audience для WWW-Authenticate
	logger    *slog.Logger
}

// New собирает Handler. verifier==nil / authz==nil → breakglass-bypass соответствующей
// стадии (только аварийный режим); в штатном деплое обе стадии обязательны. uploads==nil
// → per-repo upload-tracking выключен (blob-finalize не пишет строку, push-time HEAD
// только-что-загруженного блоба останется 404 до появления манифеста — REG-33 не
// закрыт); в штатном деплое uploads обязателен.
func New(verifier TokenVerifier, authz Authorizer, backend Backend, forwarder Forwarder, repoReg RepoRegistrar, regLookup RegistryLookup, uploads UploadRecorder, realm, service string, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	if realm == "" {
		realm = "https://api.kacho.local/iam/token"
	}
	if service == "" {
		service = "registry.kacho.local"
	}
	return &Handler{
		verifier:  verifier,
		authz:     authz,
		backend:   backend,
		forwarder: forwarder,
		repoReg:   repoReg,
		regLookup: regLookup,
		uploads:   uploads,
		realm:     realm,
		service:   service,
		logger:    logger,
	}
}

// recordUploadTimeout — дедлайн синхронной durable-записи blob-finalize (REG-33).
// Запись обязана закоммититься ДО релея 2xx клиенту, поэтому исполняется на detached-
// контексте (WithoutCancel): даже если клиент отвалится, ожидая ответ, строка
// докоммитится (иначе retry-HEAD за 201 снова упрётся в 404). Собственный дедлайн
// ограничивает хвост при недоступной БД (fail-closed 503 — push ретраится).
const recordUploadTimeout = 10 * time.Second

// ServeHTTP реализует http.Handler. Порядок: AuthN (401-challenge fail-closed) →
// DELETE-блок (405) → parse (traversal → 400) → per-request authz → forward.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	subject, invalidToken, ok := h.authenticate(r)
	if !ok {
		h.challenge(w, invalidToken)
		return
	}

	// REG-35: data-plane HTTP-метод DELETE не проксируется — единственный путь
	// удаления — control-plane DeleteTag. Reject 405 ДО zot, независимо от прав.
	if r.Method == http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}

	p, err := parsePath(r.URL.EscapedPath())
	if err != nil {
		writeError(w, http.StatusBadRequest, "NAME_INVALID", "malformed path")
		return
	}

	fga := fgaSubject(subject)
	switch p.route {
	case routePing:
		h.writePing(w, r)
	case routeCatalog:
		h.serveCatalog(w, r, fga)
	case routeManifest:
		h.serveManifest(w, r, p, fga)
	case routeBlob:
		h.serveBlob(w, r, p, fga)
	case routeTagsList:
		h.servePullOnly(w, r, p, fga, relVList)
	case routeReferrers:
		h.servePullOnly(w, r, p, fga, relVGet)
	case routeUpload:
		h.servePush(w, r, p, fga)
	default:
		writeNotFound(w)
	}
}

// authenticate верифицирует Bearer-JWT. Возвращает (subject, invalidToken, ok):
// ok=false + invalidToken=false — токена нет/не Bearer; ok=false + invalidToken=true
// — токен есть, но не прошёл JWKS-верификацию (challenge с error="invalid_token").
// verifier==nil → breakglass bypass.
func (h *Handler) authenticate(r *http.Request) (subject string, invalidToken bool, ok bool) {
	if h.verifier == nil {
		return "bootstrap", false, true
	}
	raw, present := bearerToken(r)
	if !present {
		return "", false, false
	}
	sub, err := h.verifier.Verify(r.Context(), raw)
	if err != nil || sub == "" {
		return "", true, false
	}
	return sub, false, true
}

// serveManifest — pull (GET/HEAD, v_get) либо push (PUT/POST/PATCH). DELETE снят выше.
func (h *Handler) serveManifest(w http.ResponseWriter, r *http.Request, p parsed, subject string) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		h.servePullOnly(w, r, p, subject, relVGet)
	case http.MethodPut, http.MethodPost, http.MethodPatch:
		h.servePush(w, r, p, subject)
	default:
		writeNotFound(w)
	}
}

// serveBlob — pull блоба (GET/HEAD): v_get на repo + per-repo blob-scope (REG-37).
// Push блобов идёт через /blobs/uploads (routeUpload), не сюда.
//
// v_get-deny обрабатывается НЕ безусловным 404: на брошенном ещё-не-материализованном
// repo применяется push-context fallback (REG-33 Defect B, см. pushContextRevealsBlob) —
// иначе первый push зависает в дедлоке (blob HEAD 404 ⟸ repo не материализован ⟸ манифест
// не запушен ⟸ blob HEAD 404). На established repo v_get-deny остаётся 404 (existence-hiding).
func (h *Handler) serveBlob(w http.ResponseWriter, r *http.Request, p parsed, subject string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeNotFound(w)
		return
	}
	ctx := r.Context()
	allowed, err := h.checkAllowed(ctx, subject, relVGet, repositoryObject(p.registryID, p.repo))
	if err != nil {
		h.failClosed(w, "authorization check failed", err)
		return
	}
	if !allowed {
		// REG-33 Defect B (deadlock): per-object registry_repository authz материализуется
		// только на manifest-PUT (register-on-first-push), поэтому на первом push blob
		// HEAD/GET упирается в v_get-deny ДО манифеста. Раскрываем блоб ⟺ это доказуемо
		// push-in-progress того же тенанта (см. pushContextRevealsBlob); иначе 404.
		reveal, ferr := h.pushContextRevealsBlob(ctx, p, subject)
		if ferr != nil {
			h.failClosed(w, "push-context blob fallback check failed", ferr)
			return
		}
		if !reveal {
			writeNotFound(w) // deny + не push-context → 404 (existence-hiding сохранён)
			return
		}
		h.forwarder.Forward(w, r)
		return
	}
	// v_get прошёл (established repo) — blob-scope existence-hiding: блоб достижим только
	// если входит в манифест(ы) авторизованного repo (чужой content-addressable блоб → 404).
	in, err := h.backend.BlobInRepo(ctx, p.registryID, p.repo, p.reference)
	if err != nil {
		h.failClosed(w, "blob scope check failed", err)
		return
	}
	if !in {
		// REG-33 Defect A: блоба ещё нет ни в одном манифесте repo. На первом push
		// блобы пишутся ДО манифеста, поэтому только-что-загруженный слой не в манифесте,
		// но docker HEAD'ит его сразу за 201. Раскрываем блоб ⟺ авторизованный writer
		// реально загрузил ЭТОТ digest в ЭТОТ repo в пределах freshness-TTL (durable
		// pending-blob record). REG-37 сохранён: zot дедуплицирует блобы глобально, но
		// раскрываются только блобы, которые writer доказуемо загрузил в этот repo (zot
		// проверил digest на finalize) — подделать запись под чужой контент нельзя.
		uploaded, uerr := h.blobUploadedToRepo(ctx, p.registryID, p.repo, p.reference)
		if uerr != nil {
			h.failClosed(w, "pending blob check failed", uerr)
			return
		}
		if !uploaded {
			writeNotFound(w)
			return
		}
	}
	h.forwarder.Forward(w, r)
}

// pushContextRevealsBlob решает, раскрыть ли blob HEAD/GET на ветке v_get-deny (REG-33
// Defect B — deadlock-фикс первого push). Возвращает true ТОЛЬКО если ВСЕ три условия
// выполнены одновременно:
//
//	(a) repo ещё НЕ материализован как tagged repo (RepoExists=false) — first-push in
//	    progress; у established repo v_get уже прошёл бы и сюда бы не зашли, а если
//	    v_get-deny на established repo — это ЛЕГИТИМНЫЙ deny (revoke/чужой), не дедлок;
//	(b) caller держит v_create@registry_registry (namespace) — то же право, что
//	    авторизовало blob-upload в servePush; доказывает push-authority того же
//	    проекта/тенанта на ЭТОТ registry (cross-tenant caller его не держит);
//	(c) ЭТОТ digest доказуемо загружен в ЭТОТ repo в пределах TTL (REG-33 durable
//	    pending-blob record) — writer владеет контентом (zot проверил digest на finalize).
//
// Все три вместе раскрывают ТОЛЬКО собственный только-что-загруженный блоб в собственном
// новом repo. REG-37 сохранён: другой тенант не держит v_create на этот registry →
// fallback denies → 404 (cross-tenant content-addressable leak невозможен). После
// manifest-PUT register-on-first-push материализует repo → v_get проходит штатно →
// fallback больше не нужен (нулевая добавленная стоимость на established pull-пути).
//
// Порядок условий short-circuit'ит по возрастанию стоимости и security-строгости: сначала
// дешёвый RepoExists (established → выход без Check), затем v_create-Check (cross-tenant →
// выход без pending-запроса), затем pending-record.
func (h *Handler) pushContextRevealsBlob(ctx context.Context, p parsed, subject string) (bool, error) {
	exists, err := h.backend.RepoExists(ctx, p.registryID, p.repo)
	if err != nil {
		return false, err
	}
	if exists {
		return false, nil // established repo — v_get-deny легитимен (не first-push дедлок)
	}
	allowed, err := h.checkAllowed(ctx, subject, relVCreate, registryObject(p.registryID))
	if err != nil {
		return false, err
	}
	if !allowed {
		return false, nil // caller не может пушить в этот registry — cross-tenant → 404
	}
	return h.blobUploadedToRepo(ctx, p.registryID, p.repo, p.reference)
}

// blobUploadedToRepo — консультируется с durable pending-blob record (REG-33): был ли
// <digest> загружен в <registryID>/<repo> в пределах TTL. uploads==nil (upload-tracking
// выключен) → false (не раскрываем без подтверждённого аплоада).
func (h *Handler) blobUploadedToRepo(ctx context.Context, registryID, repo, digest string) (bool, error) {
	if h.uploads == nil {
		return false, nil
	}
	return h.uploads.BlobUploaded(ctx, registryID, repo, digest)
}

// servePullOnly — read-путь (manifest GET/HEAD, tags/list, referrers): single Check
// на repo-объект + forward. Deny → 404 (existence-hiding).
func (h *Handler) servePullOnly(w http.ResponseWriter, r *http.Request, p parsed, subject, relation string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeNotFound(w)
		return
	}
	if !h.check(w, r, subject, relation, repositoryObject(p.registryID, p.repo)) {
		return
	}
	h.forwarder.Forward(w, r)
}

// registerPushTimeout — дедлайн detached-контекста register-on-first-push. Работа
// исполняется на пути ответа ПОСЛЕ Forward, поэтому отвязана от отмены r.Context()
// (закрытие соединения клиентом до коммита registry_outbox иначе теряет owner/
// parent-tuple без ретрая). Собственный дедлайн ограничивает post-response-хвост.
const registerPushTimeout = 10 * time.Second

// servePush — push-путь (blob-upload / manifest-PUT). verb-map: repo существует →
// v_update@registry_repository; repo новый → v_create@registry_registry (право
// создавать repo в namespace). cross-repo mount — отдельный exfil-guard (два Check).
// На успешном manifest-PUT нового repo → register-on-first-push.
func (h *Handler) servePush(w http.ResponseWriter, r *http.Request, p parsed, subject string) {
	ctx := r.Context()

	// cross-repo blob mount: POST /blobs/uploads/?mount=<digest>&from=<reg/src>.
	if p.route == routeUpload && r.Method == http.MethodPost {
		if from := r.URL.Query().Get("from"); r.URL.Query().Get("mount") != "" && from != "" {
			h.serveMount(w, r, p, subject, from)
			return
		}
	}

	exists, err := h.backend.RepoExists(ctx, p.registryID, p.repo)
	if err != nil {
		h.failClosed(w, "repo existence check failed", err)
		return
	}

	var relation, object string
	if exists {
		relation, object = relVUpdate, repositoryObject(p.registryID, p.repo)
	} else {
		relation, object = relVCreate, registryObject(p.registryID)
	}
	if !h.check(w, r, subject, relation, object) {
		return
	}

	// REG-33 Defect A: blob PUT/POST-finalize (routeUpload с ?digest=<d>) обязан durable-
	// записать (registryID, repo, digest) ДО релея 2xx клиенту — иначе docker HEAD сразу
	// за 201 упрётся в 404 (блоб ещё не в манифесте). Буферизуем (пустой) ответ zot,
	// на 2xx пишем строку, затем релеим. Прочие push-запросы (POST upload-init, PATCH
	// chunk, manifest PUT) идут прежним стриминговым Forward.
	if isBlobFinalize(p, r) {
		h.forwardBlobFinalize(w, r, p)
		return
	}

	status := h.forwarder.Forward(w, r)

	// register-on-first-push: repo материализуется как authz-объект на первом
	// успешном manifest-PUT (parent-tuple ПЕРВЫМ + owner-tuple pushing-SA). Intent
	// несёт ParentProjectID реестра — иначе resource_mirror строка репо пустая и
	// iam-reconciler не материализует per-object v_* (репо непуллим даже владельцем).
	if !exists && p.route == routeManifest && r.Method == http.MethodPut && status >= 200 && status < 300 {
		// Эта работа идёт ПОСЛЕ Forward — ответ клиенту уже отдан. r.Context()
		// отменяется в момент, когда клиент закрывает соединение, а single-shot
		// docker/CI push рвёт connection сразу за 201 → cancellable ctx погиб бы
		// ДО коммита registry_outbox-транзакции, безвозвратно потеряв owner/parent
		// FGA-tuple (drainer реплеит только закоммиченные строки → репо непуллим
		// даже владельцем, без ретрая). Отвязываем от отмены запроса (как LRO-
		// воркеры) и даём собственный дедлайн на durable-emit + project-lookup.
		bgCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), registerPushTimeout)
		defer cancel()
		projectID := h.resolveRegistryProject(bgCtx, p.registryID)
		intent := domain.RegisterIntentForRepoPush(p.registryID, p.repo, projectID, subject)
		if h.repoReg != nil {
			if rerr := h.repoReg.RegisterRepository(bgCtx, intent); rerr != nil {
				// Push успешен; register-intent durable-emit провалился (редкий DB-сбой).
				// Не рвём клиенту уже отданный ответ — логируем.
				h.logger.Error("register-on-first-push emit failed",
					"repo", p.registryID+"/"+p.repo, "err", rerr)
			}
		}
	}
}

// isBlobFinalize распознаёт blob PUT/POST-finalize: routeUpload с непустым ?digest=.
// Это единственный push-запрос, материализующий блоб в repo (монолитный POST?digest
// либо PUT?digest после PATCH-чанков). Mount (POST ?mount=&from=) сюда не попадает —
// он несёт ?mount=, а не ?digest, и перехвачен early-return serveMount выше.
func isBlobFinalize(p parsed, r *http.Request) bool {
	if p.route != routeUpload {
		return false
	}
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		return false
	}
	return r.URL.Query().Get("digest") != ""
}

// forwardBlobFinalize проксирует blob-finalize БУФЕРИЗОВАННО (ForwardCapture) и на
// успех (2xx) синхронно durable-записывает (registryID, repo, digest) ДО релея ответа
// клиенту — чтобы немедленный HEAD за 201 гарантированно нашёл строку (REG-33 Defect A).
// Запись идёт на detached-контексте (WithoutCancel): даже если клиент отвалится, ожидая
// ответ, строка докоммитится (не-detached write отменился бы → retry-HEAD снова 404).
// Сбой записи → fail-closed 503 (201 НЕ релеится): нельзя отдать 2xx, чей блоб мы не
// можем стабильно раскрыть по HEAD — иначе Defect A вернётся. Push ретраит upload
// (идемпотентно: zot дедуплицирует блоб). uploads==nil → трекинг выключен, просто релей.
func (h *Handler) forwardBlobFinalize(w http.ResponseWriter, r *http.Request, p parsed) {
	digest := r.URL.Query().Get("digest")
	captured := h.forwarder.ForwardCapture(r)

	twoXX := captured.Status >= 200 && captured.Status < 300
	if twoXX && h.uploads != nil {
		recCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), recordUploadTimeout)
		rerr := h.uploads.RecordUploadedBlob(recCtx, p.registryID, p.repo, digest)
		cancel()
		if rerr != nil {
			// Блоб в zot есть (2xx), но pending-строку записать не удалось. Отдать 201
			// нельзя: следующий HEAD вернул бы 404 (реинтро Defect A). Fail-closed.
			h.failClosed(w, "record uploaded blob failed", rerr)
			return
		}
	}
	writeCaptured(w, captured)
}

// resolveRegistryProject резолвит owning-project реестра для containment scope
// register-intent. regLookup==nil → "" (best-effort, интент без project). Ошибка
// lookup'а на этом post-response пути логируется; интент всё равно эмитится (хотя бы
// структурный parent-tuple), не регрессируя ниже прежнего поведения.
func (h *Handler) resolveRegistryProject(ctx context.Context, registryID string) string {
	if h.regLookup == nil {
		return ""
	}
	projectID, err := h.regLookup.RegistryProjectID(ctx, registryID)
	if err != nil {
		h.logger.Error("register-on-first-push project lookup failed",
			"registry", registryID, "err", err)
		return ""
	}
	return projectID
}

// serveMount — cross-repo blob mount exfil-guard: ДВА Check — v_get на src-repo И
// write-verb на dst-repo — ПЛЮС blob-scope членство digest'а в src-repo (REG-37,
// как serveBlob). v_get(src)=deny → mount 404 (нельзя вытащить чужой блоб); digest не
// член src-repo → тоже 404 (zot не изолирует content-addressable блобы по repo).
// dst-verb зеркалит servePush: существующий dst-repo → v_update@registry_repository,
// новый → v_create@registry_registry (право создавать repo в namespace).
func (h *Handler) serveMount(w http.ResponseWriter, r *http.Request, p parsed, subject, from string) {
	if strings.Contains(from, "..") {
		writeError(w, http.StatusBadRequest, "NAME_INVALID", "malformed mount source")
		return
	}
	ctx := r.Context()
	allowedSrc, err := h.checkAllowed(ctx, subject, relVGet, repositoryObjectFull(from))
	if err != nil {
		h.failClosed(w, "mount src check failed", err)
		return
	}
	// dst verb-map зеркалит servePush: mount пишет блоб в dst-repo, поэтому существующий
	// repo гейтится v_update@registry_repository, новый — v_create@registry_registry.
	// Хардкод v_create@registry_repository расходился бы с push-путём (verb-mismatch):
	// namespace-creator не прошёл бы mount в новый repo, а v_create-only принципал писал
	// бы в существующий repo мимо v_update.
	dstExists, err := h.backend.RepoExists(ctx, p.registryID, p.repo)
	if err != nil {
		h.failClosed(w, "mount dst existence check failed", err)
		return
	}
	dstRelation, dstObject := relVCreate, registryObject(p.registryID)
	if dstExists {
		dstRelation, dstObject = relVUpdate, repositoryObject(p.registryID, p.repo)
	}
	allowedDst, err := h.checkAllowed(ctx, subject, dstRelation, dstObject)
	if err != nil {
		h.failClosed(w, "mount dst check failed", err)
		return
	}
	if !allowedSrc || !allowedDst {
		writeNotFound(w) // exfil-guard: чужой блоб не монтируется (existence-hiding)
		return
	}
	// REG-37 mount blob-scope: v_get(src) доказывает доступ к src-repo, но zot НЕ
	// изолирует блобы по repo (content-addressable глобальны) — точно как в serveBlob.
	// Поэтому дополнительно проверяем, что монтируемый digest реально входит в src-repo;
	// иначе принципал с легальным доступом к своим src/dst смонтировал бы чужой
	// глобальный блоб (cross-tenant exfil). non-member → 404 (existence-hiding).
	fromRegistryID, fromRepo, ok := strings.Cut(from, "/")
	if !ok {
		writeNotFound(w) // from без repo-сегмента не адресует реальный блоб
		return
	}
	in, err := h.backend.BlobInRepo(ctx, fromRegistryID, fromRepo, r.URL.Query().Get("mount"))
	if err != nil {
		h.failClosed(w, "mount blob scope check failed", err)
		return
	}
	if !in {
		writeNotFound(w)
		return
	}
	h.forwarder.Forward(w, r)
}

// catalogMaxPageSize — жёсткий потолок числа сырых repo-имён, обрабатываемых за один
// _catalog-запрос (и, значит, число per-repo authz-Check). Применяется ВСЕГДА, даже
// без `?n=` — иначе один дешёвый GET /v2/_catalog развернулся бы в N последовательных
// iam.Check по всему кросс-тенантному каталогу (N = глобальное число репо, которое
// вызывающий не контролирует; CWE-770/400 self-amplifying DoS).
const catalogMaxPageSize = 1000

// catalogAuthzConcurrency — верхняя граница параллельных authz-Check при фильтрации
// одной страницы _catalog (bound fan-out в iam, как blob-scope в zot-адаптере).
const catalogAuthzConcurrency = 8

// serveCatalog — GET /v2/_catalog: per-repo listauthz-фильтр zot-каталога (Check
// v_list на registry_repository:<full-name>) — межтенантно/межрепозиторно не течёт.
// Синтезирует отфильтрованный ответ, а не проксирует сырой каталог. OCI-пагинация
// `n=`/`last=` ограничивает окно ДО authz-цикла (bounded Check-count), Check'и окна —
// bounded-concurrency; при усечении отдаётся Link: rel="next".
//
// Курсор `last=` — ОПАКОВЫЙ offset (base64 позиции в отсортированном каталоге), а НЕ
// сырое имя репо: echo pageSize-го имени окна раскрыл бы вызывающему имена чужих репо
// (за пределами его per-repo v_list) — existence-oracle. Offset ничего не именует, но
// доводит пагинацию до всех разрешённых репо даже через полностью-отфильтрованные окна
// (OCI-клиент следует URL из Link как есть, поэтому непрозрачный `last` совместим).
func (h *Handler) serveCatalog(w http.ResponseWriter, r *http.Request, subject string) {
	if r.Method != http.MethodGet {
		writeNotFound(w)
		return
	}
	names, err := h.backend.CatalogRepoNames(r.Context())
	if err != nil {
		h.failClosed(w, "catalog read failed", err)
		return
	}

	pageSize := parseCatalogPageSize(r.URL.Query().Get("n"))
	window, nextOffset, more := catalogWindow(names, r.URL.Query().Get("last"), pageSize)

	// Bounded-concurrency authz-фильтр окна; результат собирается в порядке имён
	// (indexed slice) — детерминированная сортировка сохраняется.
	allowedFlags := make([]bool, len(window))
	g, gctx := errgroup.WithContext(r.Context())
	g.SetLimit(catalogAuthzConcurrency)
	for i, full := range window {
		i, full := i, full
		g.Go(func() error {
			allowed, cerr := h.checkAllowed(gctx, subject, relVList, repositoryObjectFull(full))
			if cerr != nil {
				return cerr
			}
			allowedFlags[i] = allowed
			return nil
		})
	}
	if werr := g.Wait(); werr != nil {
		h.failClosed(w, "catalog filter check failed", werr)
		return
	}

	visible := make([]string, 0, len(window))
	for i, full := range window {
		if allowedFlags[i] {
			visible = append(visible, full)
		}
	}

	if more && len(window) > 0 {
		next := "/v2/_catalog?" + url.Values{
			"n":    []string{strconv.Itoa(pageSize)},
			"last": []string{encodeCatalogCursor(nextOffset)},
		}.Encode()
		w.Header().Set("Link", `<`+next+`>; rel="next"`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"repositories": visible})
}

// parseCatalogPageSize разбирает OCI `n=` (размер страницы _catalog). Пусто/битое/
// ≤0 → потолок catalogMaxPageSize; больше потолка → потолок (кламп, чтобы клиент не
// снял границу Check-count). Возвращает всегда положительное значение в [1..max].
func parseCatalogPageSize(n string) int {
	if n == "" {
		return catalogMaxPageSize
	}
	v, err := strconv.Atoi(n)
	if err != nil || v <= 0 || v > catalogMaxPageSize {
		return catalogMaxPageSize
	}
	return v
}

// catalogWindow выделяет страницу из отсортированных имён по ОПАКОВОМУ offset-курсору
// (last — base64 позиции, не имя репо: см. serveCatalog — echo сырого имени течёт
// existence-oracle). Берёт до pageSize имён от offset; nextOffset — позиция после
// окна (следующий курсор), more=true, если за окном остались имена. Пустой/битый/
// вне-диапазона курсор → clamp в [0..len] (fail-safe рестарт, без leak/паники). names
// ожидается отсортированным (CatalogRepoNames сортирует).
func catalogWindow(names []string, last string, pageSize int) (window []string, nextOffset int, more bool) {
	start := decodeCatalogCursor(last)
	if start < 0 {
		start = 0
	}
	if start > len(names) {
		start = len(names)
	}
	rest := names[start:]
	if len(rest) > pageSize {
		return rest[:pageSize], start + pageSize, true
	}
	return rest, start + len(rest), false
}

// encodeCatalogCursor кодирует offset в опаковый base64-курсор (`last=`). Не несёт
// имён репо — только позицию в отсортированном каталоге.
func encodeCatalogCursor(offset int) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(offset)))
}

// decodeCatalogCursor разбирает опаковый offset-курсор. Пусто/битьё → 0 (рестарт с
// начала — безопасно: leak'а нет, лишь повторный листинг).
func decodeCatalogCursor(cursor string) int {
	if cursor == "" {
		return 0
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0
	}
	off, err := strconv.Atoi(string(raw))
	if err != nil {
		return 0
	}
	return off
}

// check — single per-request Check против repo/namespace-объекта. allow → true
// (caller форвардит); deny → 404 (existence-hiding); az-error → fail-closed 503.
// authz==nil (breakglass) → allow. Возвращает false, если ответ уже записан.
func (h *Handler) check(w http.ResponseWriter, r *http.Request, subject, relation, object string) bool {
	allowed, err := h.checkAllowed(r.Context(), subject, relation, object)
	if err != nil {
		h.failClosed(w, "authorization check failed", err)
		return false
	}
	if !allowed {
		writeNotFound(w) // deny → 404 (не раскрываем существование чужого объекта)
		return false
	}
	return true
}

// checkAllowed — тонкая обёртка Authorizer.Check. authz==nil → allow (breakglass).
func (h *Handler) checkAllowed(ctx context.Context, subject, relation, object string) (bool, error) {
	if h.authz == nil {
		return true, nil
	}
	return h.authz.Check(ctx, subject, relation, object)
}

// failClosed — недоступность зависимости (iam.Check / zot-интроспекция): fail-closed
// 503 (не пропускаем «на всякий случай»). Причина — только в лог, наружу не течёт.
func (h *Handler) failClosed(w http.ResponseWriter, msg string, err error) {
	h.logger.Warn("data-plane fail-closed", "reason", msg, "err", err)
	writeError(w, http.StatusServiceUnavailable, "UNAVAILABLE", "service unavailable")
}

// writePing — GET /v2/ handshake (клиент уже аутентифицирован).
func (h *Handler) writePing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeNotFound(w)
		return
	}
	w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("{}"))
}

// challenge — 401 c WWW-Authenticate: Bearer realm=<IAM /token>,service=<audience>.
// invalidToken=true (токен есть, но не прошёл верификацию) → добавляет
// error="invalid_token" (клиент вынужден пере-логиниться).
func (h *Handler) challenge(w http.ResponseWriter, invalidToken bool) {
	challenge := `Bearer realm="` + h.realm + `",service="` + h.service + `"`
	if invalidToken {
		challenge += `,error="invalid_token"`
	}
	w.Header().Set("WWW-Authenticate", challenge)
	writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
}

// bearerToken извлекает токен из "Authorization: Bearer <token>" (схема
// case-insensitive). present=false — заголовка нет либо не Bearer.
func bearerToken(r *http.Request) (token string, present bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", false
	}
	const scheme = "bearer "
	if len(auth) <= len(scheme) || !strings.EqualFold(auth[:len(scheme)], scheme) {
		return "", false
	}
	return strings.TrimSpace(auth[len(scheme):]), true
}

// writeNotFound — 404 existence-hiding (deny / несуществующий namespace/repo/блоб).
func writeNotFound(w http.ResponseWriter) {
	writeError(w, http.StatusNotFound, "NAME_UNKNOWN", "not found")
}

// writeCaptured релеит буферизованный ответ zot (ForwardCapture) клиенту: копирует
// заголовки, пишет статус и тело. Вызывается ПОСЛЕ durable-побочки blob-finalize
// (RecordUploadedBlob закоммичен) — так немедленный HEAD за 201 гарантированно видит
// строку (REG-33 Defect A). Заголовки zot (напр. Location/Docker-Content-Digest)
// сохраняются 1:1 — docker полагается на них при финализации блоба.
func writeCaptured(w http.ResponseWriter, cr CapturedResponse) {
	for k, vs := range cr.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	if cr.Status == 0 {
		cr.Status = http.StatusOK
	}
	w.WriteHeader(cr.Status)
	_, _ = w.Write(cr.Body)
}

// writeError пишет минимальный OCI-error-body с нужным HTTP-статусом; сырых причин
// наружу не отдаём (defense-in-depth / existence-hiding).
func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"errors": []map[string]string{{"code": code, "message": message}},
	})
}
