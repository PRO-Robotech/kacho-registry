// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package dataplane

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

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
	realm     string // IAM /token realm для WWW-Authenticate
	service   string // service-audience для WWW-Authenticate
	logger    *slog.Logger
}

// New собирает Handler. verifier==nil / authz==nil → breakglass-bypass соответствующей
// стадии (только аварийный режим); в штатном деплое обе стадии обязательны.
func New(verifier TokenVerifier, authz Authorizer, backend Backend, forwarder Forwarder, repoReg RepoRegistrar, regLookup RegistryLookup, realm, service string, logger *slog.Logger) *Handler {
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
		realm:     realm,
		service:   service,
		logger:    logger,
	}
}

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
func (h *Handler) serveBlob(w http.ResponseWriter, r *http.Request, p parsed, subject string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeNotFound(w)
		return
	}
	if !h.check(w, r, subject, relVGet, repositoryObject(p.registryID, p.repo)) {
		return
	}
	// blob-scope existence-hiding: блоб достижим только если входит в манифест(ы)
	// авторизованного repo (чужой content-addressable блоб → 404).
	in, err := h.backend.BlobInRepo(r.Context(), p.registryID, p.repo, p.reference)
	if err != nil {
		h.failClosed(w, "blob scope check failed", err)
		return
	}
	if !in {
		writeNotFound(w)
		return
	}
	h.forwarder.Forward(w, r)
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

	status := h.forwarder.Forward(w, r)

	// register-on-first-push: repo материализуется как authz-объект на первом
	// успешном manifest-PUT (parent-tuple ПЕРВЫМ + owner-tuple pushing-SA). Intent
	// несёт ParentProjectID реестра — иначе resource_mirror строка репо пустая и
	// iam-reconciler не материализует per-object v_* (репо непуллим даже владельцем).
	if !exists && p.route == routeManifest && r.Method == http.MethodPut && status >= 200 && status < 300 {
		projectID := h.resolveRegistryProject(ctx, p.registryID)
		intent := domain.RegisterIntentForRepoPush(p.registryID, p.repo, projectID, subject)
		if h.repoReg != nil {
			if rerr := h.repoReg.RegisterRepository(ctx, intent); rerr != nil {
				// Push успешен; register-intent durable-emit провалился (редкий DB-сбой).
				// Не рвём клиенту уже отданный ответ — логируем.
				h.logger.Error("register-on-first-push emit failed",
					"repo", p.registryID+"/"+p.repo, "err", rerr)
			}
		}
	}
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
// v_create на dst-repo. v_get(src)=deny → mount 404 (нельзя вытащить чужой блоб).
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
	allowedDst, err := h.checkAllowed(ctx, subject, relVCreate, repositoryObject(p.registryID, p.repo))
	if err != nil {
		h.failClosed(w, "mount dst check failed", err)
		return
	}
	if !allowedSrc || !allowedDst {
		writeNotFound(w) // exfil-guard: чужой блоб не монтируется (existence-hiding)
		return
	}
	h.forwarder.Forward(w, r)
}

// serveCatalog — GET /v2/_catalog: per-repo listauthz-фильтр полного zot-каталога
// (Check v_list на registry_repository:<full-name>) — межтенантно/межрепозиторно не
// течёт. Синтезирует отфильтрованный ответ, а не проксирует сырой каталог.
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
	visible := make([]string, 0, len(names))
	for _, full := range names {
		allowed, cerr := h.checkAllowed(r.Context(), subject, relVList, repositoryObjectFull(full))
		if cerr != nil {
			h.failClosed(w, "catalog filter check failed", cerr)
			return
		}
		if allowed {
			visible = append(visible, full)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"repositories": visible})
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

// writeError пишет минимальный OCI-error-body с нужным HTTP-статусом; сырых причин
// наружу не отдаём (defense-in-depth / existence-hiding).
func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"errors": []map[string]string{{"code": code, "message": message}},
	})
}
