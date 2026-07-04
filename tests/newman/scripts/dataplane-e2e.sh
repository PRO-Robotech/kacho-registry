#!/usr/bin/env bash

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

# tests/newman/scripts/dataplane-e2e.sh — data-plane (:8080) OCI authz corner-case
# harness для kacho-registry. Гоняет реальный Docker Registry v2 / OCI Distribution
# поток (raw HTTP + Bearer-токен из iam /iam/token) против живого стека (fe3455) и
# проверяет authz-инварианты data-plane: 401-challenge без токена, existence-hiding
# (deny → 404), register-on-first-push, запрет деструктивного DELETE на data-plane
# (405, удаление — только control-plane DeleteTag), URL-encoded traversal guard (400).
#
# Токены НЕ минтятся здесь (SA-key показывается один раз при создании): caller
# передаёт CLIENT_ID + путь к приватному PEM. Harness лишь брокерит identity-JWT
# у шима /iam/token (Basic client_id:PEM → Hydra client_credentials → identity-JWT).
#
# Параметризация (env):
#   REG_TOKEN_URL   базовый URL шима iam /token (:9096), к нему добавляется /iam/token
#   DATAPLANE_URL   базовый URL data-plane OCI-прокси (:8080)
#   CLIENT_ID       OAuth client_id SA-ключа (из IssueSAKey, show-once)
#   SA_KEY_PEM      путь к приватному PEM SA-ключа (из IssueSAKey, show-once)
#   REGISTRY_ID     id реестра-namespace (reg…) с гранта push/pull на caller-SA
#   ADMIN_JWT       (опц.) Bearer control-plane для cross-check ListRepositories
#   GATEWAY_URL     (опц.) базовый URL api-gateway REST для control-plane cross-check
#   RUN             (опц.) суффикс изоляции прогона; иначе 1-й арг; иначе date +%s
#
# Вызов:
#   REG_TOKEN_URL=http://localhost:9096 DATAPLANE_URL=http://localhost:8080 \
#   CLIENT_ID=sva… SA_KEY_PEM=/path/sa.pem REGISTRY_ID=reg… \
#   ADMIN_JWT="$JWT" GATEWAY_URL=http://localhost:38080 \
#   ./scripts/dataplane-e2e.sh 1720000000
#
# Exit-код: ненулевой, если провалена ЛЮБАЯ hard-assertion (401/200/202/201/405/400).
# Documented-only проверки (существование-hiding для non-granted principal, control-
# plane cross-check при пустом ADMIN_JWT/GATEWAY_URL) НЕ роняют exit-код — печатают DOC.

set -uo pipefail

# ---------------------------------------------------------------------------
# Параметры прогона
# ---------------------------------------------------------------------------
RUN="${RUN:-${1:-}}"
if [[ -z "$RUN" ]]; then
  RUN="$(date +%s 2>/dev/null || echo manual)"
fi

REG_TOKEN_URL="${REG_TOKEN_URL:-http://localhost:9096}"
DATAPLANE_URL="${DATAPLANE_URL:-http://localhost:8080}"
GATEWAY_URL="${GATEWAY_URL:-}"
ADMIN_JWT="${ADMIN_JWT:-}"
SERVICE_AUD="${SERVICE_AUD:-registry.kacho.local}"

# strip trailing slashes для предсказуемой конкатенации URL
REG_TOKEN_URL="${REG_TOKEN_URL%/}"
DATAPLANE_URL="${DATAPLANE_URL%/}"
GATEWAY_URL="${GATEWAY_URL%/}"

REPO="e2e-app-${RUN}"
TAG="v1"

fail_env() { echo "FATAL: missing required env $1" >&2; exit 2; }
[[ -n "${CLIENT_ID:-}" ]]   || fail_env CLIENT_ID
[[ -n "${SA_KEY_PEM:-}" ]]  || fail_env SA_KEY_PEM
[[ -n "${REGISTRY_ID:-}" ]] || fail_env REGISTRY_ID
[[ -f "$SA_KEY_PEM" ]]      || { echo "FATAL: SA_KEY_PEM not a file: $SA_KEY_PEM" >&2; exit 2; }
command -v curl    >/dev/null || { echo "FATAL: curl not found"    >&2; exit 2; }
command -v python3 >/dev/null || { echo "FATAL: python3 not found" >&2; exit 2; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/reg-dpe2e.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
BODY="$TMP/body"
HDR="$TMP/hdr"

HARD_FAILS=0
DOC_NOTES=0

echo "=== kacho-registry data-plane OCI e2e ==="
echo "  run=$RUN  registry=$REGISTRY_ID  repo=$REPO:$TAG"
echo "  token-url=$REG_TOKEN_URL  dataplane=$DATAPLANE_URL"
echo

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

# do_req METHOD URL [curl-args…] — тело → $BODY, заголовки → $HDR, echo HTTP-код
# (на сетевом сбое curl печатает "000" через -w; пустой вывод → "000").
do_req() {
  local method="$1" url="$2"; shift 2
  local code
  code="$(curl -sS --path-as-is -o "$BODY" -D "$HDR" -w '%{http_code}' \
    -X "$method" "$url" "$@" 2>/dev/null)"
  echo "${code:-000}"
}

# assert_hard LABEL ACTUAL EXPECTED… — PASS если ACTUAL совпал с одним из EXPECTED;
# иначе FAIL + инкремент HARD_FAILS.
assert_hard() {
  local label="$1" actual="$2"; shift 2
  local e
  for e in "$@"; do
    if [[ "$actual" == "$e" ]]; then
      echo "PASS [hard] $label — HTTP $actual"
      return 0
    fi
  done
  echo "FAIL [hard] $label — HTTP $actual (expected: $*)"
  HARD_FAILS=$((HARD_FAILS + 1))
  return 1
}

# doc_note LABEL … — печатает документирующую (не-hard) строку.
doc_note() {
  echo "DOC  [documented-only] $*"
  DOC_NOTES=$((DOC_NOTES + 1))
}

# body_contains STR — 0 если тело $BODY содержит STR.
body_contains() { grep -qF -- "$1" "$BODY"; }

# ---------------------------------------------------------------------------
# 1. Mint identity-JWT: POST {REG_TOKEN_URL}/iam/token?service=… Basic(client_id:PEM)
# ---------------------------------------------------------------------------
echo "--- 1. mint token (/iam/token, Basic SA-key) ---"
BASIC="$({ printf '%s:' "$CLIENT_ID"; cat "$SA_KEY_PEM"; } | base64 | tr -d '\n\r')"
code="$(do_req POST "${REG_TOKEN_URL}/iam/token?service=${SERVICE_AUD}" \
  -H "Authorization: Basic ${BASIC}")"
assert_hard "token mint" "$code" 200 || true

TOKEN="$(python3 - "$BODY" <<'PY' 2>/dev/null || true
import json, sys
try:
    j = json.load(open(sys.argv[1]))
except Exception:
    print(""); sys.exit(0)
print(j.get("token") or j.get("access_token") or "")
PY
)"
HAVE_TOKEN=0
if [[ -n "$TOKEN" ]]; then
  HAVE_TOKEN=1
  echo "       token acquired (len=${#TOKEN})"
else
  echo "FAIL [hard] token extraction — empty .token/.access_token"
  HARD_FAILS=$((HARD_FAILS + 1))
fi
AUTH=(-H "Authorization: Bearer ${TOKEN}")
echo

# ---------------------------------------------------------------------------
# 2. GET /v2/ БЕЗ токена → 401 + WWW-Authenticate: Bearer realm=…
# ---------------------------------------------------------------------------
echo "--- 2. ping without token → 401 challenge ---"
code="$(do_req GET "${DATAPLANE_URL}/v2/")"
assert_hard "GET /v2/ no-token" "$code" 401 || true
if grep -qiE '^WWW-Authenticate:[[:space:]]*Bearer[[:space:]]+realm=' "$HDR"; then
  echo "PASS [hard] WWW-Authenticate Bearer realm present"
else
  echo "FAIL [hard] WWW-Authenticate Bearer realm missing"
  HARD_FAILS=$((HARD_FAILS + 1))
fi
echo

# ---------------------------------------------------------------------------
# 3. GET /v2/ С токеном → 200
# ---------------------------------------------------------------------------
echo "--- 3. ping with token → 200 ---"
if [[ "$HAVE_TOKEN" == 1 ]]; then
  code="$(do_req GET "${DATAPLANE_URL}/v2/" "${AUTH[@]}")"
  assert_hard "GET /v2/ with-token" "$code" 200 || true
else
  echo "SKIP [hard] GET /v2/ with-token — no token"
  HARD_FAILS=$((HARD_FAILS + 1))
fi
echo

# ---------------------------------------------------------------------------
# 4. push-init POST /v2/{reg}/{repo}/blobs/uploads/ → 202 (grant present)
#    ИЛИ 404 (documented existence-hiding: caller-SA без v_create в namespace)
# ---------------------------------------------------------------------------
echo "--- 4. push-init blobs/uploads/ → 202 (or 404 no-grant, documented) ---"
UPLOAD_URL=""
PUSH_SKIP=0
if [[ "$HAVE_TOKEN" == 1 ]]; then
  code="$(do_req POST "${DATAPLANE_URL}/v2/${REGISTRY_ID}/${REPO}/blobs/uploads/" "${AUTH[@]}")"
  if [[ "$code" == 202 ]]; then
    echo "PASS [hard] push-init — HTTP 202 (grant present)"
    loc="$(awk 'BEGIN{IGNORECASE=1} /^Location:/ {v=$2; sub(/\r$/,"",v); print v}' "$HDR" | tail -1)"
    if [[ -z "$loc" ]]; then
      echo "FAIL [hard] push-init — 202 without Location header"
      HARD_FAILS=$((HARD_FAILS + 1)); PUSH_SKIP=1
    elif [[ "$loc" == http* ]]; then
      UPLOAD_URL="$loc"
    else
      UPLOAD_URL="${DATAPLANE_URL}${loc}"
    fi
  elif [[ "$code" == 404 ]]; then
    doc_note "push-init → 404 — existence-hiding: caller-SA lacks v_create in registry_registry:${REGISTRY_ID}; push/pull steps skipped"
    PUSH_SKIP=1
  else
    echo "FAIL [hard] push-init — HTTP $code (expected 202, or documented 404)"
    HARD_FAILS=$((HARD_FAILS + 1)); PUSH_SKIP=1
  fi
else
  echo "SKIP push-init — no token"; PUSH_SKIP=1
fi
echo

# ---------------------------------------------------------------------------
# 5. monolithic push: PUT config blob (201) → PUT manifest (201)
# ---------------------------------------------------------------------------
echo "--- 5. monolithic push: config blob + manifest → 201/201 ---"
MANIFEST_OK=0
if [[ "$PUSH_SKIP" == 0 && -n "$UPLOAD_URL" ]]; then
  # config-blob: минимальный OCI image-config (data-plane/zot верифицируют digest,
  # не семантику; register-on-first-push срабатывает на manifest-PUT).
  printf '%s' '{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}' > "$TMP/config.json"
  read -r CFG_DIGEST CFG_SIZE < <(python3 - "$TMP/config.json" <<'PY'
import hashlib, sys
b = open(sys.argv[1], "rb").read()
print("sha256:" + hashlib.sha256(b).hexdigest(), len(b))
PY
)
  # monolithic blob upload (PUT session-URL ?digest=…)
  if [[ "$UPLOAD_URL" == *\?* ]]; then blob_url="${UPLOAD_URL}&digest=${CFG_DIGEST}"; else blob_url="${UPLOAD_URL}?digest=${CFG_DIGEST}"; fi
  code="$(do_req PUT "$blob_url" "${AUTH[@]}" \
    -H "Content-Type: application/octet-stream" --data-binary "@${TMP}/config.json")"
  assert_hard "PUT config blob" "$code" 201 || true

  # OCI image-manifest, config→pushed blob, layers пусто (artifact-style push,
  # как в проверенном live-потоке).
  python3 - "$CFG_DIGEST" "$CFG_SIZE" > "$TMP/manifest.json" <<'PY'
import json, sys
digest, size = sys.argv[1], int(sys.argv[2])
print(json.dumps({
    "schemaVersion": 2,
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "config": {
        "mediaType": "application/vnd.oci.image.config.v1+json",
        "digest": digest,
        "size": size,
    },
    "layers": [],
}))
PY
  code="$(do_req PUT "${DATAPLANE_URL}/v2/${REGISTRY_ID}/${REPO}/manifests/${TAG}" "${AUTH[@]}" \
    -H "Content-Type: application/vnd.oci.image.manifest.v1+json" --data-binary "@${TMP}/manifest.json")"
  if assert_hard "PUT manifest" "$code" 201; then MANIFEST_OK=1; fi
else
  echo "SKIP push — no upload session (step 4 skipped/failed)"
fi
echo

# ---------------------------------------------------------------------------
# 6. pull: GET manifest (200) → GET config blob (200) → GET tags/list (200 + tag)
# ---------------------------------------------------------------------------
echo "--- 6. pull: manifest / blob / tags-list → 200 ---"
if [[ "$MANIFEST_OK" == 1 ]]; then
  code="$(do_req GET "${DATAPLANE_URL}/v2/${REGISTRY_ID}/${REPO}/manifests/${TAG}" "${AUTH[@]}" \
    -H "Accept: application/vnd.oci.image.manifest.v1+json")"
  assert_hard "GET manifest" "$code" 200 || true

  code="$(do_req GET "${DATAPLANE_URL}/v2/${REGISTRY_ID}/${REPO}/blobs/${CFG_DIGEST}" "${AUTH[@]}")"
  assert_hard "GET config blob (blob-scope in-repo)" "$code" 200 || true

  code="$(do_req GET "${DATAPLANE_URL}/v2/${REGISTRY_ID}/${REPO}/tags/list" "${AUTH[@]}")"
  assert_hard "GET tags/list" "$code" 200 || true
  if body_contains "\"${TAG}\""; then
    echo "PASS [hard] tags/list contains ${TAG}"
  else
    echo "FAIL [hard] tags/list missing ${TAG}"
    HARD_FAILS=$((HARD_FAILS + 1))
  fi
else
  echo "SKIP pull — manifest not pushed"
fi
echo

# ---------------------------------------------------------------------------
# 7. NEGATIVE existence-hiding
#    (a) push-init на свежий repo БЕЗ Authorization → 401 (hard)
#    (b) non-granted principal → 404 (documented-only; отдельный SA не минтим здесь)
# ---------------------------------------------------------------------------
echo "--- 7. negative existence-hiding ---"
code="$(do_req POST "${DATAPLANE_URL}/v2/${REGISTRY_ID}/${REPO}-noauth/blobs/uploads/")"
assert_hard "push-init no-auth (fresh repo)" "$code" 401 || true
doc_note "non-granted principal push/pull → 404 (existence-hiding): требует второго SA без v_* на объекте; здесь не минтим (SA-key show-once). Инвариант: deny === 404, факт существования чужого repo не раскрывается"
echo

# ---------------------------------------------------------------------------
# 8. direct manifest DELETE → 405 (data-plane запрещает деструктив; удаление —
#    только control-plane DeleteTag)
# ---------------------------------------------------------------------------
echo "--- 8. manifest DELETE → 405 (data-plane forbids destructive) ---"
if [[ "$HAVE_TOKEN" == 1 ]]; then
  code="$(do_req DELETE "${DATAPLANE_URL}/v2/${REGISTRY_ID}/${REPO}/manifests/${TAG}" "${AUTH[@]}")"
  assert_hard "DELETE manifest" "$code" 405 || true
else
  echo "SKIP [hard] DELETE manifest — no token"
  HARD_FAILS=$((HARD_FAILS + 1))
fi
echo

# ---------------------------------------------------------------------------
# 9. path-traversal (URL-encoded) → 400
# ---------------------------------------------------------------------------
echo "--- 9. path-traversal ..%2f..%2fetc → 400 ---"
if [[ "$HAVE_TOKEN" == 1 ]]; then
  code="$(do_req GET "${DATAPLANE_URL}/v2/${REGISTRY_ID}/..%2f..%2fetc/manifests/x" "${AUTH[@]}")"
  assert_hard "traversal GET" "$code" 400 || true
else
  echo "SKIP [hard] traversal GET — no token"
  HARD_FAILS=$((HARD_FAILS + 1))
fi
echo

# ---------------------------------------------------------------------------
# 10. control-plane cross-check (documented): ListRepositories видит register-on-
#     first-push repo. Требует ADMIN_JWT + GATEWAY_URL; иначе DOC-skip.
# ---------------------------------------------------------------------------
echo "--- 10. control-plane cross-check ListRepositories (documented) ---"
if [[ -n "$ADMIN_JWT" && -n "$GATEWAY_URL" ]]; then
  code="$(do_req GET "${GATEWAY_URL}/registry/v1/registries/${REGISTRY_ID}/repositories" \
    -H "Authorization: Bearer ${ADMIN_JWT}")"
  if [[ "$code" == 200 ]] && body_contains "$REPO"; then
    echo "PASS [documented] ListRepositories contains ${REPO} (register-on-first-push visible) — HTTP 200"
  else
    doc_note "ListRepositories cross-check — HTTP $code, ${REPO} $(body_contains "$REPO" && echo present || echo absent); FGA-пропагация register-on-first-push ~0.6–2s (poll-retry вне scope harness)"
  fi
else
  doc_note "control-plane cross-check skipped — set ADMIN_JWT + GATEWAY_URL to verify register-on-first-push visibility"
fi
echo

# ---------------------------------------------------------------------------
# Итог
# ---------------------------------------------------------------------------
echo "=== summary: hard-failures=${HARD_FAILS}  documented-notes=${DOC_NOTES} ==="
if [[ "$HARD_FAILS" -gt 0 ]]; then
  echo "RESULT: FAIL (${HARD_FAILS} hard assertion(s) failed)"
  exit 1
fi
echo "RESULT: PASS (all hard assertions green)"
exit 0
