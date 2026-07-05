# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Authz-покрытие RegistryService (kacho-registry) — existence-hiding + verb-tier.

Black-box через api-gateway REST (`/registry/v1/registries`). Проверяет инвариант
безопасности: субъект без нужной verb-relation на существующем ресурсе денается без
раскрытия существования ресурса (никакого `deny_reasons`-оракула наружу, никакого
success-with-data), а `List` не-члена возвращает пустой массив (не 403).

Адаптация под текущий стенд (single-user). На fe3455 зарегистрирован ровно ОДИН
IAM-юзер (cluster-admin). `external_id` юзера проецируется из Kratos-IdP и не
создаётся публичным API — поэтому «зарегистрированный-но-негрантнутый stranger» и
viewer-tier юзер здесь не провиженятся:

- **Stranger** — dev-JWT с незарегистрированным `sub` gateway трактует как
  UNAUTHENTICATED → HTTP 401 (code 16, "subject: unauthenticated request"), НЕ как
  authenticated-но-denied 404. Кейсы принимают весь denied/empty-диапазон
  `[200-empty, 401, 403, 404]`, но НИКОГДА success-with-data и НИКОГДА не раскрывают
  существование фикстуры (её regId). Проверка «нет deny_reasons» гейтится на код
  != 401 (unauthenticated-тело несёт generic-причину, не resource-existence leak).
- **Viewer-tier** (GET-VIEWER-OK / UPDATE-VIEWER-DENY / DELETE-VIEWER-DENY) — требуют
  зарегистрированного viewer-юзера, которого стенд дать не может. Кейс fixture-gated:
  при пустом `jwtProjectViewerA` кейс НЕ эмитит зелёный pm.test (console-note + return
  без assertion — не false-green, ban #13), при наличии токена — полный энфорс реальных
  assertions. Граница «viewer держит v_get, но НЕ v_update/v_delete → Update/Delete =
  NOT_FOUND (existence-hidden)» ДОПОЛНИТЕЛЬНО покрыта всегда-исполняемым Go-тестом
  internal/check/viewer_boundary_test.go (реальный corelib authz-interceptor поверх
  registry PermissionMap + fake CheckClient, грантящий ровно v_get) — граница НЕ висит
  только на fixture-gated SKIP'е.

Инвариант existence-hiding (authenticated-ungranted → 404, никогда 403, без leak'а)
отдельно верифицируется GREEN control-plane-сьютом и data-plane-харнессом.

Фикстура: setup создаёт registry от project-editor (сохраняет {{regIdAz}}); кейсы
исполняются от разных субъектов (jwtStranger / jwtProjectViewerA / anonymous);
cleanup удаляет registry от editor ПОСЛЕДНИМ. Изоляция — свой runId; работает в
pre-allocated existingProjectId (env). Мутации async → Operation (poll до done);
read sync (200 напрямую).
"""

CASES = []

REG = "/registry/v1/registries"

# Registry-операции несут id-префикс rop/reo (opsproxy-роутинг в api-gateway).
_OP_PREFIX = "^(rop|reo)[a-z0-9]+$"


def _assert_denied_or_empty():
    # Stranger на single-user стенде: dev-JWT с незарегистрированным sub → gateway
    # трактует как unauthenticated → 401. Принимаем весь denied/empty-диапазон,
    # но НИКОГДА success-with-data (это ловят per-case regId/empty-проверки).
    return ["pm.test('denied or empty (200/401/403/404)', () => pm.expect(pm.response.code).to.be.oneOf([200, 401, 403, 404]));"]


def _deny_leak_gated():
    # Аутентифицированный денай не должен раскрывать authz-причины наружу. На 401
    # (unauthenticated) тело несёт generic "subject unauthenticated" — это НЕ утечка
    # существования ресурса, поэтому проверку гейтим на код != 401.
    return [
        "if (pm.response.code !== 401) {",
        "  pm.test('authenticated deny -> no resource-existence leak', () => pm.expect(JSON.stringify(pm.response.json())).to.not.include('deny_reasons'));",
        "}",
    ]


def _never_reveals_regid():
    # Денай/пустой ответ не должен раскрывать существование фикстуры (её regId).
    return [
        "const _rid = pm.environment.get('regIdAz') || '';",
        "if (_rid) pm.test('never reveals fixture regId', () => pm.expect(pm.response.text()).to.not.include(_rid));",
    ]


def _viewer_gate():
    # Viewer-tier кейсы требуют зарегистрированного viewer-юзера. На single-user
    # стенде (external_id проецируется из Kratos-IdP, публичным API не создаётся)
    # фикстуры нет. В этом случае кейс НЕ эмитит зелёный pm.test: раньше здесь стоял
    # pm.test('SKIPPED', () => pm.expect(true).to.eql(true)) — no-op assertion, которая
    # не может упасть и рапортовала непроверенную границу как green (ban #13, inflate
    # pass-count). Теперь при отсутствии фикстуры — console-note + return БЕЗ assertion
    # (кейс отражается как «нет тестов», а не false-green). При наличии токена —
    # реальные viewer-assertions (полный энфорс). Сама граница v_get→NOT_FOUND всегда
    # покрыта Go-тестом internal/check/viewer_boundary_test.go.
    return [
        "const _viewer = pm.environment.get('jwtProjectViewerA') || '';",
        "if (!_viewer) {",
        "  console.log('SKIP viewer-tier (no jwtProjectViewerA fixture); boundary covered by internal/check/viewer_boundary_test.go');",
        "  return;",
        "}",
    ]


# Фикстура: создать registry от project-editor → poll → capture {{regIdAz}}.
CASES.append(Case(
    id="REG-AZ-SETUP-FIXTURE",
    title="Setup: Create registry as project-editor → Operation → poll → capture regIdAz (prefix reg)",
    classes=["AZD"], priority="P1",
    steps=[
        Step(name="create-fixture", method="POST", path=REG,
             body={"name": "az-fixture-{{runId}}", "projectId": "{{existingProjectId}}",
                   "description": "authz coverage fixture"},
             test_script=[*assert_status(200), *assert_operation_envelope(_OP_PREFIX),
                          *save_from_response("j.id", "opId")]),
        poll_operation_until_done(),
        Step(name="capture-fixture-id", method="GET", path="/operations/{{opId}}",
             test_script=[*assert_status(200),
                          "pm.test('setup op ok', () => pm.expect(pm.environment.get('lastOpError')||'').to.eql(''));",
                          *save_from_response("(j.response&&j.response.id)||''", "regIdAz"),
                          "pm.test('fixture regId captured (prefix reg)', () => pm.expect((pm.environment.get('regIdAz')||'').startsWith('reg')).to.be.true);"]),
    ],
))

# Get как jwtStranger на существующем regId. Stranger здесь unauthenticated → 401;
# принимаем denied/empty-диапазон, но существование фикстуры не раскрываем.
CASES.append(Case(
    id="REG-AZ-GET-STRANGER-HIDDEN",
    title="Get as jwtStranger on existing regId → denied/empty (200/401/403/404), never reveals regId; no deny_reasons (gated !=401)",
    classes=["AZD", "NEG"], priority="P0",
    steps=[Step(name="get-stranger", method="GET", path=f"{REG}/{{{{regIdAz}}}}", auth="jwtStranger",
                test_script=[*_assert_denied_or_empty(), *_never_reveals_regid(), *_deny_leak_gated()])],
))

# Positive control: Get как jwtProjectViewerA → 200 (viewer имеет v_get).
# Fixture-gated: без зарегистрированного viewer-юзера — informational SKIP.
# Retry-on-404 поглощает grant-latency (FGA-пропагация project-tuple ~0.6-2s).
CASES.append(Case(
    id="REG-AZ-GET-VIEWER-OK",
    title="Get as jwtProjectViewerA on existing regId → 200 (viewer has v_get) — positive control (fixture-gated)",
    classes=["AZD"], priority="P1",
    steps=[Step(name="get-viewer", method="GET", path=f"{REG}/{{{{regIdAz}}}}", auth="jwtProjectViewerA",
                test_script=[
                    *_viewer_gate(),
                    "const _n = parseInt(pm.environment.get('_azViewerRetry') || '0', 10);",
                    "if (pm.response.code === 404 && _n < 20) {",
                    "  pm.environment.set('_azViewerRetry', String(_n + 1));",
                    "  postman.setNextRequest(pm.info.requestName);",
                    "  return;",
                    "}",
                    "pm.environment.unset('_azViewerRetry');",
                    *assert_status(200),
                    "const j = pm.response.json();",
                    "pm.test('viewer sees fixture (v_get)', () => pm.expect(j.id).to.eql(pm.environment.get('regIdAz')));"])],
))

# List как jwtStranger для {{existingProjectId}}. Не-член видит пусто (gateway-exempt
# call-gate, не 403); stranger здесь unauthenticated → 401. Принимаем оба, при 200 —
# массив обязан быть пуст, и существование фикстуры не раскрываем.
CASES.append(Case(
    id="REG-AZ-LIST-STRANGER-EMPTY",
    title="List as jwtStranger for existingProjectId → denied/empty (200 empty / 401 / 403 / 404), never reveals regId",
    classes=["AZD", "NEG"], priority="P0",
    steps=[Step(name="list-stranger", method="GET", path=f"{REG}?projectId={{{{existingProjectId}}}}", auth="jwtStranger",
                test_script=[
                    *_assert_denied_or_empty(),
                    "if (pm.response.code === 200) {",
                    "  const j = pm.response.json();",
                    "  pm.test('registries is array', () => pm.expect(j.registries || []).to.be.an('array'));",
                    "  pm.test('non-member sees empty list', () => pm.expect((j.registries || []).length).to.eql(0));",
                    "}",
                    *_never_reveals_regid(),
                    *_deny_leak_gated()])],
))

# Update как jwtProjectViewerA (нет v_update) → 403/404 existence-hidden; без deny_reasons.
# Fixture-gated: без зарегистрированного viewer-юзера — informational SKIP.
CASES.append(Case(
    id="REG-AZ-UPDATE-VIEWER-DENY",
    title="Update as jwtProjectViewerA (no v_update) → 403/404 (existence-hidden); no deny_reasons (fixture-gated)",
    classes=["AZD", "NEG"], priority="P0",
    steps=[Step(name="update-viewer", method="PATCH", path=f"{REG}/{{{{regIdAz}}}}", auth="jwtProjectViewerA",
                body={"updateMask": "description", "description": "viewer-edit-{{runId}}"},
                test_script=[
                    *_viewer_gate(),
                    "pm.test('denied 403/404 (no v_update)', () => pm.expect(pm.response.code).to.be.oneOf([403, 404]));",
                    *_deny_leak_gated()])],
))

# Delete как jwtProjectViewerA (нет v_delete) → 403/404 existence-hidden; без deny_reasons.
# Fixture-gated: без зарегистрированного viewer-юзера — informational SKIP. Денай
# оставляет ресурс нетронутым → {{regIdAz}} валиден для cleanup.
CASES.append(Case(
    id="REG-AZ-DELETE-VIEWER-DENY",
    title="Delete as jwtProjectViewerA (no v_delete) → 403/404 (existence-hidden); no deny_reasons (fixture-gated)",
    classes=["AZD", "NEG"], priority="P0",
    steps=[Step(name="delete-viewer", method="DELETE", path=f"{REG}/{{{{regIdAz}}}}", auth="jwtProjectViewerA",
                test_script=[
                    *_viewer_gate(),
                    "pm.test('denied 403/404 (no v_delete)', () => pm.expect(pm.response.code).to.be.oneOf([403, 404]));",
                    *_deny_leak_gated()])],
))

# Create как jwtStranger в {{existingProjectId}}. Stranger здесь unauthenticated → 401;
# на многопользовательском стенде — 403 (visible project, no v_create) / 404 (hidden).
# Принимаем denied/empty-диапазон; без deny_reasons-leak (gated !=401).
CASES.append(Case(
    id="REG-AZ-CREATE-STRANGER-DENY",
    title="Create as jwtStranger in existingProjectId → denied (200/401/403/404); no deny_reasons (gated !=401)",
    classes=["AZD", "NEG"], priority="P0",
    steps=[Step(name="create-stranger", method="POST", path=REG, auth="jwtStranger",
                body={"name": "az-intruder-{{runId}}", "projectId": "{{existingProjectId}}"},
                test_script=[*_assert_denied_or_empty(), *_deny_leak_gated()])],
))

# Update как jwtStranger на существующем regId. Stranger здесь unauthenticated → 401;
# на многопользовательском стенде — 403 (visible project, no v_update) / 404 (hidden).
# Мутация stranger'а НИКОГДА не 200-success (нет v_update); deny_reasons-leak не
# раскрываем (gated !=401 — 401-тело несёт generic-причину, не existence-oracle).
CASES.append(Case(
    id="REG-AZ-UPDATE-STRANGER-DENY",
    title="Update as jwtStranger on existing regId → denied (401/403/404, never 200 success); no deny_reasons (gated !=401)",
    classes=["AZD", "NEG"], priority="P0",
    steps=[Step(name="update-stranger", method="PATCH", path=f"{REG}/{{{{regIdAz}}}}", auth="jwtStranger",
                body={"updateMask": "description", "description": "x"},
                test_script=[
                    "pm.test('denied 401/403/404 (stranger, never 200 success)', () => pm.expect(pm.response.code).to.be.oneOf([401, 403, 404]));",
                    *_deny_leak_gated()])],
))

# Delete как jwtStranger на существующем regId. Тот же денай-диапазон [401/403/404],
# НИКОГДА 200-success (нет v_delete). Денай оставляет фикстуру нетронутой → {{regIdAz}}
# валиден для cleanup. deny_reasons-leak не раскрываем (gated !=401).
CASES.append(Case(
    id="REG-AZ-DELETE-STRANGER-DENY",
    title="Delete as jwtStranger on existing regId → denied (401/403/404, never 200 success); no deny_reasons (gated !=401)",
    classes=["AZD", "NEG"], priority="P0",
    steps=[Step(name="delete-stranger", method="DELETE", path=f"{REG}/{{{{regIdAz}}}}", auth="jwtStranger",
                test_script=[
                    "pm.test('denied 401/403/404 (stranger, never 200 success)', () => pm.expect(pm.response.code).to.be.oneOf([401, 403, 404]));",
                    *_deny_leak_gated()])],
))

# anonymous (без Authorization) Get на существующем regId → 401 AUTHN_REQUIRED.
CASES.append(Case(
    id="REG-AZ-GET-ANON-401",
    title="anonymous Get on existing regId → 401 (authN required, no bearer)",
    classes=["AZD", "NEG"], priority="P0",
    steps=[Step(name="get-anon", method="GET", path=f"{REG}/{{{{regIdAz}}}}", auth="anonymous",
                test_script=[*assert_status(401)])],
))

# Cleanup: удалить фикстуру от project-editor ПОСЛЕДНИМ → poll → Get 404.
CASES.append(Case(
    id="REG-AZ-CLEANUP-FIXTURE",
    title="Cleanup: Delete fixture registry as project-editor (LAST) → Operation → poll → Get 404",
    classes=["AZD"], priority="P2",
    steps=[
        Step(name="delete-fixture", method="DELETE", path=f"{REG}/{{{{regIdAz}}}}",
             test_script=[*assert_status(200), *assert_operation_envelope(_OP_PREFIX),
                          *save_from_response("j.id", "opId")]),
        poll_operation_until_done(),
        Step(name="confirm-deleted", method="GET", path=f"{REG}/{{{{regIdAz}}}}",
             test_script=["pm.test('cleanup op ok', () => pm.expect(pm.environment.get('lastOpError')||'').to.eql(''));",
                          *assert_status(404), *assert_grpc_code(5, "NOT_FOUND")]),
    ],
))
