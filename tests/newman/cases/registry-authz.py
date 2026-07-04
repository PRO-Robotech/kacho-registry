# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Authz-покрытие RegistryService (kacho-registry) — existence-hiding + verb-tier.

Black-box через api-gateway REST (`/registry/v1/registries`). Проверяет инвариант
безопасности: субъект без нужной verb-relation на существующем ресурсе получает
404 NOT_FOUND (никогда 403), и тело ответа НЕ раскрывает `deny_reasons` (не отдаём
authz-оракул наружу). Дополнительно — positive control (viewer с v_get видит ресурс),
gateway-exempt call-gate у List (не-член видит пустой список, не 403), tier-денай
мутаций и anonymous → 401.

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


def _no_deny_leak():
    # Тело authz-денаев не должно раскрывать внутренние причины отказа наружу.
    return ["pm.test('no deny_reasons leak', () => pm.expect(pm.response.text()).to.not.include('deny_reasons'));"]


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

# Get как jwtStranger на существующем regId → 404 NOT_FOUND (НЕ 403); без deny_reasons.
CASES.append(Case(
    id="REG-AZ-GET-STRANGER-HIDDEN",
    title="Get as jwtStranger on existing regId → 404 NOT_FOUND (existence-hidden, not 403); no deny_reasons",
    classes=["AZD", "NEG"], priority="P0",
    steps=[Step(name="get-stranger", method="GET", path=f"{REG}/{{{{regIdAz}}}}", auth="jwtStranger",
                test_script=[*assert_status(404), *assert_grpc_code(5, "NOT_FOUND"), *_no_deny_leak()])],
))

# Positive control: Get как jwtProjectViewerA → 200 (viewer имеет v_get).
# Retry-on-404 поглощает grant-latency (FGA-пропагация project-tuple ~0.6-2s).
CASES.append(Case(
    id="REG-AZ-GET-VIEWER-OK",
    title="Get as jwtProjectViewerA on existing regId → 200 (viewer has v_get) — positive control",
    classes=["AZD"], priority="P1",
    steps=[Step(name="get-viewer", method="GET", path=f"{REG}/{{{{regIdAz}}}}", auth="jwtProjectViewerA",
                test_script=[
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

# List как jwtStranger для {{existingProjectId}} → 200 с пустым массивом
# (не-член видит пусто; gateway-exempt call-gate, не 403).
CASES.append(Case(
    id="REG-AZ-LIST-STRANGER-EMPTY",
    title="List as jwtStranger for existingProjectId → 200 empty array (non-member sees nothing, gateway-exempt)",
    classes=["AZD", "NEG"], priority="P0",
    steps=[Step(name="list-stranger", method="GET", path=f"{REG}?projectId={{{{existingProjectId}}}}", auth="jwtStranger",
                test_script=[*assert_status(200),
                             "const j = pm.response.json();",
                             "pm.test('registries is array', () => pm.expect(j.registries || []).to.be.an('array'));",
                             "pm.test('non-member sees empty list', () => pm.expect((j.registries || []).length).to.eql(0));"])],
))

# Update как jwtProjectViewerA (нет v_update) → 403/404 existence-hidden; без deny_reasons.
CASES.append(Case(
    id="REG-AZ-UPDATE-VIEWER-DENY",
    title="Update as jwtProjectViewerA (no v_update) → 403/404 (existence-hidden); no deny_reasons",
    classes=["AZD", "NEG"], priority="P0",
    steps=[Step(name="update-viewer", method="PATCH", path=f"{REG}/{{{{regIdAz}}}}", auth="jwtProjectViewerA",
                body={"updateMask": "description", "description": "viewer-edit-{{runId}}"},
                test_script=["pm.test('denied 403/404 (no v_update)', () => pm.expect(pm.response.code).to.be.oneOf([403, 404]));",
                             *_no_deny_leak()])],
))

# Delete как jwtProjectViewerA (нет v_delete) → 403/404 existence-hidden; без deny_reasons.
# Денай оставляет ресурс нетронутым → {{regIdAz}} валиден для cleanup.
CASES.append(Case(
    id="REG-AZ-DELETE-VIEWER-DENY",
    title="Delete as jwtProjectViewerA (no v_delete) → 403/404 (existence-hidden); no deny_reasons",
    classes=["AZD", "NEG"], priority="P0",
    steps=[Step(name="delete-viewer", method="DELETE", path=f"{REG}/{{{{regIdAz}}}}", auth="jwtProjectViewerA",
                test_script=["pm.test('denied 403/404 (no v_delete)', () => pm.expect(pm.response.code).to.be.oneOf([403, 404]));",
                             *_no_deny_leak()])],
))

# Create как jwtStranger в {{existingProjectId}} → 403 PERMISSION_DENIED или 404
# (проект скрыт от не-члена); без deny_reasons. Денай синхронный (до Operation).
CASES.append(Case(
    id="REG-AZ-CREATE-STRANGER-DENY",
    title="Create as jwtStranger in existingProjectId → 403 PERMISSION_DENIED or 404 (project hidden); no deny_reasons",
    classes=["AZD", "NEG"], priority="P0",
    steps=[Step(name="create-stranger", method="POST", path=REG, auth="jwtStranger",
                body={"name": "az-intruder-{{runId}}", "projectId": "{{existingProjectId}}"},
                test_script=["pm.test('denied 403/404 (perm denied or project hidden)', () => pm.expect(pm.response.code).to.be.oneOf([403, 404]));",
                             *_no_deny_leak()])],
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
