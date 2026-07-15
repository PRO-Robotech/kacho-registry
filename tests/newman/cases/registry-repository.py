# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Case-set для config-overlay Repository RPC (kacho-registry, RG-1).

Black-box через api-gateway REST — покрывает 6 новых RPC RegistryService
(GetRepository/ListReferrers sync; CreateRepository/UpdateRepository/
DeleteRepository/RenameRepository → Operation), ≥1 happy + ≥1 negative на RPC.

  CreateRepository  — happy(durable-empty, PRIVATE, tagCount=0) · bad-name(400)
  GetRepository     — happy(durable-empty) · absent(404 "repository not found")
  UpdateRepository  — happy(description) · immutable name in mask(400)
  DeleteRepository  — happy(empty→done) · absent(404 existence-hiding)
  RenameRepository  — happy(old→new) · no-op new_name==current(400)
  ListReferrers     — happy(empty→[] 200) · malformed subject_digest(400)

REST-контракт (repository содержит `/` → wildcard-сегмент):
  POST   /registry/v1/registries/{regId}/repositories                 (body)
  GET    /registry/v1/registries/{regId}/repositories/{repo}
  PATCH  /registry/v1/registries/{regId}/repositories/{repo}          (body)
  DELETE /registry/v1/registries/{regId}/repositories/{repo}
  POST   /registry/v1/registries/{regId}/repositories/{repo}:rename   (body)
  GET    /registry/v1/registries/{regId}/repositories/{repo}/referrers?subjectDigest=…

Мутации async (Operation prefix `rop`/`reo`, поллятся через /operations/{opId}).
Само-достаточность: shared setup (`REPO-SETUP`) создаёт общий registry {{repoRegId}};
кейсы работают над ним; финальный `REPO-CLEANUP` сносит его. Изоляция — `-{{runId}}`.

Прим.: исполнение требует зарегистрированных в api-gateway public RPC (отдельный
api-gateway-registrar-срез) — до его merge кейсы генерируются, но зелёными станут
после регистрации маршрутов (Tests трассируются к acceptance RG-1-<Group><NN>).
"""

CASES = []

REG = "/registry/v1/registries"
OP_ENVELOPE = "^(rop|reo)[a-z0-9]+$"


def _reg_base():
    return REG + "/{{repoRegId}}/repositories"


def _create_registry(name_expr, id_var):
    """Setup: Create registry (async Op) → poll → capture id into id_var."""
    body = {"name": name_expr, "projectId": "{{existingProjectId}}", "description": "RG-1 overlay CI"}
    return [
        Step(name="reg-create", method="POST", path=REG, body=body,
             test_script=[*assert_status(200), *assert_operation_envelope("^(rop|reo)[a-z0-9]+$"),
                          *save_from_response("j.id", "opId")]),
        poll_operation_until_done(),
        Step(name="reg-capture", method="GET", path="/operations/{{opId}}",
             test_script=[*assert_status(200),
                          "const r=(pm.response.json().response)||{};",
                          *save_from_response("(j.response&&j.response.id)||''", id_var)]),
    ]


def _create_repo(repo_expr, extra_asserts=None, body_extra=None):
    """Create repository (async Op) → poll → capture done. Returns list[Step]."""
    body = {"repository": repo_expr, "description": "api service images", "labels": {"team": "core"}}
    if body_extra:
        body.update(body_extra)
    cap = [
        "const r=(pm.response.json().response)||{};",
        "pm.test('op ok', () => pm.expect(pm.environment.get('lastOpError')||'').to.eql(''));",
    ]
    if extra_asserts:
        cap += extra_asserts
    return [
        Step(name="repo-create", method="POST", path=_reg_base(), body=body,
             test_script=[*assert_status(200), *assert_operation_envelope(OP_ENVELOPE),
                          *save_from_response("j.id", "opId")]),
        poll_operation_until_done(),
        Step(name="repo-capture", method="GET", path="/operations/{{opId}}", test_script=[*assert_status(200), *cap]),
    ]


# --- shared setup ----------------------------------------------------------
CASES.append(Case(
    id="REPO-SETUP", title="Setup: create shared registry for overlay Repository cases",
    classes=["CRUD"], priority="P0",
    steps=_create_registry("overlay-reg-{{runId}}", "repoRegId"),
))

# --- CreateRepository ------------------------------------------------------
CASES.append(Case(
    id="REPO-CR-OK", title="CreateRepository durable-empty → Operation → durable, PRIVATE, tagCount=0 (A01)",
    classes=["CRUD"], priority="P0",
    steps=[
        *_create_repo("backend/api-{{runId}}", extra_asserts=[
            "pm.test('visibility PRIVATE (inherited)', () => pm.expect(r.visibility).to.eql('PRIVATE'));",
            "pm.test('tagCount 0 (survives-empty)', () => pm.expect(Number(r.tagCount||0)).to.eql(0));",
            "pm.test('createdAt set', () => pm.expect(r.createdAt||'').to.not.eql(''));",
        ]),
    ],
))

CASES.append(Case(
    id="REPO-CR-NEG-BADNAME", title="CreateRepository malformed name → 400 INVALID_ARGUMENT (A05)",
    classes=["NEG", "VAL"], priority="P1",
    steps=[Step(name="create-bad", method="POST", path=_reg_base(),
                body={"repository": "Bad Name!"},
                test_script=[*assert_status(400), *assert_grpc_code(3, "INVALID_ARGUMENT"),
                             "pm.test('invalid name text', () => pm.expect((pm.response.json().message||'')).to.include('invalid repository name'));"])],
))

# --- GetRepository ---------------------------------------------------------
CASES.append(Case(
    id="REPO-GET-OK", title="GetRepository durable-empty → 200 (overlay projection, A07)",
    classes=["CRUD"], priority="P0",
    steps=[
        *_create_repo("get/svc-{{runId}}"),
        Step(name="get-repo", method="GET", path=_reg_base() + "/get/svc-{{runId}}",
             test_script=[*assert_status(200),
                          "const j=pm.response.json();",
                          "pm.test('name matches', () => pm.expect(j.name).to.eql('get/svc-'+pm.environment.get('runId')));",
                          "pm.test('visibility PRIVATE', () => pm.expect(j.visibility).to.eql('PRIVATE'));"]),
    ],
))

CASES.append(Case(
    id="REPO-GET-NEG-ABSENT", title="GetRepository absent → 404 \"repository not found\" (existence-hiding, A08)",
    classes=["NEG"], priority="P1",
    steps=[Step(name="get-absent", method="GET", path=_reg_base() + "/ghost/svc-{{runId}}",
                test_script=[*assert_status(404), *assert_grpc_code(5, "NOT_FOUND"),
                             "pm.test('repository not found text', () => pm.expect(pm.response.json().message).to.eql('repository not found'));"])],
))

# --- UpdateRepository ------------------------------------------------------
CASES.append(Case(
    id="REPO-UPD-OK", title="UpdateRepository description/labels → Operation → Get reflects (A09)",
    classes=["CRUD"], priority="P1",
    steps=[
        *_create_repo("upd/svc-{{runId}}"),
        Step(name="update-repo", method="PATCH", path=_reg_base() + "/upd/svc-{{runId}}",
             body={"description": "api images v2", "labels": {"team": "core", "tier": "gold"},
                   "updateMask": "description,labels"},
             test_script=[*assert_status(200), *assert_operation_envelope(OP_ENVELOPE),
                          *save_from_response("j.id", "opId")]),
        poll_operation_until_done(),
        Step(name="update-verify", method="GET", path=_reg_base() + "/upd/svc-{{runId}}",
             test_script=[*assert_status(200),
                          "pm.test('description updated', () => pm.expect(pm.response.json().description).to.eql('api images v2'));"]),
    ],
))

CASES.append(Case(
    id="REPO-UPD-NEG-IMMUTABLE", title="UpdateRepository name in mask → 400 immutable text (A11)",
    classes=["NEG", "VAL"], priority="P1",
    steps=[
        *_create_repo("imm/svc-{{runId}}"),
        Step(name="update-immutable", method="PATCH", path=_reg_base() + "/imm/svc-{{runId}}",
             body={"description": "x", "updateMask": "name"},
             test_script=[*assert_status(400), *assert_grpc_code(3, "INVALID_ARGUMENT"),
                          "pm.test('name immutable text', () => pm.expect(pm.response.json().message).to.eql('name is immutable after Repository.Create'));"]),
    ],
))

# --- DeleteRepository ------------------------------------------------------
CASES.append(Case(
    id="REPO-DEL-OK", title="DeleteRepository empty durable → Operation done → Get 404 (A13)",
    classes=["CRUD", "IDEM"], priority="P1",
    steps=[
        *_create_repo("del/svc-{{runId}}"),
        Step(name="delete-repo", method="DELETE", path=_reg_base() + "/del/svc-{{runId}}",
             test_script=[*assert_status(200), *assert_operation_envelope(OP_ENVELOPE),
                          *save_from_response("j.id", "opId")]),
        poll_operation_until_done(),
        Step(name="delete-verify", method="GET", path=_reg_base() + "/del/svc-{{runId}}",
             test_script=[*assert_status(404), *assert_grpc_code(5, "NOT_FOUND")]),
    ],
))

CASES.append(Case(
    id="REPO-DEL-NEG-ABSENT", title="DeleteRepository absent → 404 (existence-hiding, A15)",
    classes=["NEG"], priority="P1",
    steps=[Step(name="delete-absent", method="DELETE", path=_reg_base() + "/nope/svc-{{runId}}",
                test_script=[*assert_status(404), *assert_grpc_code(5, "NOT_FOUND"),
                             "pm.test('repository not found text', () => pm.expect(pm.response.json().message).to.eql('repository not found'));"])],
))

# --- RenameRepository ------------------------------------------------------
CASES.append(Case(
    id="REPO-REN-OK", title="RenameRepository durable old→new → Get(new) 200, Get(old) 404 (A16)",
    classes=["CRUD"], priority="P1",
    steps=[
        *_create_repo("ren/old-{{runId}}"),
        Step(name="rename-repo", method="POST", path=_reg_base() + "/ren/old-{{runId}}:rename",
             body={"newName": "ren/new-{{runId}}"},
             test_script=[*assert_status(200), *assert_operation_envelope(OP_ENVELOPE),
                          *save_from_response("j.id", "opId")]),
        poll_operation_until_done(),
        Step(name="rename-verify-new", method="GET", path=_reg_base() + "/ren/new-{{runId}}",
             test_script=[*assert_status(200),
                          "pm.test('new name', () => pm.expect(pm.response.json().name).to.eql('ren/new-'+pm.environment.get('runId')));"]),
        Step(name="rename-verify-old", method="GET", path=_reg_base() + "/ren/old-{{runId}}",
             test_script=[*assert_status(404), *assert_grpc_code(5, "NOT_FOUND")]),
    ],
))

CASES.append(Case(
    id="REPO-REN-NEG-NOOP", title="RenameRepository new_name==current → 400 (A19)",
    classes=["NEG", "VAL"], priority="P1",
    steps=[
        *_create_repo("noop/svc-{{runId}}"),
        Step(name="rename-noop", method="POST", path=_reg_base() + "/noop/svc-{{runId}}:rename",
             body={"newName": "noop/svc-{{runId}}"},
             test_script=[*assert_status(400), *assert_grpc_code(3, "INVALID_ARGUMENT"),
                          "pm.test('differ text', () => pm.expect(pm.response.json().message).to.eql('new name must differ from current name'));"]),
    ],
))

# --- ListReferrers ---------------------------------------------------------
CASES.append(Case(
    id="REPO-REF-EMPTY", title="ListReferrers subject без referrer'ов → [] 200 (C03)",
    classes=["CRUD"], priority="P2",
    steps=[
        *_create_repo("ref/svc-{{runId}}"),
        Step(name="referrers-empty", method="GET",
             path=_reg_base() + "/ref/svc-{{runId}}/referrers?subjectDigest=sha256:" + ("e" * 64),
             test_script=[*assert_status(200),
                          "pm.test('empty referrers []', () => pm.expect((pm.response.json().referrers||[]).length).to.eql(0));"]),
    ],
))

CASES.append(Case(
    id="REPO-REF-NEG-BADDIGEST", title="ListReferrers malformed subject_digest → 400 (C04)",
    classes=["NEG", "VAL"], priority="P1",
    steps=[
        *_create_repo("refbad/svc-{{runId}}"),
        Step(name="referrers-bad", method="GET",
             path=_reg_base() + "/refbad/svc-{{runId}}/referrers?subjectDigest=not-a-digest",
             test_script=[*assert_status(400), *assert_grpc_code(3, "INVALID_ARGUMENT"),
                          "pm.test('invalid digest text', () => pm.expect(pm.response.json().message).to.include('invalid subject digest'));"]),
    ],
))

# --- cleanup ---------------------------------------------------------------
CASES.append(Case(
    id="REPO-CLEANUP", title="Cleanup: delete shared overlay registry",
    classes=["CRUD"], priority="P3",
    steps=[
        Step(name="reg-delete", method="DELETE", path=REG + "/{{repoRegId}}",
             test_script=["pm.test('delete accepted (200/404)', () => pm.expect(pm.response.code).to.be.oneOf([200, 404]));",
                          "const j=pm.response.json(); if (j && j.id) pm.environment.set('opId', String(j.id));"]),
        poll_operation_until_done(),
    ],
))
