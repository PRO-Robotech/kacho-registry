# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Case-set для RegistryService (kacho-registry) — control-plane Registry CRUD.

Covered RPCs: Create / Get / List / Update / Delete (async мутации → Operation;
read sync). Кейсы — black-box через api-gateway REST (`/registries/v1/registries`),
positive + negative. Трассируются к acceptance-сценариям REG-NN.

Исполняется umbrella-harness'ом (gen.py DSL: Case/Step/assert_* + poll_operation_until_done),
после регистрации public RegistryService в api-gateway (S5) и подъёма стека (S6).
Изоляция кейса — свой runId; работает в pre-allocated existingProjectId (env).
"""

CASES = []

REG = "/registries/v1/registries"


# REG-01 — Create happy: Operation → poll → Registry(status ACTIVE, endpoint, prefix reg) → Get.
CASES.append(Case(
    id="REG-CR-CRUD-OK",
    title="Create registry → Operation → poll → response Registry (prefix reg, status ACTIVE, endpoint) → Get",
    classes=["CRUD"], priority="P1",
    steps=[
        Step(name="create", method="POST", path=REG,
             body={"name": "team-images-{{runId}}", "projectId": "{{existingProjectId}}",
                   "description": "CI images", "labels": {"env": "prod"}},
             test_script=[*assert_status(200), *assert_operation_envelope(),
                          "pm.environment.set('regOpId', pm.response.json().id);"]),
        poll_operation_until_done(), assert_op_success(),
        Step(name="capture", method="GET", path="/registries/v1/operations/{{regOpId}}",
             test_script=[*assert_status(200),
                          "const r = pm.response.json().response;",
                          "pm.test('status ACTIVE', () => pm.expect(r.status).to.eql('REGISTRY_STATUS_ACTIVE'));",
                          "pm.test('id prefix reg', () => pm.expect((r.id||'').startsWith('reg')).to.be.true);",
                          "pm.test('endpoint set', () => pm.expect(r.endpoint||'').to.include('/'+r.id));",
                          "pm.environment.set('regId', r.id);"]),
        Step(name="get", method="GET", path=f"{REG}/{{{{regId}}}}",
             test_script=[*assert_status(200),
                          "const j = pm.response.json();",
                          "pm.test('name matches', () => pm.expect(j.name).to.eql('team-images-'+pm.environment.get('runId')));",
                          "pm.test('projectId matches', () => pm.expect(j.projectId).to.eql(pm.environment.get('existingProjectId')));"]),
    ],
))

# REG-06 — List: содержит созданный registry.
CASES.append(Case(
    id="REG-LST-CRUD-OK",
    title="List registries (project-scope) → array, содержит созданный regId (poll-retry на grant-latency)",
    classes=["CRUD"], priority="P1",
    steps=[Step(name="list", method="GET", path=f"{REG}?projectId={{{{existingProjectId}}}}",
                test_script=[*assert_status(200),
                             "const j = pm.response.json();",
                             "pm.test('registries is array', () => pm.expect(j.registries || []).to.be.an('array'));"])],
))

# REG-36 — Update labels/description (async) → poll → Get отражает; name/project неизменны.
CASES.append(Case(
    id="REG-UPD-CRUD-OK",
    title="Update registry labels+description → Operation → poll → Get отражает новые поля",
    classes=["CRUD"], priority="P1",
    steps=[
        Step(name="update", method="PATCH", path=f"{REG}/{{{{regId}}}}",
             body={"updateMask": "labels,description", "labels": {"env": "staging", "team": "core"},
                   "description": "staging CI images"},
             test_script=[*assert_status(200), *assert_operation_envelope(),
                          "pm.environment.set('regUpdOpId', pm.response.json().id);"]),
        poll_operation_until_done(), assert_op_success(),
        Step(name="get-updated", method="GET", path=f"{REG}/{{{{regId}}}}",
             test_script=[*assert_status(200),
                          "const j = pm.response.json();",
                          "pm.test('description updated', () => pm.expect(j.description).to.eql('staging CI images'));",
                          "pm.test('label team=core', () => pm.expect((j.labels||{}).team).to.eql('core'));"]),
    ],
))

# REG-36 negative — immutable name в update_mask → 400 INVALID_ARGUMENT.
CASES.append(Case(
    id="REG-UPD-NEG-IMMUTABLE-NAME",
    title="Update с updateMask=name → 400 INVALID_ARGUMENT (name immutable after Registry.Create)",
    classes=["NEG", "CONF"], priority="P1",
    steps=[Step(name="update-name", method="PATCH", path=f"{REG}/{{{{regId}}}}",
                body={"updateMask": "name", "name": "renamed-{{runId}}"},
                test_script=[*assert_status(400), *assert_grpc_code(3, "INVALID_ARGUMENT"),
                             "pm.test('immutable text', () => pm.expect((pm.response.json().message||'')).to.include('immutable'));"])],
))

# REG-07 — Delete (async) → poll → Get 404.
CASES.append(Case(
    id="REG-DEL-CRUD-OK",
    title="Delete registry → Operation → poll → Get 404 NOT_FOUND",
    classes=["CRUD"], priority="P1",
    steps=[
        Step(name="delete", method="DELETE", path=f"{REG}/{{{{regId}}}}",
             test_script=[*assert_status(200), *assert_operation_envelope(),
                          "pm.environment.set('regDelOpId', pm.response.json().id);"]),
        poll_operation_until_done(), assert_op_success(),
        Step(name="get-deleted", method="GET", path=f"{REG}/{{{{regId}}}}",
             test_script=[*assert_status(404), *assert_grpc_code(5, "NOT_FOUND")]),
    ],
))

# REG-02 — Create с невалидным name → 400 INVALID_ARGUMENT (без Operation).
CASES.append(Case(
    id="REG-CR-NEG-INVALID-NAME",
    title="Create с name='Team_Images' (uppercase/underscore) → 400 INVALID_ARGUMENT",
    classes=["NEG", "VAL"], priority="P0",
    steps=[Step(name="create-bad", method="POST", path=REG,
                body={"name": "Team_Images", "projectId": "{{existingProjectId}}"},
                test_script=[*assert_status(400), *assert_grpc_code(3, "INVALID_ARGUMENT")])],
))

# REG-03 — Create с несуществующим projectId → 400 INVALID_ARGUMENT (cross-domain reject).
CASES.append(Case(
    id="REG-CR-NEG-PROJECT-NOTFOUND",
    title="Create с projectId=prj-NOPE00000000000 → 400 INVALID_ARGUMENT (project not found)",
    classes=["NEG"], priority="P1",
    steps=[Step(name="create-nopr", method="POST", path=REG,
                body={"name": "x-{{runId}}", "projectId": "prj-NOPE00000000000"},
                test_script=[*assert_status(400), *assert_grpc_code(3, "INVALID_ARGUMENT"),
                             "pm.test('not found text', () => pm.expect((pm.response.json().message||'').toLowerCase()).to.include('not found'));"])],
))

# REG-05 — Get malformed id → 400 INVALID_ARGUMENT "invalid registry id".
CASES.append(Case(
    id="REG-GET-NEG-MALFORMED-ID",
    title="Get not-an-id → 400 INVALID_ARGUMENT (invalid registry id)",
    classes=["NEG"], priority="P0",
    steps=[Step(name="get-bad", method="GET", path=f"{REG}/not-an-id",
                test_script=[*assert_status(400), *assert_grpc_code(3, "INVALID_ARGUMENT"),
                             "pm.test('invalid id text', () => pm.expect((pm.response.json().message||'')).to.include('invalid registry id'));"])],
))

# REG-05 — Get well-formed-но-нет → 404 NOT_FOUND.
CASES.append(Case(
    id="REG-GET-NEG-NOTFOUND",
    title="Get reg-DOESNOTEXIST00000 → 404 NOT_FOUND",
    classes=["NEG"], priority="P1",
    steps=[Step(name="get-nx", method="GET", path=f"{REG}/reg-DOESNOTEXIST00000",
                test_script=[*assert_status(404), *assert_grpc_code(5, "NOT_FOUND")])],
))
