# CASES-INDEX — catalogue of registry newman cases (kacho-registry)

This catalogue enumerates every case-id in the kacho-registry newman suite across
its three surfaces:

- **control-plane CRUD** — `cases/registry.py` → `collections/registry.postman_collection.json`
  (black-box through api-gateway REST `/registries/v1/...`);
- **control-plane authz** — `cases/registry-authz.py` (existence-hiding / listauthz /
  grant-latency / owner-tuple), also black-box through api-gateway;
- **data-plane + token-exchange** — `scripts/dataplane-e2e.sh` (Docker Registry v2 / OCI
  handshake, push/pull, `/v2/` Bearer, IAM `/iam/token` shim, Hydra federation), a bash
  harness driving the docker CLI + raw HTTP, **not** a gen.py collection.

`validate-cases.py` enforces that every case-id emitted by `gen.py` (i.e. from
`cases/*.py`) is either literally listed below OR matches a `*-<SUFFIX>` pattern
(suffix = everything after the first `-`) OR carries a `# index:` tag in the case file.
Data-plane harness scenario ids are informational (the harness is not a gen.py module,
so `validate-cases.py` does not gate them).

> Format: `<case-id>` — `<classes>` — `<priority>` — `<meaning>` — `Verifies REG-NN`
> Acceptance source of truth:
> `docs/specs/sub-phase-registry-mvp-acceptance.md` (REG-01..REG-44) and
> `docs/specs/sub-phase-registry-token-exchange-acceptance.md` (REG-TX-01..22).

## Class legend

| Token | Meaning |
|---|---|
| `CRUD` | happy-path create/read/update/delete lifecycle |
| `VAL` | input validation (name regex, mask, malformed id) |
| `NEG` | negative / error-path (NotFound, precondition, reject) |
| `CONF` | conflict / immutability / concurrency (UNIQUE, immutable field) |
| `AZ` | authorization (existence-hiding deny→404, listauthz, grant-latency, owner-tuple) |
| `DP` | data-plane (Docker Registry v2 / OCI HTTP surface) |
| `TX` | token-exchange (IAM `/iam/token` shim, Hydra federation, JWKS) |

---

## 1. Control-plane CRUD — `cases/registry.py` (PRESENT — 9 cases)

RegistryService: `Get`/`List` sync, `Create`/`Update`/`Delete` async (→ `Operation`,
op-id prefix `reo`, polled via `/registries/v1/operations/{id}`). Registry id prefix
`reg`. All cases run authenticated in a pre-allocated `existingProjectId`, isolated by
`{{runId}}`-suffixed names.

| Case id | Classes | Prio | Meaning | Verifies |
|---|---|---|---|---|
| `REG-CR-CRUD-OK` | CRUD | P1 | Create → Operation → poll → response Registry (prefix `reg`, status ACTIVE, endpoint) → Get echoes name/projectId | REG-01 |
| `REG-LST-CRUD-OK` | CRUD | P1 | List (project-scope) → `registries[]` array (authz-filtered) | REG-06 |
| `REG-UPD-CRUD-OK` | CRUD | P1 | Update labels+description via `updateMask` → Operation → poll → Get reflects new fields | REG-36 |
| `REG-UPD-NEG-IMMUTABLE-NAME` | NEG, CONF | P1 | Update with `updateMask=name` → 400 INVALID_ARGUMENT ("name is immutable after Registry.Create") | REG-36 |
| `REG-DEL-CRUD-OK` | CRUD | P1 | Delete → Operation → poll → Get 404 NOT_FOUND | REG-07 |
| `REG-CR-NEG-INVALID-NAME` | NEG, VAL | P0 | Create `name="Team_Images"` (uppercase/underscore) → 400 INVALID_ARGUMENT, no Operation | REG-02 |
| `REG-CR-NEG-PROJECT-NOTFOUND` | NEG | P1 | Create with unknown `projectId` → 400 INVALID_ARGUMENT ("project ... not found", cross-domain reject) | REG-03 |
| `REG-GET-NEG-MALFORMED-ID` | NEG | P0 | Get `not-an-id` → 400 INVALID_ARGUMENT ("invalid registry id") | REG-05 |
| `REG-GET-NEG-NOTFOUND` | NEG | P1 | Get well-formed absent id → 404 NOT_FOUND | REG-05 |

### Intended CRUD saturation (add when authored — `*-<SUFFIX>` pre-catalogued)

These patterns are reserved so the file can grow without touching this index. When a
matching case-id lands in `cases/registry.py`, `validate-cases.py` passes via the suffix.

- `*-CR-CONF-ALREADY-EXISTS` — CONF, NEG/P1 — duplicate `(project_id, name)` → 409 ALREADY_EXISTS (DB UNIQUE) (REG-04)
- `*-CR-CONF-RECREATE-OVER-DELETING` — CONF/P2 — re-Create name over a DELETING registry → OK (partial UNIQUE predicate) (REG-04, REG-31)
- `*-DEL-NEG-NAMESPACE-NOT-EMPTY` — NEG, CONF/P0 — Delete non-empty registry → FAILED_PRECONDITION (REG-08)
- `*-DEL-CONF-IDEMPOTENT-CAS` — CONF/P1 — concurrent Delete → one OK + idempotent (atomic CAS, DELETING forward-only) (REG-09)
- `*-LSTREPO-CRUD-OK` — CRUD/P1 — ListRepositories (per-repo projection from zot) → array (REG-22)
- `*-LSTTAGS-CRUD-OK` — CRUD/P1 — ListTags of a repo → array (REG-24)
- `*-DELTAG-CRUD-OK` — CRUD/P1 — DeleteTag → Operation → poll → tag gone; repo-unregister on last tag (REG-25)
- `*-METHOD-PUT-NOT-ALLOWED` / `*-METHOD-DELETE-LIST` — VAL, NEG/P3 — HTTP-method semantics on the collection

---

## 1b. Config-overlay Repository (RG-1) — `cases/registry-repository.py` (PRESENT — 13 cases)

6 новых RegistryService RPC поверх config-overlay `repository_configs`: `GetRepository`/
`ListReferrers` sync; `CreateRepository`/`UpdateRepository`/`DeleteRepository`/
`RenameRepository` async (→ `Operation`, prefix `rop`). Repository ключуется натуральным
ключом `(registryId, name)` (имя несёт `/` → REST wildcard-сегмент). Requires api-gateway
public-mux registration (отдельный срез) — green after routes wired. Verifies RG-1-<Group><NN>.

| Case id | Classes | Prio | Meaning | Verifies |
|---|---|---|---|---|
| `REPO-SETUP` | CRUD | P0 | Setup: create shared overlay registry | RG-1-A01 |
| `REPO-CR-OK` | CRUD | P0 | CreateRepository durable-empty → Operation → durable, PRIVATE (inherited), tagCount=0, createdAt set | RG-1-A01 |
| `REPO-CR-NEG-BADNAME` | NEG, VAL | P1 | CreateRepository malformed name → 400 INVALID_ARGUMENT ("invalid repository name") | RG-1-A05 |
| `REPO-GET-OK` | CRUD | P0 | GetRepository durable-empty → 200 (overlay ⟂ projection, visibility PRIVATE) | RG-1-A07 |
| `REPO-GET-NEG-ABSENT` | NEG | P1 | GetRepository absent → 404 "repository not found" (existence-hiding) | RG-1-A08 |
| `REPO-UPD-OK` | CRUD | P1 | UpdateRepository description/labels via updateMask → Operation → Get reflects | RG-1-A09 |
| `REPO-UPD-NEG-IMMUTABLE` | NEG, VAL | P1 | UpdateRepository `updateMask=name` → 400 ("name is immutable after Repository.Create") | RG-1-A11 |
| `REPO-DEL-OK` | CRUD, IDEM | P1 | DeleteRepository empty durable → Operation done → Get 404 | RG-1-A13 |
| `REPO-DEL-NEG-ABSENT` | NEG | P1 | DeleteRepository absent → sync 404 "repository not found" (existence-hiding) | RG-1-A15 |
| `REPO-REN-OK` | CRUD | P1 | RenameRepository durable old→new → Get(new) 200, Get(old) 404 | RG-1-A16 |
| `REPO-REN-NEG-NOOP` | NEG, VAL | P1 | RenameRepository `newName==repository` → 400 ("new name must differ from current name") | RG-1-A19 |
| `REPO-REF-EMPTY` | CRUD | P2 | ListReferrers subject без referrer'ов → `referrers=[]` 200 (not 404) | RG-1-C03 |
| `REPO-REF-NEG-BADDIGEST` | NEG, VAL | P1 | ListReferrers malformed subject_digest → 400 ("invalid subject digest") | RG-1-C04 |
| `REPO-CLEANUP` | CRUD | P3 | Cleanup: delete shared overlay registry | RG-1-A01 |

---

## 2. Control-plane authz — `cases/registry-authz.py` (PENDING — not yet in repo)

> STATUS: **not yet present** in `tests/newman/cases/`. The following are the **intended**
> case-ids derived from the REG-NN authz scenarios. When the module is authored each id
> must appear below (literal or as a `*-<SUFFIX>` pattern) so `validate-cases.py` passes.

Auth model — **existence-hiding** (see TEST-PLAN §Auth model): read/mutation of a resource
the subject cannot see returns `NOT_FOUND` (deny→404, `corelib ErrHideExistence`), never
`PERMISSION_DENIED`. Exception: `Create` is authorized on the **parent project**
(`v_create@iam_project`); deny on a **visible** project → `PERMISSION_DENIED`, deny on a
**hidden** project → `NOT_FOUND`. `List` returns only authz-visible rows (listauthz,
`viewer ∪ v_list`).

| Intended case id | Classes | Prio | Meaning | Verifies |
|---|---|---|---|---|
| `REG-GET-AZ-EXISTENCE-HIDING` | AZ, NEG | P0 | Get someone else's `reg-*` without `v_get` → 404 NOT_FOUND, **not** 403 (deny→404 no-leak) | REG-05 |
| `REG-LST-AZ-OWNER-SEES-OWN` | AZ | P0 | editor sees own registry in authz-filtered List (read==enforce) | REG-06 |
| `REG-LST-AZ-CROSS-TENANT-NOLEAK` | AZ, NEG | P0 | List by subject scoped to project A does **not** contain project-B registries | REG-06 |
| `REG-CR-AZ-NO-GRANT-DENIED` | AZ, NEG | P0 | Create without `v_create` on a **visible** member project → 403 PERMISSION_DENIED, no Operation | REG-01a |
| `REG-CR-AZ-HIDDEN-PROJECT-NF` | AZ, NEG | P1 | Create targeting a **non-member/hidden** project → 404 NOT_FOUND (existence-hiding on parent) | REG-01a |
| `REG-DEL-AZ-NO-GRANT-NF` | AZ, NEG | P0 | Delete without `v_delete` → **sync** 404 NOT_FOUND (existence-hiding), no Operation, status unchanged | REG-07 |
| `REG-UPD-AZ-NO-GRANT-NF` | AZ, NEG | P1 | Update without `v_update` → **sync** 404 NOT_FOUND (existence-hiding), no Operation | REG-36 |
| `REG-AZ-ANON-UNAUTH` | AZ, NEG | P0 | Control-plane RPC with no `Authorization` → 401 UNAUTHENTICATED (fail-closed) | REG-10, REG-26 |
| `REG-AZ-OWNER-TUPLE-CREATOR` | AZ | P1 | creator gets owner/project-tuple → sees own registry in List (atomic outbox → drainer) | REG-28 |
| `REG-AZ-GRANT-LATENCY-POLL` | AZ | P1 | grant a role → access appears within FGA propagation (poll-retry, ~0.6–2s) | REG-30 |
| `REG-AZ-DOMAIN-BINDING` | AZ | P1 | object-prefix `registry_` == service name → owner-tuples accepted, resources visible | REG-29 |
| `REG-AZ-CATALOG-COMPLETE` | AZ | P1 | full enumeration of `registry.*` permission catalog present (verb-decoupled relations) | REG-28 |

---

## 3. Data-plane + token-exchange — `scripts/dataplane-e2e.sh` (PENDING — not yet in repo)

> STATUS: **not yet present** in `tests/newman/scripts/`. This is a **bash harness** (docker
> CLI login/push/pull + raw-HTTP `/v2/`, `/iam/token`, Hydra `/oauth2/token`), run against
> the live stack; it is **not** a gen.py collection and is not gated by `validate-cases.py`.
> The scenario ids below are the **intended** coverage from REG-10..REG-25/35/37 (data-plane)
> and REG-TX-01..22 (token-exchange). Each maps 1:1 to a scenario in the acceptance docs.

### 3a. Data-plane OCI proxy (Docker Registry v2 / OCI 1.1) — REG-10..25, 35, 37

Auth model — **per-request `InternalIAMService.Check` (Variant B) with existence-hiding
down to blob-level** (per-repo blob-scope): deny → `404`. push into a **new** repo →
`v_create@registry_registry` (namespace); push into an **existing** repo →
`v_update@registry_repository` (verb-decoupling, anti-`#241`); pull → `v_get`; the HTTP
`DELETE` method is rejected `405` before zot (deletion only via `v_delete`-gated DeleteTag).

| Intended scenario id | Classes | Prio | Meaning | Verifies |
|---|---|---|---|---|
| `DP-HANDSHAKE-ANON-401` | DP, AZ, NEG | P0 | `GET /v2/` without a token → 401 fail-closed (no `/v2/*` path returns 2xx unauth) | REG-10 |
| `DP-PUSH-NEW-VCREATE` | DP, CRUD | P0 | docker push to a new repo with `v_create` → registers `registry_repository`, 201/202 | REG-14 |
| `DP-PUSH-OVERWRITE-VUPDATE` | DP, CRUD | P1 | push overwrite of existing tag → each upload Check'd `v_update@registry_repository` | REG-15 |
| `DP-PUSH-EXISTING-NO-VUPDATE-404` | DP, AZ, NEG | P0 | subject with namespace `v_create` but no repo `v_update` → first upload 404 (decoupling) | REG-15 |
| `DP-PULL-VGET-200` | DP, CRUD | P0 | docker pull with `v_get` → 200 | REG-16 |
| `DP-PULL-NOAUTH-404` | DP, AZ, NEG | P0 | pull of another tenant's repo → 404 existence-hiding (+ Check-unavailable fail-closed) | REG-17 |
| `DP-PUSH-NOAUTH-404` | DP, AZ, NEG | P0 | push without rights → 404 existence-hiding | REG-18 |
| `DP-PATH-TRAVERSAL-REJECT` | DP, NEG | P0 | namespace-traversal (`..` raw + `%2e%2e` URL-encoded) → reject before zot | REG-19 |
| `DP-CROSS-REPO-BLOB-MOUNT-GUARD` | DP, AZ, NEG | P0 | cross-repo blob mount exfil-guard — **two** Checks (source + target repo) | REG-20 |
| `DP-PUSH-IDEMPOTENT` | DP, IDEM | P1 | re-push same digest → idempotent (no error, no duplicate) | REG-21 |
| `DP-BLOB-EXISTENCE-PERREPO-404` | DP, AZ, NEG | P0 | another repo's blob is unreachable per-repo blob-scope → 404 (crit-2 variant b) | REG-37 |
| `DP-CATALOG-PERREPO-FILTER` | DP, AZ | P0 | `GET /v2/_catalog` per-repo listauthz — cross-tenant/cross-repo rows do not leak | REG-22, REG-23 |
| `DP-TAGS-LIST-PERREPO-FILTER` | DP, AZ | P0 | `GET /v2/<repo>/tags/list` per-repo listauthz row-filter | REG-24 |
| `DP-DELETE-METHOD-405` | DP, NEG | P0 | data-plane HTTP `DELETE` blocked → 405 (deletion only via DeleteTag) | REG-35 |
| `DP-DELETETAG-VDELETE` | DP, CRUD | P1 | DeleteTag async `v_delete` + repo-unregister on last tag (worker-principal) | REG-25 |
| `DP-TOKEN-SAKEY-VALID` | DP, TX | P1 | IAM `/token` with a valid SA-key → identity-JWT accepted at `/v2/` | REG-11 |
| `DP-TOKEN-SAKEY-INVALID-401` | DP, TX, NEG | P1 | IAM `/token` with invalid/revoked SA-key → 401 | REG-12 |
| `DP-TOKEN-JWKS-VERIFY` | DP, TX | P1 | registry verifies token via IAM/Hydra JWKS (does not trust blindly) + revocation-residual | REG-13, REG-39 |

### 3b. Token-exchange (Hydra federation, Variant H) — REG-TX-01..22

Issuer = Hydra (docker `private_key_jwt` shim + k8s `jwt-bearer`); data-plane verifies
Hydra JWKS; per-request Check remains authZ. Identity-only tokens — authorization is still
the data-plane per-request Check.

| Intended scenario id | Classes | Prio | Meaning | Verifies |
|---|---|---|---|---|
| `TX-HYDRA-DISCOVERY-JWKS` | TX | P0 | Hydra OIDC-discovery + JWKS reachable (verify-source for data-plane) | REG-TX-01 |
| `TX-DOCKER-LOGIN-HAPPY` | TX, DP | P0 | docker login → `/iam/token` `private_key_jwt` shim → Hydra `client_credentials` → JWT | REG-TX-02 |
| `TX-DOCKER-ANON-401` | TX, NEG | P0 | `/iam/token` shim without Basic → 401 + `WWW-Authenticate` (docker-CLI contract) | REG-TX-03 |
| `TX-DOCKER-INVALID-SAKEY-401` | TX, NEG | P1 | docker with invalid/revoked SA-key → 401 | REG-TX-04 |
| `TX-DOCKER-AUDIENCE-401` | TX, NEG | P1 | `?service=` outside allowlist / wrong audience → 401 | REG-TX-05 |
| `TX-K8S-JWT-BEARER-HAPPY` | TX, DP | P0 | k8s pull via `jwt-bearer`/trusted_subject (no imagePullSecrets) | REG-TX-06 |
| `TX-K8S-NO-TRUSTED-SUBJECT-DENY` | TX, NEG | P0 | no FEDERATED-client / subject mismatch → deny (`invalid_grant`) | REG-TX-07 |
| `TX-K8S-BADTOKEN-DENY` | TX, NEG | P1 | expired / wrong-issuer / bad-signature projected-token → deny | REG-TX-08 |
| `TX-K8S-AUDIENCE-MISMATCH-DENY` | TX, NEG | P1 | projected-token audience mismatch → deny (anti-confused-deputy) | REG-TX-09 |
| `TX-IDENTITY-ONLY-CHECK` | TX, AZ | P1 | identity-only token — per-request Check still enforces authZ (docker + k8s) | REG-TX-10 |
| `TX-SAKEY-ISSUE-STANDARD` | TX, CRUD | P1 | Issue SA-key STANDARD (docker) — async Operation | REG-TX-11 |
| `TX-SAKEY-ISSUE-FEDERATED` | TX, CRUD | P1 | Issue SA-key FEDERATED (k8s) — trusted_subjects, no private key | REG-TX-12 |
| `TX-DP-HYDRA-JWKS-SWITCH` | TX, DP | P0 | data-plane verifies Hydra JWKS (switched off IAM RS256 — CRIT) | REG-TX-13 |
| `TX-SAKEY-ISSUE-VALIDATION-AUTHZ` | TX, VAL, AZ | P1 | federation-config validation (literal-anchored subject, https issuer) + authz on Issue | REG-TX-14 |
| `TX-SAKEY-REVOKE` | TX, NEG | P1 | Revoke SA-key → subsequent docker + k8s exchange denied | REG-TX-15 |
| `TX-HYDRA-WIRING` | TX | P1 | fe3455 iam→hydra-admin cluster-internal wiring fix present | REG-TX-16 |
| `TX-RS256-DEPRECATION` | TX | P2 | IAM-native RS256 registry-token deprecated / removed | REG-TX-17 |
| `TX-TOKEN-RATE-LIMIT` | TX | P2 | rate-limit on `/iam/token` shim and `/v2/` | REG-TX-18, REG-43 |
| `TX-FEDERATION-OUT-AUDIENCE` | TX, NEG | P2 | federation-out audience — only `registry.kacho.local` accepted | REG-TX-19 |
| `TX-HYDRA-MINT-UNAVAIL-FAILCLOSED` | TX, NEG | P0 | Hydra unavailable on mint path (docker shim) → fail-closed, no-leak | REG-TX-20 |
| `TX-DP-JWKS-UNAVAIL-FAILCLOSED` | TX, DP, NEG | P0 | Hydra JWKS unreachable / unknown-kid → fail-closed + kid-miss refetch, cache-TTL | REG-TX-21 |
| `TX-E2E-LIVE-GATE` | TX, DP, CRUD | P0 | end-to-end live: docker login+pull + k8s projected-token pull; negatives in same run | REG-TX-22 |

---

## 4. Module / surface summary

| Surface | Module | Status | Cases / scenarios | Acceptance |
|---|---|---|---|---|
| Control-plane CRUD | `cases/registry.py` | present | 9 | REG-01/02/03/05/06/07/36 |
| Control-plane authz | `cases/registry-authz.py` | **pending** | 12 intended | REG-01a/05/06/07/26/28/29/30/36 |
| Data-plane OCI proxy | `scripts/dataplane-e2e.sh` | **pending** | 18 intended | REG-10..25, 35, 37, 39 |
| Token-exchange (Hydra) | `scripts/dataplane-e2e.sh` | **pending** | 22 intended | REG-TX-01..22 |

Not covered by newman/harness (out of scope, see TEST-PLAN §Out-of-scope): real GC
execution internals, zot HA/S3 failover, OCI-1.1 Referrers signature verification,
InternalRegistryService GC/Stats deep internals (integration-tested, mTLS-only).

## Authz (existence-hiding) — `cases/registry-authz.py` (present)

| Case id | Scenario |
|---|---|
| `REG-AZ-SETUP-FIXTURE` | fixture: create registry as editor → save regIdAz |
| `REG-AZ-GET-STRANGER-HIDDEN` | Get as stranger → 404 (existence-hiding, no deny_reasons) |
| `REG-AZ-GET-VIEWER-OK` | Get as viewer (v_get) → 200 (positive control) |
| `REG-AZ-LIST-STRANGER-EMPTY` | List as stranger → 200 empty (non-member) |
| `REG-AZ-UPDATE-VIEWER-DENY` | Update as viewer (no v_update) → 403/404 |
| `REG-AZ-DELETE-VIEWER-DENY` | Delete as viewer → 403/404 |
| `REG-AZ-CREATE-STRANGER-DENY` | Create as stranger → 403/404 |
| `REG-AZ-UPDATE-STRANGER-DENY` | Update as stranger → 401/403/404 (never 200; no deny_reasons leak when !=401) |
| `REG-AZ-DELETE-STRANGER-DENY` | Delete as stranger → 401/403/404 (never 200; fixture untouched; no deny_reasons leak when !=401) |
| `REG-AZ-GET-ANON-401` | Get anonymous → 401 |
| `REG-AZ-CLEANUP-FIXTURE` | cleanup: delete regIdAz as editor → 404 |
