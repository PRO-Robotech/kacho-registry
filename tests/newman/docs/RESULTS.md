# RESULTS — kacho-registry newman + data-plane run history

> Live-run verification against the **fe3455** stack (api-gateway REST + OCI `/v2/`
> data-plane + Hydra token-exchange). Three surfaces: control-plane CRUD (newman),
> control-plane authz (newman), and the data-plane + token-exchange bash harness.

## Latest baseline — fe3455

| Surface | Module | Cases / scenarios | Assertions | Failed | Verification |
|---|---|---|---|---|---|
| Control-plane CRUD | `cases/registry.py` | 30 | 150 | 0 | **GREEN on fe3455** |
| Control-plane authz | `cases/registry-authz.py` | 9 | all executed | 0 | **GREEN on fe3455** (3 viewer-tier cases fixture-gated → console-only SKIP, no green assertion) |
| Data-plane OCI proxy + token-exchange | `scripts/dataplane-e2e.sh` | full handshake→push→pull→delete flow | all hard assertions | 0 | **ALL hard assertions GREEN on fe3455** |

### Control-plane CRUD (`cases/registry.py`, 30 cases) — 150 assertions GREEN

All 8 `RegistryService` RPCs exercised black-box through api-gateway REST
(`/registry/v1/registries`), each with happy + negative + corner coverage:

- `Create` — happy (→ Operation, prefix `reo`, poll → ACTIVE), invalid name (regex),
  unknown project (cross-domain reject), duplicate `(project,name)` (ALREADY_EXISTS),
  missing name.
- `Get` — happy (echoes name/projectId), malformed id (400 "invalid registry id"),
  well-formed absent (404 NOT_FOUND).
- `List` — happy (authz-filtered array), bad page-token (INVALID_ARGUMENT),
  page-size BVA, non-member sees empty.
- `Update` — happy (labels+description via mask), unknown mask field, immutable name,
  immutable project, empty-mask full PATCH, not-found.
- `ListRepositories` — happy (per-repo projection), bad token, not-found.
- `ListTags` — happy, bad token, existence-hidden not-found.
- `DeleteTag` — idempotent-absent, malformed id.
- `Delete` — happy (→ Operation → poll → Get 404), not-found, idempotent double-delete;
  plus suite cleanup.

Result: **150 assertions, 0 failed** against the deployed stack.

### Control-plane authz (`cases/registry-authz.py`, 9 cases) — GREEN

Existence-hiding + verb-tier invariants black-box through api-gateway:

- **Stranger / anonymous existence-hiding cases — GREEN.** On this stand a stranger
  dev-JWT carries an unregistered `sub`, so the gateway treats it as UNAUTHENTICATED
  → HTTP 401 (code 16, "subject: unauthenticated request"). The stranger cases
  (`REG-AZ-GET-STRANGER-HIDDEN`, `REG-AZ-LIST-STRANGER-EMPTY`,
  `REG-AZ-CREATE-STRANGER-DENY`) accept the full denied/empty range
  `[200-empty, 401, 403, 404]`, assert **never success-with-data** (List array empty
  when 200; the fixture `regId` is never revealed), and gate the "no `deny_reasons`
  leak" check to responses that are **not** 401 (an unauthenticated 401 carries a
  generic reason, not a resource-existence leak). `REG-AZ-GET-ANON-401` (no bearer
  → 401) is GREEN as-is.
- **Viewer-tier cases — fixture-gated (SKIP on single-user stand).**
  `REG-AZ-GET-VIEWER-OK`, `REG-AZ-UPDATE-VIEWER-DENY`, `REG-AZ-DELETE-VIEWER-DENY`
  each begin with a guard: when `jwtProjectViewerA` is empty they emit a **console-only
  SKIP note and return with no assertion** (previously a passing `pm.test('SKIPPED …')`
  no-op — a green test that verified nothing, inflating the pass count; removed as
  borderline ban #13). With a real viewer token present the full assertions run and are
  enforced. The v_get→NOT_FOUND boundary these cases target is covered unconditionally by
  the Go seam `internal/check/viewer_boundary_test.go`, so the SKIP path reports no
  green, not a false green. fe3455 has exactly one registered IAM user (the
  cluster-admin) and a user's `external_id` is Kratos-IdP-projected — it cannot be
  created via the public API — so a viewer-tier user is not provisionable here.

### Data-plane OCI proxy + token-exchange (`scripts/dataplane-e2e.sh`) — ALL hard assertions GREEN

Bash harness driving the docker CLI + raw HTTP against the live OCI `/v2/` surface and
the Hydra token-exchange. All hard assertions GREEN on fe3455:

- token-mint (IAM `/token` shim → Hydra federation → identity-JWT);
- `GET /v2/` ping without a token → 401, with a valid token → 200;
- push-init (`POST /v2/<repo>/blobs/uploads/`) → 202;
- blob upload + manifest PUT → 201;
- pull (`GET` manifest) → 200 (poll-retry to absorb grant-latency, ~0.6–2s);
- tags list (`GET /v2/<repo>/tags/list`) → present;
- no-auth request → 401 (fail-closed);
- data-plane HTTP `DELETE` → 405 (deletion only via `v_delete`-gated DeleteTag);
- namespace path-traversal (`..` / `%2e%2e`) → 400 (rejected before zot);
- `ListRepositories` — repo registered on first push, visible in the projection.

---

## Real product bugs found by this suite (TDD RED→GREEN, fixed + deployed to fe3455)

> Each was RED against the live stack (a real product defect, not a wrong
> case-expectation), then fixed and re-run GREEN on fe3455. Both are the class of bug
> that unit/integration/mock coverage cannot catch — only e2e through the real gateway
> + authz stack surfaces them.

1. **Registry LRO polling was completely unreachable (403/404).** The api-gateway
   `opsProxy` did not route the registry operation-prefix `rop`, **and** the registry
   `PermissionMap` did not exempt `OperationService.Get`/`Cancel`. Because every
   registry mutation returns an `Operation` that the client must poll, this made
   `Create`/`Update`/`Delete`/`DeleteTag` effectively unusable end-to-end — the
   mutation succeeded but the operation could never be polled to `done`.
   **Fix:** add `OperationService` `Get`/`Cancel` as Public-exempt in the registry
   `check.PermissionMap` (and route the `rop` operation-prefix through opsProxy).

2. **The gateway authz-edge rejected EVERY valid registry id with 400 "invalid
   resource id".** The api-gateway was pinned to a `kacho-corelib` version whose
   `resourceIDPrefixes` allow-list lacked the `reg` / `rop` prefixes. The gateway
   validates resource ids on the authz edge, so every `Get`/`Update`/`Delete` on a
   well-formed `reg…` id was rejected `400 INVALID_ARGUMENT` before reaching the
   service.
   **Fix:** build the gateway against a `kacho-corelib` that carries the `reg`/`rop`
   prefixes. Publishing corelib + re-pinning the gateway to the released version is
   the follow-up (see below); the fix is live on fe3455 via a surgical image.

---

## Known limitations / follow-ups

- **Viewer-tier authz fixture.** The 3 viewer-tier authz cases are fixture-gated and
  SKIP on the single-user fe3455 stand. Full enforcement needs a **registered viewer
  user**; a user's `external_id` is Kratos-IdP-projected and cannot be minted via the
  public API, so this requires provisioning a second IdP identity + a project
  viewer-role grant on the lane. Once `jwtProjectViewerA` is populated the cases run
  and enforce automatically (no code change).
- **corelib publish + gateway re-pin.** The two product fixes above are live on fe3455
  through **surgical images** (`kacho-api-gateway:reg-idprefix`,
  `kacho-registry:opsvc-exempt`), not through the normal release train. Follow-up:
  publish `kacho-corelib` with the `reg`/`rop` `resourceIDPrefixes`, then re-pin
  `kacho-api-gateway` (and the registry service) to the released version and rebuild
  the standard images.

---

## Verification status — authored vs live-verified

> "Authored" = the case/scenario exists and `validate-cases.py`/`gen.py` (or the
> harness shell) parses it. "Live-verified" = **run green against the deployed stack**
> through api-gateway / the OCI `/v2/` surface. Per `testing.md`, unit/integration
> green and pod-health are not proof of function.

| Surface | Authored | Live-verified | Environment / evidence |
|---|---|---|---|
| Control-plane CRUD (`registry.py`, 30) | ✅ | ✅ | fe3455 — 150 assertions, 0 failed |
| Control-plane authz (`registry-authz.py`, 9) | ✅ | ✅ | fe3455 — stranger/anon GREEN; 3 viewer-tier fixture-gated (console-only SKIP, no green) |
| Data-plane OCI proxy + token-exchange (`dataplane-e2e.sh`) | ✅ | ✅ | fe3455 — all hard assertions GREEN (docker CLI + `/v2/` + Hydra) |
| InternalRegistryService (:9091, mTLS) | 🔬 integration | 🔬 | Go integration only (no public REST) |

Legend: ✅ done · ▢ pending · 🔬 covered by Go integration (not newman/harness).

---

## How to re-run

```bash
cd tests/newman
python3 scripts/validate-cases.py                                   # uniqueness + catalogue
python3 scripts/gen.py                                              # regenerate collections
./scripts/run.sh --env environments/fe3455.postman_environment.json --service registry
./scripts/run.sh --env environments/fe3455.postman_environment.json --service registry-authz
./scripts/dataplane-e2e.sh --env environments/fe3455.postman_environment.json
```
