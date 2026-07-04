# RESULTS — kacho-registry newman + data-plane run history

> Baseline established with the initial check-in of the registry newman suite.
> Updated after every run via `scripts/run.sh` → `out/summary.txt` and the data-plane
> harness `scripts/dataplane-e2e.sh`. Fill the TBD cells after each execution.

## Latest baseline

| Surface | Module | Cases / scenarios | Assertions | Failed | Verification |
|---|---|---|---|---|---|
| Control-plane CRUD | `registry` | 9 | TBD | TBD | authored — live-run TBD |
| Control-plane authz | `registry-authz` | 12 intended | TBD | TBD | **pending** (file not yet authored) |
| Data-plane OCI proxy | `dataplane-e2e.sh` | 18 intended | TBD | TBD | **pending** (harness not yet authored) |
| Token-exchange (Hydra) | `dataplane-e2e.sh` | 22 intended | TBD | TBD | **pending** (harness not yet authored) |
| **TOTAL** | — | ≥61 | TBD | TBD | — |

Until the concurrently-authored `cases/registry-authz.py` and `scripts/dataplane-e2e.sh`
land, the suite is **structurally valid** for the 9 control-plane CRUD cases
(`validate-cases.py` passes, `gen.py` produces a parseable collection) but the authz and
data-plane surfaces are not yet executable.

## Version history

| Date | Suite version | Cases | Failed | Notes |
|---|---|---|---|---|
| YYYY-MM-DD | v0 baseline | 9 (control-plane CRUD) | n/a | Initial check-in: `cases/registry.py` + scripts + docs scaffold; collection generated; authz + data-plane pending. |

After each run, paste `out/summary.txt` into a new row above and update the
**Latest baseline** table.

---

## Known failing — product bugs

> A row here means: a case is **red against the live stack** because the product
> misbehaves (not a wrong case-expectation). Each entry MUST carry a GitHub Issue
> (`bug` + `verified-by:test`), a `# verifies <issue-url>` annotation in the case/harness,
> and a KAC-trail. Remove the row when the product is fixed and the case goes green.

| Case / scenario | REG-NN | Symptom (observed) | Expected (acceptance) | Issue | Status |
|---|---|---|---|---|---|
| _(none yet — populate after first live run)_ | — | — | — | — | — |

If the first live run is 100% green, keep this section with the "(none yet)" row so the
absence of product bugs is explicit (as in the reference nlb suite).

---

## Triage & corrections (per run)

> Not every red assertion is a product bug. Classify each failure before declaring "done":
>
> - **timing** — async Operation not yet `done` on first poll → increase `run.sh --delay`
>   or poll longer; not a bug.
> - **grant-latency** — authz-filtered `List` / data-plane Check right after a grant not yet
>   propagated (~0.6–2s) → poll-retry; not a bug.
> - **wrong case-expectation** — the case asserted a contract that contradicts the
>   convention-correct product behaviour (verify in source) → correct the case, record the
>   before→after + product justification here.
> - **fixture-limit** — a required seed (project, SA-key, zot image, Hydra client) absent on
>   the lane → provision or gate tolerantly; not a bug.
> - **product bug** — everything else → open an Issue and add a row to *Known failing* above.

| Run date | Case / scenario | Class | Before → After / resolution | Justification (source) |
|---|---|---|---|---|
| _(populate per run)_ | — | — | — | — |

---

## Verification status — authored vs live-verified

> "Authored" = the case/scenario exists and `validate-cases.py`/`gen.py` (or the harness
> shell) parses it. "Live-verified" = it has been **run green against the deployed stack**
> through api-gateway / the OCI `/v2/` surface. Per `testing.md`, unit/integration green and
> pod-health are **not** proof — a feature is not "done" until the relevant surface is
> live-verified. State "NOT verified e2e" honestly where the stand was unavailable.

| Surface | Authored | Live-verified | Environment / evidence |
|---|---|---|---|
| Control-plane CRUD (`registry.py`, 9) | ✅ | TBD | fe3455 / `out/registry.json` — TBD |
| Control-plane authz (`registry-authz.py`, 12) | ▢ pending | ▢ | — |
| Data-plane OCI proxy (`dataplane-e2e.sh`, 18) | ▢ pending | ▢ | — |
| Token-exchange (`dataplane-e2e.sh`, 22) | ▢ pending | ▢ | — |
| InternalRegistryService (:9091, mTLS) | 🔬 integration | 🔬 | Go integration only (no public REST) |

Legend: ✅ done · ▢ pending · 🔬 covered by Go integration (not newman/harness).

---

## Acceptance gate

Production-readiness (MVP acceptance §12 + token-exchange functional-gate REG-TX-22):
the registry newman surfaces (control-plane CRUD + authz) and the data-plane + Hydra
harness must be **100% green against the live stack**, with every REQUIRED cell in
`TEST-PLAN.md` covered. Verified by the `newman-e2e` workflow (`kacho-deploy`) once the
registry epic reaches deployable state; the data-plane/token harness is verified on fe3455
with the docker CLI + live Hydra.

## How to re-run

```bash
cd tests/newman
python3 scripts/validate-cases.py                                   # uniqueness + catalogue
python3 scripts/gen.py                                              # regenerate collections
./scripts/run.sh --env environments/fe3455.postman_environment.json --service registry
./scripts/run.sh --env environments/fe3455.postman_environment.json --service registry-authz
./scripts/dataplane-e2e.sh --env environments/fe3455.postman_environment.json
```

Then paste `out/summary.txt` into **Version history** and update the **Latest baseline**,
**Known failing**, and **Verification status** tables above.
