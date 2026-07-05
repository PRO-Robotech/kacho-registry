# Known architectural divergences — kacho-registry

Deliberate, reviewed deviations from a strict Clean-Architecture reading. Recorded
here (per workspace CLAUDE.md «Не баг … Документировать осознанные by-design
отклонения») so they are not re-filed as defects. Each entry states the rule, the
divergence, why it is accepted, and what would change the decision.

## 1. Use-case layer imports gRPC status + proto stubs (LRO envelope)

**Rule.** Clean Architecture: `service/` (use-case) imports only `domain`; grpc-stubs
/ `status` / proto are adapter concerns and belong in `handler/`.

**Divergence.** `internal/apps/kacho/api/registry` imports `registryv1` proto-stubs and
`anypb` (`ProtoRegistry`, `CreateRegistryMetadata`, `registryAny`) — the LRO envelope.

**R3 update (2026-07-05, sec-hardening-r3).** The *error path* leak flagged by the 3rd
audit is closed: the use-case no longer imports `google.golang.org/grpc/codes` /
`status` and no longer hand-codes gRPC codes. Every use-case error is now expressed as a
`regerrors.*` domain sentinel and mapped through the **single** `serviceerr.ToStatus`
seam via the `errmap.go` helpers (`failInvalidArg` / `failFailedPrecondition` /
`failAlreadyExists` / `failUnavailable`). `grep -R 'grpc/status\|grpc/codes'
internal/apps/kacho/api/registry` is now empty. Exact error texts are preserved (the
sentinel wraps the same message; `serviceerr` strips the sentinel prefix), so the wire
contract is unchanged. The residual documented below is now **only** the proto/`Any` LRO
envelope, not error transport.

**Why the proto/`Any` residual is accepted.**
- **Inherent to the kachō async-LRO pattern.** Every mutation returns an
  `operation.Operation`; its `response`/`metadata` are `google.protobuf.Any`, and the
  worker closure that finalises the operation lives *in the use-case* (it captures the
  request-ctx principal and the created domain object). Serialising the domain result
  into a proto `Any` therefore happens inside the use-case by construction — the proto
  import cannot be removed no matter how the error path is refactored. This matches the
  established kachō LRO layout (godzila skill: "async Operation LRO envelope", use-case
  owns the worker). `corelib operations.Run` maps the worker error via
  `status.FromError`, so the worker closure must yield a gRPC status (a bare sentinel
  would collapse to INTERNAL) — the `serviceerr` seam supplies exactly that.
- **Established test contract.** 25+ use-case unit assertions call `status.Code()` on
  the use-case return (the use-case *is* the layer producing the gRPC-shaped LRO
  envelope); inverting to bare sentinels would require rewriting them for no wire change.

**What would revisit this.** If a non-gRPC transport is ever added, extract the
proto-`Any` serialisation behind a mapper injected at the composition root. Until then
the coupling is confined to the LRO envelope and reconciled by a single mapper.

## 2. Data-plane OCI proxy has no separate use-case layer

**Rule.** Thin handler: no domain-state branching or resource-lifecycle side-effects in
transport (`handler/`).

**Divergence.** `internal/dataplane/handler.go` decides the push verb from repo state
(`RepoExists → v_update@repository` else `v_create@registry`), emits the
register-on-first-push intent, and encodes the cross-repo mount exfil-guard directly in
the HTTP handler; there is no `service/` layer under `internal/dataplane`.

**Why accepted.**
- The data-plane is a **transport-level OCI auth-proxy**, deliberately designed as an
  orchestrator over injected ports (`TokenVerifier`, `Authorizer`, `Backend`,
  `Forwarder`, `RepoRegistrar`, `RegistryLookup`) — parse → verify → authz → forward.
  Its "business logic" is a small, fixed authorization policy (exists→verb table,
  exfil-guard, register-on-first-push), not a rich domain model.
- That policy is **fully unit-tested** against fakes in
  `internal/dataplane/handler_test.go` (verb selection, existence-hiding, mount guard,
  register-on-first-push emission), so it is not un-testable transport code in practice.
- The authorization vocabulary it uses is already centralised in `internal/domain`
  (verb-relations, object refs, subject encoding) — the transport only *applies* it.

**What would revisit this.** If a second consumer needs the same "first-push
materialises repo authz object" decision, or the verb-mapping policy grows beyond the
current fixed table, extract a `dataplane` use-case (AuthorizePush / AuthorizePull /
RegisterOnFirstPush) owning the decision and leave the handler to translate it to HTTP
status codes.

## 3. Cross-service (registry ↔ zot) TOCTOU windows are software-validated, not DB-enforced

**Rule.** CLAUDE.md «Within-service refs — DB-уровень обязателен» (#10): every reference
and invariant *inside one service DB* must be a DB construct (FK / UNIQUE / EXCLUDE /
CAS); software `check → act` is forbidden.

**Divergence (by rule's own cross-service exception).** Two narrow windows exist across
the registry-DB ↔ zot boundary — a *different DB / different service* boundary that rule
#10 and #8 explicitly exempt (no cross-DB FK possible):

- **Delete-vs-push** (`internal/apps/kacho/api/registry/delete.go`): `doDelete` CAS-marks
  the registry `DELETING`, re-checks `zot.NamespaceEmpty` **after** the CAS, then
  physically DELETEs the row + emits the unregister-intent. A push authorized *before*
  tuple removal could land content in the gap between the second `NamespaceEmpty()==true`
  check and the final DELETE.
- **DeleteTag emptiness** (`deletetag.go` `unregisterRepoIfEmpty`): after deleting the
  last tag it reads `zot.ListTags`; if empty it emits the repo unregister-intent. A push
  landing a new tag between the read and the emit strips a parent-tuple the push just
  created.

**Why accepted.**
- **The boundary is cross-service** (registry Postgres vs zot's own store) — DB
  constraints cannot span it (database-per-service, #8). Rule #10 keeps software
  validation + graceful dangling-ref as the sanctioned pattern precisely here.
- **Defense-in-depth already in place.** Delete is `forward-only` and re-checks
  `NamespaceEmpty` *after* the CAS→DELETING (a real second guard, not a single
  check-then-act), and `zot`-unavailable → `Unavailable`/`FailedPrecondition`
  (fail-closed, retriable) rather than a destructive erase.
- **Self-healing.** Register-on-first-push re-materialises any stripped repo/namespace
  authz object on the next push; the transient state is an existence-hiding `NOT_FOUND`,
  never a cross-tenant leak or data-loss of committed metadata.

**What would revisit this.** A true write-fence: gate data-plane push authorization on
registry status (deny push while `DELETING`) so `DELETING` becomes a hard fence, and/or
order the register/unregister intents by a per-repo monotonic marker (the
`registry_outbox.source_version` BIGSERIAL from migration 0002 already gives
commit-order monotonicity for registries — extending it to repo intents would let
register-on-push always win). Both are behavioural changes to the push path and are
tracked as follow-ups rather than folded into a contracts-frozen hardening pass.

## 4. Platform config via envconfig struct-tags (not viper/koanf YAML)

**Rule.** evgeniy regime: service config is YAML via viper/koanf, not `envconfig`
struct-tags.

**Divergence.** `internal/apps/kacho/config/config.go` loads config from env via
`corelib config.LoadPrefixed` with `envconfig:"…"` struct-tags.

**Why accepted.** This is the **platform-wide** corelib convention
(`corecfg.LoadPrefixed` is used identically by every `kacho-*` service). It is a
regime-conformance choice made once at the corelib layer, not a registry-local defect;
changing it is a workspace-wide migration of `kacho-corelib/config` under a dedicated
release phase, out of scope for a single-service hardening pass. No runtime defect —
only the layered-profile / hot-reload affordances of viper/koanf are unavailable.

**What would revisit this.** A platform decision to migrate `kacho-corelib/config` to
viper/koanf YAML with env override; then every service (including this one) follows.

## 5. Authenticated-deny → 404 existence-hiding: live e2e assertion blocked on test infra

**Rule.** CLAUDE.md #12: security invariants are enforced end-to-end, not only by unit
fakes.

**Gap (test-infrastructure, not code).** The core tenant-isolation invariant —
*authenticated non-member sees `NOT_FOUND` (existence-hidden), never a 403 leak, never
success-with-data* — has no **live** black-box (Newman-through-gateway) assertion. The
single-user dev stand registers exactly one IAM identity (cluster-admin); a dev-JWT with
an unregistered `sub` is treated as `UNAUTHENTICATED` (401), so `jwtStranger` cases
cannot drive an *authenticated-but-ungranted* request, and the viewer-tier cases are
fixture-gated (SKIP while `jwtProjectViewerA` is empty). See
`tests/newman/cases/registry-authz.py` docstring.

**Current mitigation (runnable in CI, no stand).**
- Real authz-seam: `internal/check/viewer_boundary_test.go` runs the **real** corelib
  authz-interceptor over the registry `PermissionMap` with a fake `CheckClient` granting
  exactly `v_get`, asserting Update/Delete → `NOT_FOUND` (existence-hidden) for an
  authenticated principal. Not a handler fake — the production interceptor + map.
- Handler ScopeFiltered path: `internal/handler/listauthz_test.go`
  (`TestHandler_REG22_ListRepositories_NamespaceDeny_NotFound`, `REG24` deny) drives an
  **authenticated** principal (`carolCtx`) with a denying authorizer →
  `NOT_FOUND`, and `filterRegistries`/`filterRepos` return empty (not 403) — the exact
  production `repoAuthz` logic, only the network Check faked.

**Why not closed here.** Closing the *live* gap requires provisioning a second IdP
identity + a project-scoped viewer grant on the deployed stand — test-environment
infrastructure, not a contract-safe code change, and not exercisable from a
build/test-only hardening pass. Shipping Newman Python that cannot be run here would be
unverified test code (against the verification discipline).

**What would revisit this.** Provision `jwtProjectViewerA` (second IdP identity + viewer
role grant) on the stand; the three fixture-gated viewer cases in `registry-authz.py`
then enforce authenticated-deny→404 automatically with no code change.

## 6. ScopeFiltered-RPC row-filter / existence-hiding lives in `handler/listauthz.go`, not the use-case

**Rule.** Thin handler: no domain-state / security decisions in transport; per-object
authz belongs with the use-case.

**Divergence.** For the three `ScopeFiltered` collection RPCs
(`List` / `ListRepositories` / `ListTags`) the per-object authz — row-filter,
existence-hiding (`deny → NOT_FOUND`), fail-closed on iam.Check error — is applied by
`internal/handler/listauthz.go` (`repoAuthz.filterRegistries` / `filterRepos` /
`namespaceGate` / `checkRepo`), *after* the use-case returns the unfiltered set. These
RPCs are deliberately marked `ScopeFiltered` so the per-RPC authz-interceptor skips them
(a single-object Check cannot express row-filter + existence-hiding at once).

**Why accepted.**
- `repoAuthz` is a **distinct authz component** wired into the handler, not ad-hoc
  transport branching — the package doc treats `use-case/authz` as a peer decision layer
  («ветвления по domain-state — в use-case/authz»). It is the *same* `Authorizer` port
  and the *same* centralised `internal/domain` verb-relations / object-refs the
  interceptor and data-plane use; drift between planes is structurally excluded.
- It is **directly unit-tested** as the production authz seam
  (`internal/handler/listauthz_test.go`: authenticated-deny → `NOT_FOUND`, filters return
  empty not 403) — see divergence #5 — so it is not un-testable transport code.
- Pushing the filter into the use-case would force the use-case to emit transport-shaped
  `NOT_FOUND`/`UNAVAILABLE` existence-hiding (a gRPC-status concern) or a bespoke
  hidden-existence sentinel + rewiring the `Authorizer` port through every `List*`
  signature and its unit tests — trading one layering seam for another with no wire
  change and real regression surface on security-critical code.

**What would revisit this.** A second consumer of `uc.List` / `uc.ListRepositories`
(e.g. a REST projection or a new admin RPC) that must not re-implement the filter:
introduce an authz-scoped list use-case returning already-filtered domain results plus a
hidden-existence sentinel, and reduce the handler to sentinel→gRPC-status translation.
Until a second caller exists, the single filtered path is the whole surface and the risk
the finding describes (a future caller forgetting to filter) has no live instance.

## 7. Newman black-box suite is not gated by the per-repo `ci.yaml`

**Rule.** testing.md: the Newman/Postman suite is the primary regression infra; a new
RPC/field ships its Newman case in the same PR.

**Divergence.** `.github/workflows/ci.yaml` runs only build-vet-test (unit `-short`),
integration (testcontainers `./internal/repo/...`), lint and govuln. The black-box
Newman collections (`tests/newman/cases/registry.py`, `registry-authz.py`) and the
data-plane harness (`scripts/dataplane-e2e.sh`) are **not** invoked by any workflow in
this repo — they run against a deployed stand via `tests/newman/scripts/run.sh` /
`dataplane-e2e.sh`.

**Why accepted.**
- Newman is a **through-the-gateway black box**: it needs a live api-gateway + Hydra
  token-exchange + IAM/OpenFGA + zot + Postgres — i.e. the aggregate deployed stack. Per
  `polyrepo.md`, e2e-through-api-gateway is owned by the deployed stand
  (`kacho-deploy` / `kacho-test`), not by a per-service unit-CI runner that has no such
  stack. Spinning the full multi-service topology inside this repo's `ci.yaml` would
  duplicate the deploy repo's responsibility.
- The cases/collections **are** authored, `validate-cases.py`/`gen.py`-clean and
  committed, so the regression assets exist and are review-gated; only their *execution*
  is deferred to the stand. Shipping a CI job that cannot bring up the stack would be a
  perpetually-red or perpetually-skipped job (no signal), which the verification
  discipline forbids.
- REST-contract / gateway-wiring / cross-service-authz regressions are additionally
  guarded here by build-time seams: `internal/handler/*_test.go` (ScopeFiltered authz),
  `internal/check/viewer_boundary_test.go` (real corelib interceptor + PermissionMap),
  and the dataplane unit suite.

**What would revisit this.** A shared CI action in `kacho-deploy`/`kacho-test` that
stands the stack up and runs `run.sh` + `dataplane-e2e.sh` on registry PRs (e.g. via a
`repository_dispatch` from this repo). At that point wire this repo's PRs to trigger it;
until the stand-in-CI exists, the suite is gated at the aggregate-e2e layer.
