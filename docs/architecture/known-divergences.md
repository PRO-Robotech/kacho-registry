# Known architectural divergences — kacho-registry

Deliberate, reviewed deviations from a strict Clean-Architecture reading. Recorded
here (per workspace CLAUDE.md «Не баг … Документировать осознанные by-design
отклонения») so they are not re-filed as defects. Each entry states the rule, the
divergence, why it is accepted, and what would change the decision.

## 1. Use-case layer imports gRPC status + proto stubs (LRO envelope)

**Rule.** Clean Architecture: `service/` (use-case) imports only `domain`; grpc-stubs
/ `status` / proto are adapter concerns and belong in `handler/`.

**Divergence.** `internal/apps/kacho/api/registry` imports `google.golang.org/grpc/codes`
+ `status` (direct `status.Error` for sync input-validation), `registryv1` proto-stubs
and `anypb` (`ProtoRegistry`, `CreateRegistryMetadata`, `registryAny`).

**Why accepted.**
- **Inherent to the kachō async-LRO pattern.** Every mutation returns an
  `operation.Operation`; its `response`/`metadata` are `google.protobuf.Any`, and the
  worker closure that finalises the operation lives *in the use-case* (it captures the
  request-ctx principal and the created domain object). Serialising the domain result
  into a proto `Any` therefore happens inside the use-case by construction — the proto
  import cannot be removed from this package no matter how the error path is refactored.
  This matches the established kachō LRO layout (godzila skill: "async Operation LRO
  envelope", use-case owns the worker).
- **No dual error contract in practice.** The hand-rolled `status.Error(codes.…)` calls
  and the sentinel path both funnel through `handler/maperr.go → serviceerr.ToStatus`,
  which passes pre-built gRPC statuses through unchanged (`serviceerr.go` FromError
  arm). Sync return and async `Operation.error` are produced by the *same* mapper, so
  there is exactly one observable code/text per condition.
- **Error text is a Kachō style contract.** The exact messages ("Illegal argument: …",
  "registry %s already exists", "project %s not found") are part of the API surface
  (CLAUDE.md YC-style error-format). A blanket rewrite to sentinels risks silently
  altering those strings for a low-severity purity gain.

**What would revisit this.** If a non-gRPC transport is ever added, extract the
proto-`Any` serialisation behind a mapper injected at the composition root and move the
sync-validation `status.Error` calls to `regerrors.*` sentinels mapped solely in the
handler. Until then the coupling is confined to the LRO envelope and reconciled by a
single mapper.

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
