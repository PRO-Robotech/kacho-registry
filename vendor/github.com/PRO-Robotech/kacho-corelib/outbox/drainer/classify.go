// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package drainer

import (
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Class is the outcome of classifying an applier (or decoder) error. It is the
// single, testable decision point that drives whether the drainer marks a row
// success, poisons it (no further retry) or retries it unbounded with backoff.
//
// Transient-class no-poison rule: a long-but-transient IAM outage (gRPC
// Unavailable / DeadlineExceeded / connection-refused / timeout) must NEVER
// poison a row — it retries forever (with backoff) so the owner-tuple is never
// lost to a temporary peer outage. Only permanent errors (4xx-non-409,
// decode-failure, malformed) poison.
type Class int

const (
	// ClassSuccess — nil error; the row is delivered.
	ClassSuccess Class = iota
	// ClassAlreadyApplied — the target reports already-applied (FGA-409 on write,
	// 404 on delete); idempotent success, the row is marked sent.
	ClassAlreadyApplied
	// ClassPermanent — retry is pointless (ErrPermanent, gRPC InvalidArgument /
	// 4xx-non-409, decode-failure). The row is poisoned (attempt_count forced to
	// MaxAttempts) and surfaced for an operator.
	ClassPermanent
	// ClassTransient — a temporary failure (peer Unavailable / DeadlineExceeded /
	// connection-refused / timeout / any unclassified error). The row is retried
	// unbounded with backoff and is NEVER driven into the poison gate.
	ClassTransient
)

// String renders the class for logs/metrics labels.
func (c Class) String() string {
	switch c {
	case ClassSuccess:
		return "success"
	case ClassAlreadyApplied:
		return "already_applied"
	case ClassPermanent:
		return "permanent"
	case ClassTransient:
		return "transient"
	default:
		return "unknown"
	}
}

// Classify maps an applier error to a Class.
//
// Decision order (most-specific first):
//  1. nil                                   → ClassSuccess
//  2. errors.Is(err, ErrAlreadyApplied)     → ClassAlreadyApplied
//  3. errors.Is(err, ErrPermanent)          → ClassPermanent
//  4. gRPC InvalidArgument (4xx-non-409)    → ClassPermanent
//  5. everything else (Unavailable,
//     DeadlineExceeded, PermissionDenied,
//     connection-refused/timeout, raw)      → ClassTransient
//
// Rationale for step 5: the canonical applier classification (compute/nlb) maps
// InvalidArgument → permanent but PermissionDenied / Unavailable → raw transient.
// A raw, un-wrapped error of unknown shape is treated as transient — fail-SAFE
// for delivery (retry rather than lose the tuple). Appliers that KNOW an error is
// permanent must wrap it in ErrPermanent.
func Classify(err error) Class {
	if err == nil {
		return ClassSuccess
	}
	if errors.Is(err, ErrAlreadyApplied) {
		return ClassAlreadyApplied
	}
	if errors.Is(err, ErrPermanent) {
		return ClassPermanent
	}
	if isPermanentGRPC(err) {
		return ClassPermanent
	}
	// Unavailable / DeadlineExceeded / PermissionDenied / connection errors /
	// any unclassified error → transient (never poison).
	return ClassTransient
}

// isPermanentGRPC reports whether err carries a gRPC status code that is
// permanent on the applier side. Only InvalidArgument is permanent here; the
// other 4xx-style codes (PermissionDenied, NotFound, FailedPrecondition) are
// treated as transient because they can be the symptom of a not-yet-provisioned
// peer (e.g. apps-SA fga_writer grant not yet applied) which heals without
// poisoning. Appliers wrap genuinely-permanent cases in ErrPermanent.
func isPermanentGRPC(err error) bool {
	st, ok := status.FromError(err)
	if !ok {
		return false
	}
	return st.Code() == codes.InvalidArgument
}
