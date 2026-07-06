// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package grpcsrv — acr.go: the SHARED ACR (Authentication Context Class
// Reference) ranking used by BOTH the api-gateway public step-up gate and the
// kacho-iam internal acr-floor, so the two never drift.
//
// ACR ordering (normative):
//
//	"" / "0" (anonymous)  <  "1" (password-only, AAL1)  <
//	"2" (phishing-resistant / MFA, AAL2)  <  "3" (hardware-bound UV passkey, AAL3)
//
// An unknown value ranks 0 (fail-closed). `required==""` (or "0") means NO
// requirement — ACRSatisfies always returns true (mirrors the public
// StepUpGate.Check `RequiredACRMin==""` no-op).
package grpcsrv

// MDKeyTokenACR is the trusted metadata key carrying the validated JWT `acr`
// claim, forwarded by the api-gateway on the mTLS-verified gateway→iam re-dial
// (alongside x-kacho-principal-*). It is read ONLY under the trust invariant
// (see UnaryTrustedPrincipalExtract) — on an unverified peer it is dropped with
// the principal (anti-spoof).
const MDKeyTokenACR = "x-kacho-token-acr" // #nosec G101 -- gRPC metadata header key, not a credential (the "token" substring is a false positive)

// ACRRank maps an ACR string to a comparable integer. Unknown / malformed
// values resolve to 0 (anonymous) — fail-closed when policy expects ≥ 1. This
// is the single source of truth for ACR ranking across Kachō.
func ACRRank(acr string) int {
	switch acr {
	case "3":
		return 3
	case "2":
		return 2
	case "1":
		return 1
	case "0", "":
		return 0
	default:
		return 0
	}
}

// ACRSatisfies reports whether a presented acr meets a required floor.
//
//   - required == "" or "0" → no requirement → always true (no-op floor).
//   - otherwise → ACRRank(presented) >= ACRRank(required).
//
// An absent / unknown presented acr ranks 0, so it fails any positive floor
// (fail-closed).
func ACRSatisfies(presented, required string) bool {
	if ACRRank(required) == 0 {
		return true
	}
	return ACRRank(presented) >= ACRRank(required)
}
