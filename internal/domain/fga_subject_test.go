// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

// fga_subject_test.go — единый источник subject-encoding: FGASubjectFromID
// (data-plane, id-prefix) обязан совпадать с FGASubjectFromPrincipal
// (control-plane, Principal.Type) для тех же principal'ов, иначе owner-tuple,
// записанный control-plane, не матчится Check'ом data-plane (deny владельцу).

import "testing"

func TestFGASubjectFromID(t *testing.T) {
	cases := []struct {
		name string
		id   string
		want string
	}{
		{"user-prefix", "usr_alice", "user:usr_alice"},
		{"service-account-prefix", "sva_ci", "service_account:sva_ci"},
		{"empty", "", ""},
		{"unknown-prefix-defaults-to-sa", "grp_admins", "service_account:grp_admins"},
		{"legacy-dash-user", "usr-legacy", "user:usr-legacy"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := FGASubjectFromID(c.id); got != c.want {
				t.Fatalf("FGASubjectFromID(%q) = %q, want %q", c.id, got, c.want)
			}
		})
	}
}

// TestFGASubjectForPrincipalID_Anon — RG-1 D-7: the data-plane resolves the
// configured anonymous principal id (the iam-issued anon Hydra client id) to the FGA
// wildcard FGASubjectPublicWildcard ("user:*"); every other id resolves by id-prefix
// via FGASubjectFromID. Empty anonPrincipalID → anonymous disabled (the token, if
// any, resolves as an ordinary principal — secure-by-default). This is the single
// mapping point a VALID anon Bearer becomes the public read-only principal (B03/B14).
func TestFGASubjectForPrincipalID_Anon(t *testing.T) {
	const anonID = "cid-registry-anon"
	cases := []struct {
		name    string
		id      string
		anonID  string
		want    string
	}{
		// Configured anon id → wildcard user:* (B03 anon pull, B14 anon no-write).
		{"anon-id-configured-maps-to-wildcard", anonID, anonID, FGASubjectPublicWildcard},
		{"wildcard-equals-user-star", anonID, anonID, "user:*"},
		// A real SA is unaffected even when anon is enabled (resolves by prefix).
		{"sa-unaffected-when-anon-enabled", "sva_ci", anonID, "service_account:sva_ci"},
		{"user-unaffected-when-anon-enabled", "usr_alice", anonID, "user:usr_alice"},
		// Anonymous DISABLED (empty anonID): even the anon-shaped id resolves as an
		// ordinary principal (never silently becomes user:*) — secure-by-default.
		{"anon-disabled-empty-anonid-no-wildcard", anonID, "", "service_account:cid-registry-anon"},
		{"empty-id-empty-anonid", "", "", ""},
		// Anon enabled but a DIFFERENT sub arrives → not the anon principal.
		{"different-sub-not-anon", "sva_other", anonID, "service_account:sva_other"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := FGASubjectForPrincipalID(c.id, c.anonID); got != c.want {
				t.Fatalf("FGASubjectForPrincipalID(%q, %q) = %q, want %q", c.id, c.anonID, got, c.want)
			}
		})
	}
}

// TestFGASubject_TwoEncodersAgree — оба encoder'а (id-prefix vs Principal.Type)
// дают идентичную subject-строку для согласованных id/type пар (инвариант против
// рассинхронизации planes, ради которой vocabulary централизован в domain).
func TestFGASubject_TwoEncodersAgree(t *testing.T) {
	pairs := []struct {
		pType string
		id    string
	}{
		{"user", "usr_alice"},
		{"service_account", "sva_ci"},
	}
	for _, p := range pairs {
		fromID := FGASubjectFromID(p.id)
		fromPrincipal := FGASubjectFromPrincipal(p.pType, p.id)
		if fromID != fromPrincipal {
			t.Fatalf("encoders disagree for (%q,%q): fromID=%q fromPrincipal=%q",
				p.pType, p.id, fromID, fromPrincipal)
		}
	}
}
