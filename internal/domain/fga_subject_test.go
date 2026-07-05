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
