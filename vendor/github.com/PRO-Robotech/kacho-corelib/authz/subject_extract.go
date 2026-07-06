// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package authz

import (
	"context"

	"github.com/PRO-Robotech/kacho-corelib/operations"
)

// defaultSubjectExtractor — стандартная реализация на основе
// operations.PrincipalFromContextOK.
//
// Возвращает:
//   - subjectFGA — "user:usr_xxx" или "service_account:sva_xxx"
//   - principalID — raw ID (для rate-limit-bucket'а)
//   - ok — false если ctx не нес Principal'а (anonymous) либо ID пустой
//
// Anonymous-запрос (ctx без Principal'а) дает ok=false → interceptor fail-closed
// (denied) еще до Check. Это закрывает обход: иначе fallback на SystemPrincipal()
// делал бы anonymous неотличимым от bootstrap и при AllowSystemPrincipal=true
// пропускал бы его. Явно установленный system-principal (WithPrincipal) дает
// ok=true и обрабатывается опцией AllowSystemPrincipal штатно.
func defaultSubjectExtractor(ctx context.Context) (string, string, bool) {
	p, ok := operations.PrincipalFromContextOK(ctx)
	if !ok || p.ID == "" {
		return "", "", false
	}
	return FormatSubject(p.Type, p.ID), p.ID, true
}

// isAnonymousSubject — helper. Returns true для всех принципалов
// эквивалентных anonymous (closed-list match):
//
//   - empty subject / empty principal_id
//   - principal_id == "anonymous" (api-gateway injectAnonymous case)
//   - subject == "system:anonymous"
//   - principal_id == "bootstrap" / subject == "system:bootstrap"
//     (PrincipalFromContext fallback когда ctx без Principal — api-gateway
//     не передал x-kacho-principal-* metadata headers).
//
// Используется в breakglass-path: даже когда authz-Check недоступен,
// anonymous request'ы должны быть denied.
func isAnonymousSubject(extract func(context.Context) (string, string, bool), ctx context.Context) bool {
	subjectFGA, principalID, ok := extract(ctx)
	if !ok || principalID == "" || subjectFGA == "" {
		return true
	}
	if principalID == "anonymous" || principalID == "bootstrap" {
		return true
	}
	if subjectFGA == "system:anonymous" || subjectFGA == "system:bootstrap" {
		return true
	}
	return false
}
