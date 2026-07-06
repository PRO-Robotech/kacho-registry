// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package operations

import "context"

// principalCtxKey — приватный тип-ключ для context.WithValue, чтобы исключить
// коллизии с другими пакетами (Go anti-pattern: string-key в ctx).
type principalCtxKey struct{}

// principalClearedKey помечает ctx как «principal явно снят» — для scrub'а
// forwarded-principal на недоверенном peer'е (transport-слой устанавливает это,
// когда forwarder не прошел trust-проверку). Снятие имеет приоритет над любым
// ранее установленным WithPrincipal, чтобы подделанный носитель не просочился.
type principalClearedKey struct{}

// WithoutPrincipal снимает principal с ctx (anonymous). После него
// PrincipalFromContextOK возвращает ok=false независимо от ранее установленного
// WithPrincipal. Используется transport-слоем для defense-in-depth-scrub'а на
// недоверенном peer'е.
func WithoutPrincipal(ctx context.Context) context.Context {
	return context.WithValue(ctx, principalClearedKey{}, true)
}

// WithPrincipal кладет Principal в context. Используется auth-interceptor'ом
// api-gateway: после валидации JWT и резолва subject через kacho-iam
// interceptor вызывает WithPrincipal и пробрасывает ctx дальше в handler.
//
// Без auth ctx остается пустым и PrincipalFromContext возвращает
// SystemPrincipal().
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalCtxKey{}, p)
}

// PrincipalFromContext извлекает Principal из ctx. Если ctx пустой (нет
// auth-interceptor'а, фоновый job, тест) — возвращает SystemPrincipal().
//
// Use-case вызывает PrincipalFromContext в начале обработки мутации и
// передает результат в repo.CreateWithPrincipal:
//
//	p := operations.PrincipalFromContext(ctx)
//	if err := repo.CreateWithPrincipal(ctx, op, p); err != nil { ... }
func PrincipalFromContext(ctx context.Context) Principal {
	p, _ := PrincipalFromContextOK(ctx)
	return p
}

// PrincipalFromContextOK извлекает Principal из ctx и отдельно сообщает, был ли
// он явно установлен (WithPrincipal). При ok=false ctx не нес Principal'а
// (anonymous / нет auth-interceptor'а) и возвращается SystemPrincipal()-fallback.
//
// Этот вариант нужен authz-слою, чтобы отличить АНОНИМНЫЙ запрос (ctx без
// Principal'а) от ЯВНО установленного system-principal: первый обязан fail-closed,
// второй может быть пропущен опцией AllowSystemPrincipal. PrincipalFromContext
// такого различения не дает (оба → SystemPrincipal()).
func PrincipalFromContextOK(ctx context.Context) (Principal, bool) {
	if ctx == nil {
		return SystemPrincipal(), false
	}
	if cleared, _ := ctx.Value(principalClearedKey{}).(bool); cleared {
		// Явный scrub имеет приоритет над любым ранее установленным principal'ом.
		return SystemPrincipal(), false
	}
	if v, ok := ctx.Value(principalCtxKey{}).(Principal); ok {
		return v, true
	}
	return SystemPrincipal(), false
}
