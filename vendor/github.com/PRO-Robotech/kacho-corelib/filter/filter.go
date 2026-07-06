// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package filter — простой парсер filter-выражений API Kachō.
//
// Текущая поддержка:
//
//	<field> = "<value>"
//
// Где <field> — whitelisted set (например "name"), <value> — double-quoted
// строка. Возвращает (FilterAST, error). FilterAST использует SQL-binding
// (без string concat) при превращении в WHERE clause.
//
// Формат сообщений об ошибках:
//
//	"Bad expression at column N. Unknown field: \"<field>\""
//	"Bad expression at column N. Expected an operator"
//	"Bad expression at column N. Expected a string, integer, date-time or boolean value"
//
// Поддержка AND/OR/STARTS_WITH/IN — отложена.
package filter

import (
	"fmt"
	"strings"
)

// FilterAST — узел AST. Для текущего узла-минимума: одно equals.
type FilterAST struct {
	Field string
	Op    string // "="
	Value string
}

// ParseError — ошибка парсинга с message в фиксированном формате.
type ParseError struct {
	Column  int
	Message string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("Bad expression at column %d. %s", e.Column, e.Message)
}

// Parse разбирает filter-выражение.
// allowedFields — whitelist полей.
//
// Возвращает (nil, nil) для пустого input — означает "no filter".
// Возвращает *FilterAST или *ParseError.
func Parse(input string, allowedFields []string) (*FilterAST, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, nil
	}

	// 1. Извлекаем имя поля
	col := 1
	i := 0
	fieldStart := i
	for i < len(input) && (isAlpha(input[i]) || input[i] == '_' || input[i] == '.') {
		i++
	}
	field := input[fieldStart:i]
	if field == "" {
		return nil, &ParseError{Column: col, Message: "Expected a field name"}
	}
	// Проверяем whitelist
	allowed := false
	for _, f := range allowedFields {
		if f == field {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, &ParseError{Column: col, Message: fmt.Sprintf("Unknown field: %q", field)}
	}

	// 2. Пропускаем (опциональные) пробелы
	for i < len(input) && input[i] == ' ' {
		i++
	}

	// 3. Оператор: единственный поддерживаемый сейчас — `=`
	if i >= len(input) || input[i] != '=' {
		return nil, &ParseError{Column: i + 1, Message: "Expected an operator"}
	}
	i++

	// 4. Опциональные пробелы
	for i < len(input) && input[i] == ' ' {
		i++
	}

	// 5. Значение: должно быть в "..." (double-quoted string)
	if i >= len(input) || input[i] != '"' {
		return nil, &ParseError{Column: i + 1, Message: "Expected a string, integer, date-time or boolean value"}
	}
	i++ // открывающая "
	valStart := i
	for i < len(input) && input[i] != '"' {
		i++
	}
	if i >= len(input) {
		return nil, &ParseError{Column: i + 1, Message: "Expected closing quote"}
	}
	value := input[valStart:i]
	i++ // закрывающая "

	// 6. Хвост — должен быть пустой
	for i < len(input) && input[i] == ' ' {
		i++
	}
	if i < len(input) {
		return nil, &ParseError{Column: i + 1, Message: "Unexpected token"}
	}

	return &FilterAST{Field: field, Op: "=", Value: value}, nil
}

func isAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// ToSQL превращает AST в безопасный SQL fragment.
// Возвращает (whereFragment, args). whereFragment использует placeholder $N,
// где N стартует с argStartIdx.
//
// Например: ast{Field:"name",Op:"=",Value:"foo"}, argStartIdx=3
//
//	→ ("name = $3", []any{"foo"}, nil)
func (a *FilterAST) ToSQL(argStartIdx int) (string, []any) {
	return fmt.Sprintf("%s = $%d", a.Field, argStartIdx), []any{a.Value}
}
