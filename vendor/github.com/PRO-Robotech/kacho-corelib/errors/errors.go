// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package errors

import (
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Builder — строитель gRPC-статуса с деталями.
type Builder struct {
	st         *status.Status
	violations []*errdetails.BadRequest_FieldViolation
	locale     string // если установлен — добавляется LocalizedMessage detail
}

func newBuilder(c codes.Code, msg string) *Builder {
	return &Builder{st: status.New(c, msg)}
}

// AddFieldViolation добавляет нарушение поля к BadRequest details.
func (b *Builder) AddFieldViolation(field, desc string) *Builder {
	b.violations = append(b.violations, &errdetails.BadRequest_FieldViolation{Field: field, Description: desc})
	return b
}

// WithLocale устанавливает locale для LocalizedMessage detail.
// При Err() добавится detail вида:
//
//	{ "@type": "type.googleapis.com/google.rpc.LocalizedMessage", "locale": "<locale>", "message": "<status.message>" }
//
// Если locale пустой — LocalizedMessage не добавляется.
func (b *Builder) WithLocale(locale string) *Builder {
	b.locale = locale
	return b
}

// Err собирает итоговую ошибку с деталями (BadRequest, опционально LocalizedMessage).
//
// LocalizedMessage добавляется ТОЛЬКО если был вызван WithLocale("<locale>")
// с непустым locale. По умолчанию Kachō возвращает только BadRequest —
// осознанное решение (более structured, machine-readable).
func (b *Builder) Err() error {
	st := b.st
	if len(b.violations) > 0 {
		if next, derr := st.WithDetails(&errdetails.BadRequest{FieldViolations: b.violations}); derr == nil {
			st = next
		}
	}
	if b.locale != "" {
		if next, derr := st.WithDetails(&errdetails.LocalizedMessage{
			Locale:  b.locale,
			Message: st.Message(),
		}); derr == nil {
			st = next
		}
	}
	return st.Err()
}

// Конструкторы ошибок.

// NotFound создает ошибку 404 с ResourceInfo detail.
//
// Текст сообщения: `<Kind> '<id>' was not found`. Используется
// resource-manager (Cloud, Folder, Organization).
func NotFound(kind, id string) *Builder {
	b := newBuilder(codes.NotFound, kind+" '"+id+"' was not found")
	if st2, err := b.st.WithDetails(&errdetails.ResourceInfo{
		ResourceType: kind, ResourceName: id,
	}); err == nil {
		b.st = st2
	}
	return b
}

// InvalidArgument создает ошибку 400, к которой можно добавить FieldViolation.
func InvalidArgument() *Builder { return newBuilder(codes.InvalidArgument, "invalid argument") }

// AlreadyExists создает ошибку 409.
func AlreadyExists(k, id string) *Builder {
	return newBuilder(codes.AlreadyExists, k+" "+id+" already exists")
}

// FailedPrecondition создает ошибку 400 (предусловие не выполнено).
func FailedPrecondition(msg string) *Builder { return newBuilder(codes.FailedPrecondition, msg) }

// Aborted создает ошибку 409 (операция прервана, требует повтора).
func Aborted(msg string) *Builder { return newBuilder(codes.Aborted, msg) }

// Unavailable создает ошибку 503.
func Unavailable(msg string) *Builder { return newBuilder(codes.Unavailable, msg) }

// Internal создает ошибку 500.
func Internal(msg string) *Builder { return newBuilder(codes.Internal, msg) }
