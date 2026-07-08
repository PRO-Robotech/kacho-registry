// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/iam/v1"

	regerrors "github.com/PRO-Robotech/kacho-registry/internal/errors"
)

// fakeProjectService — in-memory ProjectServiceServer (симулирует iam public :9090).
type fakeProjectService struct {
	iamv1.UnimplementedProjectServiceServer

	getResp *iamv1.Project
	getErr  error
	lastReq *iamv1.GetProjectRequest
}

func (f *fakeProjectService) Get(_ context.Context, req *iamv1.GetProjectRequest) (*iamv1.Project, error) {
	f.lastReq = req
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.getResp, nil
}

// fakeInternalIAM — in-memory InternalIAMServiceServer (симулирует iam internal :9091).
// НЕ несёт ProjectService — ровно как реальный :9091 листенер kacho-iam, где
// ProjectService зарегистрирован ТОЛЬКО на public :9090.
type fakeInternalIAM struct {
	iamv1.UnimplementedInternalIAMServiceServer
}

// startFakeIAM поднимает gRPC server in-memory (TCP loopback :0). Регистрирует
// переданные fake-server'ы; nil-fake — соответствующий service не регистрируется
// (вызов такого service вернёт codes.Unimplemented, как реальный листенер без него).
func startFakeIAM(
	t *testing.T,
	project iamv1.ProjectServiceServer,
	internal iamv1.InternalIAMServiceServer,
) *grpc.ClientConn {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer()
	if project != nil {
		iamv1.RegisterProjectServiceServer(srv, project)
	}
	if internal != nil {
		iamv1.RegisterInternalIAMServiceServer(srv, internal)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() { srv.GracefulStop() })

	conn, err := grpc.NewClient(
		lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// captureSlog перенаправляет slog.Default() в буфер на время теста (restore в Cleanup).
// Позволяет проверить, что диагностический лог действительно эмитится.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

// TestProjectExists_HappyPath — conn к листенеру, несущему ProjectService (public
// :9090): Get отвечает проектом → ProjectExists=nil.
func TestProjectExists_HappyPath(t *testing.T) {
	fake := &fakeProjectService{getResp: &iamv1.Project{Id: "reg-prj-1"}}
	conn := startFakeIAM(t, fake, nil)
	c := New(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	require.NoError(t, c.ProjectExists(ctx, "reg-prj-1"))
	assert.Equal(t, "reg-prj-1", fake.lastReq.GetProjectId())
}

// TestProjectExists_ProjectServiceUnimplemented_OnInternalListener — воспроизводит
// корневую причину «Create → internal database error»: conn направлен на листенер,
// который НЕСЁТ InternalIAMService, но НЕ ProjectService (ровно iam internal :9091).
// ProjectService.Get → codes.Unimplemented; ProjectExists обязан (а) вернуть
// ErrInternal и (б) ЗАЛОГИРОВАТЬ gRPC-код, чтобы Unimplemented больше не терялся немо.
func TestProjectExists_ProjectServiceUnimplemented_OnInternalListener(t *testing.T) {
	buf := captureSlog(t)
	// Только InternalIAMService — ProjectService отсутствует (Unimplemented на Get).
	conn := startFakeIAM(t, nil, &fakeInternalIAM{})
	c := New(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := c.ProjectExists(ctx, "reg-prj-1")
	require.Error(t, err)
	assert.True(t, errors.Is(err, regerrors.ErrInternal), "expected ErrInternal, got %v", err)

	logged := buf.String()
	assert.Contains(t, logged, "grpc_code", "unexpected ProjectService.Get code must be logged")
	assert.Contains(t, strings.ToLower(logged), "unimplemented",
		"the raw gRPC code (Unimplemented) must appear in the diagnostic log")
}

// TestProjectExists_NotFound_MapsInvalidArg — NotFound от ProjectService → ErrInvalidArg
// (existence-hiding: tenant не различает «нет» и «нет доступа»).
func TestProjectExists_NotFound_MapsInvalidArg(t *testing.T) {
	fake := &fakeProjectService{getErr: status.Error(codes.NotFound, "no such project")}
	conn := startFakeIAM(t, fake, nil)
	c := New(conn)

	err := c.ProjectExists(context.Background(), "reg-prj-missing")
	require.Error(t, err)
	assert.True(t, errors.Is(err, regerrors.ErrInvalidArg), "expected ErrInvalidArg, got %v", err)
}

// TestProjectExists_NilConn_Unavailable — conn не подан (peer не сконфигурирован):
// мутация fail-closed (ErrUnavailable), не паника.
func TestProjectExists_NilConn_Unavailable(t *testing.T) {
	c := New(nil)
	err := c.ProjectExists(context.Background(), "reg-prj-1")
	require.Error(t, err)
	assert.True(t, errors.Is(err, regerrors.ErrUnavailable), "expected ErrUnavailable, got %v", err)
}

// blockingProjectService — ProjectServiceServer чей Get блокируется до отмены
// переданного (server-side) ctx — симулирует зависший-но-подключённый iam.
type blockingProjectService struct {
	iamv1.UnimplementedProjectServiceServer
}

func (blockingProjectService) Get(ctx context.Context, _ *iamv1.GetProjectRequest) (*iamv1.Project, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// leak/MEDIUM (round-6 audit, iam_client.go:61) — ProjectExists раньше форвардил
// сырой inbound ctx в ProjectService.Get без per-call deadline: retry.OnUnavailable
// только bounds backoff между попытками, но НЕ ограничивает время одного зависшего
// Get — зависший-но-подключённый iam пинил Create-горутину навсегда. Фикс —
// context.WithTimeout(ctx, iamCallTimeout) ВНУТРИ ProjectExists (не полагаться на
// inbound ctx deadline), зеркалит check.checkTimeout (internal/check/check_client.go).
func TestProjectExists_BlockingPeer_BoundsPerCallDeadline(t *testing.T) {
	conn := startFakeIAM(t, blockingProjectService{}, nil)
	c := New(conn)

	start := time.Now()
	// Родительский ctx НЕ имеет собственного дедлайна — единственная граница обязана
	// прийти изнутри ProjectExists (иначе тест не отличает "клиент сам поставил
	// timeout" от "родитель уже был bounded").
	err := c.ProjectExists(context.Background(), "reg-prj-1")
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.True(t, errors.Is(err, regerrors.ErrUnavailable), "expected ErrUnavailable (fail-closed on deadline), got %v", err)
	assert.Less(t, elapsed, iamCallTimeout+3*time.Second,
		"ProjectExists обязан вернуться около iamCallTimeout, не висеть на inbound ctx без дедлайна")
	assert.GreaterOrEqual(t, elapsed, iamCallTimeout-100*time.Millisecond,
		"ProjectExists не должен возвращаться раньше configured iamCallTimeout")
}
