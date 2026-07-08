// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package check

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	iamv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/iam/v1"
)

// blockingIAMClient — fake iamv1.InternalIAMServiceClient чей Check блокируется до
// отмены переданного ctx (симулирует зависший/недоступный iam). Остальные методы
// интерфейса не реализованы (embed nil-interface) — тест их не вызывает.
type blockingIAMClient struct {
	iamv1.InternalIAMServiceClient
}

func (blockingIAMClient) Check(ctx context.Context, _ *iamv1.CheckRequest, _ ...grpc.CallOption) (*iamv1.CheckResponse, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// leak/MEDIUM (round-5 audit, internal/dataplane/handler.go:403 +
// internal/handler/listauthz.go:152) — IAMCheckClient.Check раньше форвардил сырой
// inbound ctx в iam.Check без per-call deadline: зависший iam пинил горутину
// навсегда (data-plane per-request Check / control-plane ScopeFiltered fan-out до
// 1000 Check на ListRepositories). Фикс — context.WithTimeout(ctx, checkTimeout)
// ВНУТРИ IAMCheckClient.Check, единая точка для ОБОИХ call-site'ов.
func TestIAMCheckClient_Check_BoundsPerCallDeadline(t *testing.T) {
	c := &IAMCheckClient{cli: blockingIAMClient{}}

	start := time.Now()
	// Родительский ctx НЕ имеет собственного дедлайна — единственная граница обязана
	// прийти изнутри Check (иначе тест не отличает "клиент сам поставил timeout" от
	// "родитель уже был bounded").
	allowed, err := c.Check(context.Background(), "user:usr-x", "v_get", "registry_registry:reg-A")
	elapsed := time.Since(start)

	require.False(t, allowed, "fail-closed: timeout не должен разрешать доступ")
	require.Error(t, err)
	require.Less(t, elapsed, 3*time.Second, "Check обязан вернуться около checkTimeout (2s), не висеть")
	require.GreaterOrEqual(t, elapsed, checkTimeout-100*time.Millisecond,
		"Check не должен возвращаться раньше configured checkTimeout")
}
