package interceptors

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGRPCMetricsUnaryInterceptorRecordsMetrics(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics, err := NewGRPCMetrics(GRPCMetricsOptions{Registerer: registry})
	if err != nil {
		t.Fatalf("failed to create metrics: %v", err)
	}

	interceptor := metrics.UnaryServerInterceptor()

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		time.Sleep(5 * time.Millisecond)
		return "ok", nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/iam.v1.TokenService/ValidateToken"}

	if _, err := interceptor(context.Background(), struct{}{}, info, handler); err != nil {
		t.Fatalf("unexpected handler error: %v", err)
	}

	labels := prometheus.Labels{"service": "iam.v1.TokenService", "method": "ValidateToken", "code": codes.OK.String()}

	if got := testutil.ToFloat64(metrics.requests.With(labels)); got != 1 {
		t.Fatalf("expected request counter 1, got %f", got)
	}

	if inflight := testutil.ToFloat64(metrics.inFlight.WithLabelValues("iam.v1.TokenService")); inflight != 0 {
		t.Fatalf("expected in-flight gauge 0, got %f", inflight)
	}

	if samples := testutil.CollectAndCount(metrics.duration); samples == 0 {
		t.Fatalf("expected histogram to record observations")
	}
}

func TestGRPCMetricsUnaryInterceptorPropagatesErrors(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics, err := NewGRPCMetrics(GRPCMetricsOptions{Registerer: registry})
	if err != nil {
		t.Fatalf("failed to create metrics: %v", err)
	}

	interceptor := metrics.UnaryServerInterceptor()

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, status.Error(codes.PermissionDenied, "denied")
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/iam.v1.AdminService/AssignRole"}

	if _, err := interceptor(context.Background(), struct{}{}, info, handler); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected permission denied, got %v", err)
	}

	labels := prometheus.Labels{"service": "iam.v1.AdminService", "method": "AssignRole", "code": codes.PermissionDenied.String()}
	if got := testutil.ToFloat64(metrics.requests.With(labels)); got != 1 {
		t.Fatalf("expected request counter 1 for denied call, got %f", got)
	}
}
