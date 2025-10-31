package interceptors

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func TestTracingInterceptorUnaryDelegatesToHandler(t *testing.T) {
	tp := sdktrace.NewTracerProvider()
	interceptor := NewTracingInterceptor(TracingOptions{TracerProvider: tp}).Unary()

	info := &grpc.UnaryServerInfo{FullMethod: "/iam.v1.TokenService/GetJWKS"}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	}

	if _, err := interceptor(context.Background(), struct{}{}, info, handler); err != nil {
		t.Fatalf("unexpected unary handler error: %v", err)
	}
}

func TestTracingInterceptorStreamDelegatesToHandler(t *testing.T) {
	tp := sdktrace.NewTracerProvider()
	interceptor := NewTracingInterceptor(TracingOptions{TracerProvider: tp}).Stream()

	info := &grpc.StreamServerInfo{FullMethod: "/iam.v1.StreamService/Watch", IsServerStream: true}

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		return status.Error(codes.OK, "")
	}

	stream := &mockServerStream{ctx: context.Background()}
	if err := interceptor(nil, stream, info, handler); status.Code(err) != codes.OK {
		t.Fatalf("expected status OK, got %v", err)
	}
}

type mockServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (m *mockServerStream) Context() context.Context {
	return m.ctx
}
