package interceptors

import (
	"context"

	"google.golang.org/grpc"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// TracingOptions customises the tracing interceptor behaviour.
type TracingOptions struct {
	TracerProvider trace.TracerProvider
	Propagators    propagation.TextMapPropagator
	Additional     []otelgrpc.Option
}

// TracingInterceptor composes OpenTelemetry server interceptors for gRPC traffic.
type TracingInterceptor struct {
	unary  grpc.UnaryServerInterceptor
	stream grpc.StreamServerInterceptor
}

// NewTracingInterceptor builds unary and stream interceptors with the supplied options.
func NewTracingInterceptor(opts TracingOptions) *TracingInterceptor {
	options := make([]otelgrpc.Option, 0, len(opts.Additional)+2)
	if opts.TracerProvider != nil {
		options = append(options, otelgrpc.WithTracerProvider(opts.TracerProvider))
	}
	if opts.Propagators != nil {
		options = append(options, otelgrpc.WithPropagators(opts.Propagators))
	}
	options = append(options, opts.Additional...)

	return &TracingInterceptor{
		unary:  otelgrpc.UnaryServerInterceptor(options...),
		stream: otelgrpc.StreamServerInterceptor(options...),
	}
}

// Unary returns the unary server interceptor.
func (ti *TracingInterceptor) Unary() grpc.UnaryServerInterceptor {
	if ti == nil || ti.unary == nil {
		return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
			return handler(ctx, req)
		}
	}
	return ti.unary
}

// Stream returns the stream server interceptor.
func (ti *TracingInterceptor) Stream() grpc.StreamServerInterceptor {
	if ti == nil || ti.stream == nil {
		return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			return handler(srv, ss)
		}
	}
	return ti.stream
}
