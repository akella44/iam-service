package telemetry

import (
	"context"
	"fmt"
	"time"

	"github.com/arklim/social-platform-iam/internal/infra/config"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// TracerProvider wraps OpenTelemetry tracer provider with lifecycle management
type TracerProvider struct {
	provider *sdktrace.TracerProvider
	logger   *zap.Logger
	cfg      config.TelemetrySettings
}

// NewTracerProvider initializes OpenTelemetry tracer provider with OTLP HTTP exporter
func NewTracerProvider(ctx context.Context, cfg config.TelemetrySettings, logger *zap.Logger) (*TracerProvider, error) {
	// Create OTLP HTTP exporter
	exporter, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpoint(cfg.OTLPEndpoint),
		otlptracehttp.WithInsecure(), // Use TLS in production
		otlptracehttp.WithTimeout(10*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("create OTLP exporter: %w", err)
	}

	// Create resource with service name and version
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion("1.0.0"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("create resource: %w", err)
	}

	// Create tracer provider with sampling
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter,
			sdktrace.WithBatchTimeout(5*time.Second),
			sdktrace.WithMaxExportBatchSize(512),
		),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(cfg.SamplingRate)),
	)

	// Register as global tracer provider
	otel.SetTracerProvider(tp)

	// Set global propagator to W3C Trace Context (for distributed tracing)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	logger.Info("OpenTelemetry tracer provider initialized",
		zap.String("otlp_endpoint", cfg.OTLPEndpoint),
		zap.String("service_name", cfg.ServiceName),
		zap.Float64("sampling_rate", cfg.SamplingRate),
	)

	return &TracerProvider{
		provider: tp,
		logger:   logger,
		cfg:      cfg,
	}, nil
}

// TracerProvider returns the underlying OpenTelemetry tracer provider
func (tp *TracerProvider) TracerProvider() *sdktrace.TracerProvider {
	return tp.provider
}

// Tracer returns a tracer for the given instrumentation name
func (tp *TracerProvider) Tracer(name string, opts ...trace.TracerOption) trace.Tracer {
	return tp.provider.Tracer(name, opts...)
}

// Shutdown gracefully shuts down the tracer provider and flushes pending spans
func (tp *TracerProvider) Shutdown(ctx context.Context) error {
	tp.logger.Info("Shutting down OpenTelemetry tracer provider")

	shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := tp.provider.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown tracer provider: %w", err)
	}

	return nil
}

// ForceFlush forces immediate flush of pending spans
func (tp *TracerProvider) ForceFlush(ctx context.Context) error {
	flushCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := tp.provider.ForceFlush(flushCtx); err != nil {
		return fmt.Errorf("force flush tracer provider: %w", err)
	}

	return nil
}
