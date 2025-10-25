package interceptors

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

// GRPCMetricsOptions controls construction of gRPC metrics collectors.
type GRPCMetricsOptions struct {
	Registerer prometheus.Registerer
	Namespace  string
	Subsystem  string
	Buckets    []float64
}

// GRPCMetrics wraps Prometheus collectors for gRPC instrumentation.
type GRPCMetrics struct {
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
	inFlight *prometheus.GaugeVec
}

// NewGRPCMetrics constructs collectors and registers them with the supplied registerer.
func NewGRPCMetrics(opts GRPCMetricsOptions) (*GRPCMetrics, error) {
	namespace := opts.Namespace
	if namespace == "" {
		namespace = "iam"
	}

	subsystem := opts.Subsystem
	if subsystem == "" {
		subsystem = "grpc"
	}

	reg := opts.Registerer
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}

	buckets := opts.Buckets
	if len(buckets) == 0 {
		buckets = prometheus.DefBuckets
	}

	requests := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      "requests_total",
		Help:      "Total number of gRPC unary requests partitioned by service, method, and status code.",
	}, []string{"service", "method", "code"})

	if err := reg.Register(requests); err != nil {
		if already, ok := err.(prometheus.AlreadyRegisteredError); ok {
			existing, ok := already.ExistingCollector.(*prometheus.CounterVec)
			if !ok {
				return nil, fmt.Errorf("existing gRPC requests collector has wrong type %T", already.ExistingCollector)
			}
			requests = existing
		} else {
			return nil, fmt.Errorf("register gRPC requests collector: %w", err)
		}
	}

	duration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      "request_duration_seconds",
		Help:      "Histogram of gRPC unary request latencies in seconds partitioned by service, method, and status code.",
		Buckets:   buckets,
	}, []string{"service", "method", "code"})

	if err := reg.Register(duration); err != nil {
		if already, ok := err.(prometheus.AlreadyRegisteredError); ok {
			existing, ok := already.ExistingCollector.(*prometheus.HistogramVec)
			if !ok {
				return nil, fmt.Errorf("existing gRPC duration collector has wrong type %T", already.ExistingCollector)
			}
			duration = existing
		} else {
			return nil, fmt.Errorf("register gRPC duration collector: %w", err)
		}
	}

	inFlight := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      "in_flight_requests",
		Help:      "Current number of in-flight gRPC unary requests partitioned by service.",
	}, []string{"service"})

	if err := reg.Register(inFlight); err != nil {
		if already, ok := err.(prometheus.AlreadyRegisteredError); ok {
			existing, ok := already.ExistingCollector.(*prometheus.GaugeVec)
			if !ok {
				return nil, fmt.Errorf("existing gRPC inflight collector has wrong type %T", already.ExistingCollector)
			}
			inFlight = existing
		} else {
			return nil, fmt.Errorf("register gRPC inflight collector: %w", err)
		}
	}

	return &GRPCMetrics{requests: requests, duration: duration, inFlight: inFlight}, nil
}

// UnaryServerInterceptor returns a gRPC unary interceptor that records metrics.
func (m *GRPCMetrics) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	if m == nil {
		return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
			return handler(ctx, req)
		}
	}

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		service, method := splitFullMethod(info.FullMethod)
		start := time.Now()

		inflightGauge := m.inFlight.WithLabelValues(service)
		inflightGauge.Inc()
		defer inflightGauge.Dec()

		resp, err := handler(ctx, req)

		code := status.Code(err).String()
		labels := prometheus.Labels{
			"service": service,
			"method":  method,
			"code":    code,
		}

		m.requests.With(labels).Inc()
		m.duration.With(labels).Observe(time.Since(start).Seconds())

		return resp, err
	}
}

func splitFullMethod(full string) (string, string) {
	if full == "" {
		return "unknown", "unknown"
	}
	if strings.HasPrefix(full, "/") {
		full = full[1:]
	}
	parts := strings.Split(full, "/")
	if len(parts) != 2 {
		return full, "unknown"
	}
	if parts[0] == "" {
		parts[0] = "unknown"
	}
	if parts[1] == "" {
		parts[1] = "unknown"
	}
	return parts[0], parts[1]
}
