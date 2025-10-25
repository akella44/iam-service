package middleware

import (
	"fmt"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
)

// HTTPMetricsOptions configures the HTTP metrics middleware.
type HTTPMetricsOptions struct {
	Registerer prometheus.Registerer
	Namespace  string
	Subsystem  string
	Buckets    []float64
}

// HTTPMetrics exposes Prometheus collectors for request instrumentation.
type HTTPMetrics struct {
	Requests *prometheus.CounterVec
	Duration *prometheus.HistogramVec
	InFlight prometheus.Gauge
}

// NewHTTPMetrics constructs collectors for HTTP request metrics and registers them with the provided registerer.
func NewHTTPMetrics(opts HTTPMetricsOptions) (*HTTPMetrics, error) {
	namespace := opts.Namespace
	if namespace == "" {
		namespace = "iam"
	}

	subsystem := opts.Subsystem
	if subsystem == "" {
		subsystem = "http"
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
		Help:      "Total number of HTTP requests partitioned by method, route, and status code.",
	}, []string{"method", "route", "status"})

	if err := reg.Register(requests); err != nil {
		if already, ok := err.(prometheus.AlreadyRegisteredError); ok {
			if existing, ok := already.ExistingCollector.(*prometheus.CounterVec); ok {
				requests = existing
			} else {
				return nil, fmt.Errorf("existing requests collector has unexpected type %T", already.ExistingCollector)
			}
		} else {
			return nil, fmt.Errorf("register requests collector: %w", err)
		}
	}

	duration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      "request_duration_seconds",
		Help:      "Histogram of HTTP request latencies in seconds partitioned by method, route, and status code.",
		Buckets:   buckets,
	}, []string{"method", "route", "status"})

	if err := reg.Register(duration); err != nil {
		if already, ok := err.(prometheus.AlreadyRegisteredError); ok {
			if existing, ok := already.ExistingCollector.(*prometheus.HistogramVec); ok {
				duration = existing
			} else {
				return nil, fmt.Errorf("existing duration collector has unexpected type %T", already.ExistingCollector)
			}
		} else {
			return nil, fmt.Errorf("register duration collector: %w", err)
		}
	}

	inFlight := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      "in_flight_requests",
		Help:      "Current number of in-flight HTTP requests.",
	})

	if err := reg.Register(inFlight); err != nil {
		if already, ok := err.(prometheus.AlreadyRegisteredError); ok {
			if existing, ok := already.ExistingCollector.(prometheus.Gauge); ok {
				inFlight = existing
			} else {
				return nil, fmt.Errorf("existing inflight collector has unexpected type %T", already.ExistingCollector)
			}
		} else {
			return nil, fmt.Errorf("register inflight collector: %w", err)
		}
	}

	return &HTTPMetrics{
		Requests: requests,
		Duration: duration,
		InFlight: inFlight,
	}, nil
}

// Handler returns a Gin middleware that records the HTTP metrics.
func (m *HTTPMetrics) Handler() gin.HandlerFunc {
	if m == nil {
		return func(c *gin.Context) {
			c.Next()
		}
	}

	return func(c *gin.Context) {
		start := time.Now()
		if m.InFlight != nil {
			m.InFlight.Inc()
			defer m.InFlight.Dec()
		}

		c.Next()

		route := c.FullPath()
		if route == "" {
			route = c.Request.URL.Path
		}

		status := strconv.Itoa(c.Writer.Status())
		labels := prometheus.Labels{
			"method": c.Request.Method,
			"route":  route,
			"status": status,
		}

		if m.Requests != nil {
			m.Requests.With(labels).Inc()
		}

		if m.Duration != nil {
			elapsed := time.Since(start).Seconds()
			m.Duration.With(labels).Observe(elapsed)
		}
	}
}
