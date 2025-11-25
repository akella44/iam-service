package telemetry

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/arklim/social-platform-iam/internal/core/port"
	"github.com/arklim/social-platform-iam/internal/infra/config"
)

// Provider represents a telemetry provider handle.
type Provider struct {
	requestCounter        prometheus.Counter
	subjectVersionMetrics *SubjectVersionMetricsRecorder
	jtiMetrics            *JTIDenylistMetricsRecorder
}

// Attach configures telemetry exporters and returns a provider handle.
func Attach(_ context.Context, cfg *config.AppConfig) (*Provider, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is nil")
	}

	counter := promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "iam",
		Name:      "http_requests_total",
		Help:      "Total number of HTTP requests",
	})

	subjectVersionHits := promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "iam",
		Name:      "subject_version_cache_hits_total",
		Help:      "Total number of subject version cache hits",
	})

	subjectVersionMisses := promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "iam",
		Name:      "subject_version_cache_misses_total",
		Help:      "Total number of subject version cache misses",
	})

	subjectVersionBumps := promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "iam",
		Name:      "subject_version_bumps_total",
		Help:      "Total subject version bumps processed",
	})

	subjectVersionLag := promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "iam",
		Name:      "subject_version_propagation_seconds",
		Help:      "Propagation lag from subject version mutation to cache update",
		Buckets:   []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5},
	})

	jtiCacheHits := promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "iam",
		Name:      "jti_cache_hits_total",
		Help:      "Total number of JTI denylist cache hits",
	})

	jtiCacheMisses := promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "iam",
		Name:      "jti_cache_misses_total",
		Help:      "Total number of JTI denylist cache misses",
	})

	jtiDenies := promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "iam",
		Name:      "jti_revocations_total",
		Help:      "Total number of access tokens denied due to JTI revocation",
	})

	jtiLag := promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "iam",
		Name:      "jti_revocation_lag_seconds",
		Help:      "Lag between token revocation and local denylist update",
		Buckets:   []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5},
	})

	subjectMetrics := &SubjectVersionMetricsRecorder{
		hits:   subjectVersionHits,
		misses: subjectVersionMisses,
		bumps:  subjectVersionBumps,
		lag:    subjectVersionLag,
	}

	jtiMetrics := &JTIDenylistMetricsRecorder{
		hits:   jtiCacheHits,
		misses: jtiCacheMisses,
		denies: jtiDenies,
		lag:    jtiLag,
	}

	return &Provider{
		requestCounter:        counter,
		subjectVersionMetrics: subjectMetrics,
		jtiMetrics:            jtiMetrics,
	}, nil
}

// RequestCounter exposes the HTTP request metric.
func (p *Provider) RequestCounter() prometheus.Counter {
	if p == nil {
		return prometheus.NewCounter(prometheus.CounterOpts{})
	}
	return p.requestCounter
}

// SubjectVersionMetrics returns the recorder for subject version telemetry.
func (p *Provider) SubjectVersionMetrics() *SubjectVersionMetricsRecorder {
	if p == nil {
		return nil
	}
	return p.subjectVersionMetrics
}

// JTIDenylistMetrics returns the recorder for denylist cache telemetry.
func (p *Provider) JTIDenylistMetrics() *JTIDenylistMetricsRecorder {
	if p == nil {
		return nil
	}
	return p.jtiMetrics
}

// SubjectVersionMetricsRecorder supplies metric helpers for subject version tracking.
type SubjectVersionMetricsRecorder struct {
	hits   prometheus.Counter
	misses prometheus.Counter
	bumps  prometheus.Counter
	lag    prometheus.Observer
}

// IncCacheHit increments the subject version cache hit counter.
func (m *SubjectVersionMetricsRecorder) IncCacheHit() {
	if m == nil || m.hits == nil {
		return
	}
	m.hits.Inc()
}

// IncCacheMiss increments the subject version cache miss counter.
func (m *SubjectVersionMetricsRecorder) IncCacheMiss() {
	if m == nil || m.misses == nil {
		return
	}
	m.misses.Inc()
}

// IncBump increments the subject version bump counter.
func (m *SubjectVersionMetricsRecorder) IncBump() {
	if m == nil || m.bumps == nil {
		return
	}
	m.bumps.Inc()
}

// ObserveLag records propagation lag in seconds.
func (m *SubjectVersionMetricsRecorder) ObserveLag(duration time.Duration) {
	if m == nil || m.lag == nil {
		return
	}
	m.lag.Observe(duration.Seconds())
}

// JTIDenylistMetricsRecorder supplies metric helpers for denylist tracking.
type JTIDenylistMetricsRecorder struct {
	hits   prometheus.Counter
	misses prometheus.Counter
	denies prometheus.Counter
	lag    prometheus.Observer
}

// IncCacheHit increments the denylist cache hit counter.
func (m *JTIDenylistMetricsRecorder) IncCacheHit() {
	if m == nil || m.hits == nil {
		return
	}
	m.hits.Inc()
}

// IncCacheMiss increments the denylist cache miss counter.
func (m *JTIDenylistMetricsRecorder) IncCacheMiss() {
	if m == nil || m.misses == nil {
		return
	}
	m.misses.Inc()
}

// IncDeny increments the counter of tokens denied by the denylist.
func (m *JTIDenylistMetricsRecorder) IncDeny() {
	if m == nil || m.denies == nil {
		return
	}
	m.denies.Inc()
}

// ObserveLag records revocation propagation lag in seconds.
func (m *JTIDenylistMetricsRecorder) ObserveLag(duration time.Duration) {
	if m == nil || m.lag == nil {
		return
	}
	m.lag.Observe(duration.Seconds())
}

var _ port.JTIDenylistMetrics = (*JTIDenylistMetricsRecorder)(nil)
