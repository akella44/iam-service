package telemetry

import (
	"context"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/arklim/social-platform-iam/internal/infra/config"
)

// Provider represents a telemetry provider handle.
type Provider struct {
	requestCounter prometheus.Counter
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

	return &Provider{
		requestCounter: counter,
	}, nil
}

// RequestCounter exposes the HTTP request metric.
func (p *Provider) RequestCounter() prometheus.Counter {
	if p == nil {
		return prometheus.NewCounter(prometheus.CounterOpts{})
	}
	return p.requestCounter
}
