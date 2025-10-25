package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestHTTPMetricsHandlerRecordsMetrics(t *testing.T) {
	gin.SetMode(gin.TestMode)

	registry := prometheus.NewRegistry()
	metrics, err := NewHTTPMetrics(HTTPMetricsOptions{Registerer: registry})
	if err != nil {
		t.Fatalf("failed to create http metrics: %v", err)
	}

	router := gin.New()
	router.Use(metrics.Handler())
	router.GET("/hello", func(c *gin.Context) {
		time.Sleep(10 * time.Millisecond)
		c.Status(http.StatusCreated)
	})

	req := httptest.NewRequest(http.MethodGet, "/hello", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d", http.StatusCreated, rr.Code)
	}

	labels := prometheus.Labels{
		"method": http.MethodGet,
		"route":  "/hello",
		"status": "201",
	}

	if got := testutil.ToFloat64(metrics.Requests.With(labels)); got != 1 {
		t.Fatalf("expected request counter 1, got %f", got)
	}

	if got := testutil.ToFloat64(metrics.InFlight); got != 0 {
		t.Fatalf("expected in-flight gauge to return to 0, got %f", got)
	}

	if samples := testutil.CollectAndCount(metrics.Duration); samples == 0 {
		t.Fatalf("expected histogram collector to have at least one sample")
	}
}

func TestHTTPMetricsHandlerNoopWhenNil(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use((*HTTPMetrics)(nil).Handler())
	router.GET("/ping", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
}
