package routes_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/arklim/social-platform-iam/internal/infra/config"
	httproutes "github.com/arklim/social-platform-iam/internal/transport/http/routes"
)

func TestHealthEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger, _ := zap.NewDevelopment()
	cfg := &config.AppConfig{App: config.AppSettings{Env: "test"}}

	r := httproutes.Register(httproutes.Dependencies{
		Config: cfg,
		Logger: logger,
	})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/healthz", nil)

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
}
