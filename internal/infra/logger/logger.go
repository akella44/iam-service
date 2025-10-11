package logger

import (
	"context"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	lg   *zap.Logger
	once sync.Once
)

// New returns a singleton zap.Logger configured for structured logging.
func New(env string) (*zap.Logger, error) {
	var err error
	once.Do(func() {
		cfg := zap.NewProductionConfig()
		if env != "production" {
			cfg = zap.NewDevelopmentConfig()
			cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		}

		lg, err = cfg.Build()
	})

	return lg, err
}

// WithContext attaches request scoped fields to the logger.
func WithContext(ctx context.Context) *zap.Logger {
	if lg == nil {
		lz, _ := zap.NewDevelopment()
		return lz
	}

	if ctx == nil {
		return lg
	}

	return lg.With(zap.String("request_id", requestIDFromContext(ctx)))
}

func requestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if val, ok := ctx.Value(RequestIDKey{}).(string); ok {
		return val
	}
	return ""
}

// RequestIDKey is used to store a request identifier on the context.
type RequestIDKey struct{}
