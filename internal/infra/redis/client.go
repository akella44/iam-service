package redis

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/arklim/social-platform-iam/internal/infra/config"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// Client wraps redis.Client with health check and lifecycle management
type Client struct {
	client *redis.Client
	logger *zap.Logger
	cfg    config.RedisSettings
}

// NewClient initializes Redis connection pool with health checks
func NewClient(cfg config.RedisSettings, logger *zap.Logger) (*Client, error) {
	opts := &redis.Options{
		Addr:     fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password: cfg.Password,
		DB:       cfg.DB,

		// Connection pool settings
		PoolSize:     10,
		MinIdleConns: 2,
		MaxRetries:   3,

		// Timeouts
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,

		// Keep-alive
		PoolTimeout:     4 * time.Second,
		ConnMaxIdleTime: 5 * time.Minute,
	}

	// Enable TLS if configured
	if cfg.TLSEnabled {
		opts.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	client := redis.NewClient(opts)

	// Perform initial health check
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis ping failed: %w", err)
	}

	logger.Info("Redis connection established",
		zap.String("host", cfg.Host),
		zap.Int("port", cfg.Port),
		zap.Int("db", cfg.DB),
		zap.Bool("tls_enabled", cfg.TLSEnabled),
	)

	return &Client{
		client: client,
		logger: logger,
		cfg:    cfg,
	}, nil
}

// Client returns the underlying redis.Client for direct access
func (c *Client) Client() *redis.Client {
	return c.client
}

// HealthCheck performs a ping to verify Redis connectivity
func (c *Client) HealthCheck(ctx context.Context) error {
	if err := c.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis health check failed: %w", err)
	}
	return nil
}

// Close gracefully closes the Redis connection pool
func (c *Client) Close() error {
	c.logger.Info("Closing Redis connection")
	if err := c.client.Close(); err != nil {
		return fmt.Errorf("close redis client: %w", err)
	}
	return nil
}

// Stats returns connection pool statistics for monitoring
func (c *Client) Stats() *redis.PoolStats {
	return c.client.PoolStats()
}
