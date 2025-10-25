package redis

import (
	"context"
	"testing"
	"time"

	miniredis "github.com/alicebob/miniredis/v2"
	red "github.com/redis/go-redis/v9"
)

func newTestRedis(t *testing.T) (*red.Client, *miniredis.Miniredis) {
	t.Helper()

	server, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}

	client := red.NewClient(&red.Options{Addr: server.Addr()})

	t.Cleanup(func() {
		_ = client.Close()
		server.Close()
	})

	return client, server
}

func TestRevocationRepository_MarkAndCheck(t *testing.T) {
	t.Helper()

	client, server := newTestRedis(t)
	repo := NewRevocationRepository(client, "revoked")

	ctx := context.Background()
	ttl := 2 * time.Minute

	if err := repo.MarkRevoked(ctx, "jti-123", "user_logout", ttl); err != nil {
		t.Fatalf("MarkRevoked returned error: %v", err)
	}

	revoked, reason, err := repo.IsRevoked(ctx, "jti-123")
	if err != nil {
		t.Fatalf("IsRevoked returned error: %v", err)
	}
	if !revoked {
		t.Fatalf("expected jti to be marked revoked")
	}
	if reason != "user_logout" {
		t.Fatalf("expected reason user_logout, got %s", reason)
	}

	remaining := server.TTL("revoked:jti-123")
	if remaining <= 0 || remaining > ttl {
		t.Fatalf("expected ttl within (0, %v], got %v", ttl, remaining)
	}
}

func TestRevocationRepository_IsRevokedMiss(t *testing.T) {
	t.Helper()

	client, _ := newTestRedis(t)
	repo := NewRevocationRepository(client, "revoked")

	revoked, reason, err := repo.IsRevoked(context.Background(), "missing")
	if err != nil {
		t.Fatalf("IsRevoked returned error: %v", err)
	}
	if revoked {
		t.Fatalf("expected revoked to be false")
	}
	if reason != "" {
		t.Fatalf("expected empty reason, got %s", reason)
	}
}

func TestRevocationRepository_InvalidInput(t *testing.T) {
	t.Helper()

	client, _ := newTestRedis(t)
	repo := NewRevocationRepository(client, "revoked")

	if err := repo.MarkRevoked(context.Background(), "", "reason", time.Minute); err == nil {
		t.Fatalf("expected error for empty jti")
	}
	if err := repo.MarkRevoked(context.Background(), "jti", "reason", 0); err == nil {
		t.Fatalf("expected error for non-positive ttl")
	}

	if _, _, err := repo.IsRevoked(context.Background(), ""); err == nil {
		t.Fatalf("expected error for empty jti in IsRevoked")
	}
}
