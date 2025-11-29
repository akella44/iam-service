package redis

import (
	"context"
	"testing"
	"time"
)

func TestSessionRevocationStore_MarkAndCheck(t *testing.T) {
	client, _ := newTestRedis(t)
	repo := NewSessionRevocationStore(client, "sess:revoked:test")

	sessionID := "session-123"
	if err := repo.MarkSessionRevoked(context.Background(), sessionID, "logout_all", time.Minute); err != nil {
		t.Fatalf("MarkSessionRevoked returned error: %v", err)
	}

	revoked, reason, err := repo.IsSessionRevoked(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("IsSessionRevoked returned error: %v", err)
	}
	if !revoked {
		t.Fatalf("expected session to be revoked")
	}
	if reason != "logout_all" {
		t.Fatalf("expected reason logout_all, got %s", reason)
	}
}

func TestSessionRevocationStore_IsRevokedMiss(t *testing.T) {
	client, _ := newTestRedis(t)
	repo := NewSessionRevocationStore(client, "sess:revoked:test")

	revoked, _, err := repo.IsSessionRevoked(context.Background(), "missing")
	if err != nil {
		t.Fatalf("IsSessionRevoked returned error: %v", err)
	}
	if revoked {
		t.Fatalf("expected session to not be revoked")
	}
}

func TestSessionRevocationStore_InvalidInput(t *testing.T) {
	client, _ := newTestRedis(t)
	repo := NewSessionRevocationStore(client, "sess:revoked:test")

	if err := repo.MarkSessionRevoked(context.Background(), "", "", time.Minute); err == nil {
		t.Fatalf("expected error for empty session id")
	}
	if err := repo.MarkSessionRevoked(context.Background(), "session-1", "", 0); err == nil {
		t.Fatalf("expected error for empty ttl")
	}
	if _, _, err := repo.IsSessionRevoked(context.Background(), ""); err == nil {
		t.Fatalf("expected error for empty session id")
	}
	if err := repo.ClearSessionRevocation(context.Background(), ""); err == nil {
		t.Fatalf("expected error for empty session id")
	}
}
