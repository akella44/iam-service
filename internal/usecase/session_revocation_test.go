package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/arklim/social-platform-iam/internal/core/domain"
)

func TestSessionService_RevokeSession(t *testing.T) {
	fixedNow := time.Date(2025, 10, 19, 15, 0, 0, 0, time.UTC)
	deviceID := "device-1"
	deviceLabel := "Chrome"
	ip := "203.0.113.10"
	ua := "Mozilla/5.0"

	session := domain.Session{
		ID:          "session-1",
		UserID:      "user-1",
		FamilyID:    "family-1",
		Version:     1,
		DeviceID:    &deviceID,
		DeviceLabel: &deviceLabel,
		IPLast:      &ip,
		UserAgent:   &ua,
		CreatedAt:   fixedNow.Add(-2 * time.Hour),
		LastSeen:    fixedNow.Add(-10 * time.Minute),
		ExpiresAt:   fixedNow.Add(3 * time.Hour),
	}

	repo := newFakeSessionRepository(session)
	repo.now = func() time.Time { return fixedNow }
	repo.tokenCounts["session-1"] = 2

	publisher := &fakeEventPublisher{}
	svc := NewSessionService(repo, nil, publisher, nil)
	svc.WithClock(func() time.Time { return fixedNow })
	cache := &stubSessionVersionCache{}
	svc.WithSessionVersionCache(cache, time.Minute)

	updated, tokensRevoked, err := svc.RevokeSession(context.Background(), "user-1", "session-1", "User Requested", "user-1")
	if err != nil {
		t.Fatalf("RevokeSession returned error: %v", err)
	}

	if updated == nil {
		t.Fatalf("expected session result")
	}
	if updated.RevokedAt == nil {
		t.Fatalf("expected revoked timestamp to be set")
	}
	if !updated.RevokedAt.Equal(fixedNow) {
		t.Fatalf("expected revoked timestamp %s, got %s", fixedNow, updated.RevokedAt)
	}
	if updated.Version != 2 {
		t.Fatalf("expected session version 2, got %d", updated.Version)
	}
	if tokensRevoked != 2 {
		t.Fatalf("expected 2 tokens revoked, got %d", tokensRevoked)
	}
	if len(repo.versionCalls) != 1 {
		t.Fatalf("expected 1 version bump, got %d", len(repo.versionCalls))
	}
	if repo.versionCalls[0].sessionID != "session-1" || repo.versionCalls[0].reason != "user_requested" {
		t.Fatalf("unexpected version bump payload: %+v", repo.versionCalls[0])
	}
	if len(cache.setCalls) != 1 || cache.setCalls[0].version != 2 {
		t.Fatalf("expected cache to store version 2, got %+v", cache.setCalls)
	}

	if len(repo.storeEventCalls) != 1 {
		t.Fatalf("expected 1 stored event, got %d", len(repo.storeEventCalls))
	}
	stored := repo.storeEventCalls[0]
	if stored.SessionID != "session-1" {
		t.Fatalf("expected event for session-1, got %s", stored.SessionID)
	}
	reason, ok := stored.Details["reason"].(string)
	if !ok || reason != "user_requested" {
		t.Fatalf("expected normalized reason, got %v", stored.Details["reason"])
	}
	tokensDetail, ok := stored.Details["tokens_revoked"].(int)
	if !ok || tokensDetail != 2 {
		t.Fatalf("expected tokens_revoked detail, got %v", stored.Details["tokens_revoked"])
	}
	versionDetail, ok := stored.Details["session_version"].(int64)
	if !ok || versionDetail != 2 {
		t.Fatalf("expected session_version detail 2, got %v", stored.Details["session_version"])
	}

	if len(publisher.sessionRevoked) != 1 {
		t.Fatalf("expected 1 published event, got %d", len(publisher.sessionRevoked))
	}
	published := publisher.sessionRevoked[0]
	if published.SessionID != "session-1" || published.UserID != "user-1" {
		t.Fatalf("unexpected published event payload: %+v", published)
	}
	if published.Reason != "user_requested" {
		t.Fatalf("expected event reason user_requested, got %s", published.Reason)
	}
	if published.Metadata == nil {
		t.Fatalf("expected metadata to include session_version entry, got nil")
	}
	versionMeta, ok := published.Metadata["session_version"].(int64)
	if !ok || versionMeta != 2 {
		t.Fatalf("expected metadata session_version 2, got %+v", published.Metadata["session_version"])
	}
}

func TestSessionService_RevokeAllSessions(t *testing.T) {
	fixedNow := time.Date(2025, 10, 19, 16, 0, 0, 0, time.UTC)
	revokedAt := fixedNow.Add(-2 * time.Hour)
	deviceLabel := "Safari"

	sessions := []domain.Session{
		{
			ID:        "session-a",
			UserID:    "user-1",
			LastSeen:  fixedNow.Add(-5 * time.Minute),
			CreatedAt: fixedNow.Add(-10 * time.Hour),
			ExpiresAt: fixedNow.Add(5 * time.Hour),
		},
		{
			ID:          "session-b",
			UserID:      "user-1",
			LastSeen:    fixedNow.Add(-30 * time.Minute),
			CreatedAt:   fixedNow.Add(-9 * time.Hour),
			ExpiresAt:   fixedNow.Add(2 * time.Hour),
			DeviceLabel: &deviceLabel,
		},
		{
			ID:        "session-revoked",
			UserID:    "user-1",
			LastSeen:  fixedNow.Add(-1 * time.Hour),
			CreatedAt: fixedNow.Add(-8 * time.Hour),
			ExpiresAt: fixedNow.Add(4 * time.Hour),
			RevokedAt: &revokedAt,
		},
		{
			ID:        "session-expired",
			UserID:    "user-1",
			LastSeen:  fixedNow.Add(-3 * time.Hour),
			CreatedAt: fixedNow.Add(-7 * time.Hour),
			ExpiresAt: fixedNow.Add(-1 * time.Minute),
		},
	}

	repo := newFakeSessionRepository(sessions...)
	repo.now = func() time.Time { return fixedNow }
	repo.tokenCounts["session-a"] = 1
	repo.tokenCounts["session-b"] = 3

	publisher := &fakeEventPublisher{}
	svc := NewSessionService(repo, nil, publisher, nil)
	svc.WithClock(func() time.Time { return fixedNow })
	cache := &stubSessionVersionCache{}
	svc.WithSessionVersionCache(cache, time.Minute)

	revokedCount, tokensRevoked, err := svc.RevokeAllSessions(context.Background(), "user-1", "Suspicious Activity", "admin-1")
	if err != nil {
		t.Fatalf("RevokeAllSessions returned error: %v", err)
	}
	if revokedCount != 2 {
		t.Fatalf("expected 2 sessions revoked, got %d", revokedCount)
	}
	if tokensRevoked != 4 {
		t.Fatalf("expected 4 tokens revoked, got %d", tokensRevoked)
	}
	if len(repo.storeEventCalls) != 2 {
		t.Fatalf("expected 2 stored events, got %d", len(repo.storeEventCalls))
	}
	if len(publisher.sessionRevoked) != 2 {
		t.Fatalf("expected 2 published events, got %d", len(publisher.sessionRevoked))
	}
	if len(repo.versionCalls) != 2 {
		t.Fatalf("expected version bump per revoked session, got %d", len(repo.versionCalls))
	}
	if len(cache.setCalls) != 2 {
		t.Fatalf("expected cache writes per revoked session, got %d", len(cache.setCalls))
	}
}

func TestSessionService_RevokeAllExceptCurrent(t *testing.T) {
	fixedNow := time.Date(2025, 10, 19, 17, 0, 0, 0, time.UTC)

	sessions := []domain.Session{
		{ID: "session-current", UserID: "user-1", LastSeen: fixedNow, CreatedAt: fixedNow.Add(-5 * time.Hour), ExpiresAt: fixedNow.Add(6 * time.Hour)},
		{ID: "session-old", UserID: "user-1", LastSeen: fixedNow.Add(-1 * time.Hour), CreatedAt: fixedNow.Add(-6 * time.Hour), ExpiresAt: fixedNow.Add(4 * time.Hour)},
		{ID: "session-alt", UserID: "user-1", LastSeen: fixedNow.Add(-2 * time.Hour), CreatedAt: fixedNow.Add(-7 * time.Hour), ExpiresAt: fixedNow.Add(2 * time.Hour)},
	}

	repo := newFakeSessionRepository(sessions...)
	repo.now = func() time.Time { return fixedNow }
	repo.tokenCounts["session-old"] = 2
	repo.tokenCounts["session-alt"] = 1

	publisher := &fakeEventPublisher{}
	svc := NewSessionService(repo, nil, publisher, nil)
	svc.WithClock(func() time.Time { return fixedNow })
	cache := &stubSessionVersionCache{}
	svc.WithSessionVersionCache(cache, time.Minute)

	revokedCount, tokensRevoked, err := svc.RevokeAllExceptCurrent(context.Background(), "user-1", "session-current", "Admin action", "admin-1")
	if err != nil {
		t.Fatalf("RevokeAllExceptCurrent returned error: %v", err)
	}
	if revokedCount != 2 {
		t.Fatalf("expected 2 sessions revoked, got %d", revokedCount)
	}
	if tokensRevoked != 3 {
		t.Fatalf("expected 3 tokens revoked, got %d", tokensRevoked)
	}
	if len(repo.versionCalls) != 2 {
		t.Fatalf("expected 2 version bumps, got %d", len(repo.versionCalls))
	}
	if len(cache.setCalls) != 2 {
		t.Fatalf("expected 2 cache writes, got %d", len(cache.setCalls))
	}

	repoMissing := newFakeSessionRepository(sessions...)
	repoMissing.now = func() time.Time { return fixedNow }
	svcMissing := NewSessionService(repoMissing, nil, nil, nil)
	svcMissing.WithClock(func() time.Time { return fixedNow })

	_, _, err = svcMissing.RevokeAllExceptCurrent(context.Background(), "user-1", "session-missing", "Admin action", "admin-1")
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}
