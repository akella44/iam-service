package usecase

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/repository"
)

type fakeSessionRepository struct {
	sessions map[string]*domain.Session
	listErr  error
	now      func() time.Time

	storeEventCalls []domain.SessionEvent
	revokeCalls     []string
	tokenCounts     map[string]int
}

func newFakeSessionRepository(sessions ...domain.Session) *fakeSessionRepository {
	repo := &fakeSessionRepository{
		sessions:    make(map[string]*domain.Session),
		tokenCounts: make(map[string]int),
	}
	for i := range sessions {
		sessionCopy := sessions[i]
		repo.sessions[sessionCopy.ID] = &sessionCopy
	}
	return repo
}

func (f *fakeSessionRepository) Create(ctx context.Context, session domain.Session) error { return nil }

func (f *fakeSessionRepository) Get(ctx context.Context, sessionID string) (*domain.Session, error) {
	session, ok := f.sessions[sessionID]
	if !ok {
		return nil, repository.ErrNotFound
	}
	copy := *session
	if session.RevokedAt != nil {
		revokedAt := session.RevokedAt.UTC()
		copy.RevokedAt = &revokedAt
	}
	if session.RevokeReason != nil {
		reason := *session.RevokeReason
		copy.RevokeReason = &reason
	}
	if session.DeviceID != nil {
		deviceID := *session.DeviceID
		copy.DeviceID = &deviceID
	}
	if session.DeviceLabel != nil {
		label := *session.DeviceLabel
		copy.DeviceLabel = &label
	}
	if session.IPFirst != nil {
		ip := *session.IPFirst
		copy.IPFirst = &ip
	}
	if session.IPLast != nil {
		ip := *session.IPLast
		copy.IPLast = &ip
	}
	if session.UserAgent != nil {
		ua := *session.UserAgent
		copy.UserAgent = &ua
	}
	if session.RefreshTokenID != nil {
		rt := *session.RefreshTokenID
		copy.RefreshTokenID = &rt
	}
	return &copy, nil
}

func (f *fakeSessionRepository) ListByUser(ctx context.Context, userID string) ([]domain.Session, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	result := make([]domain.Session, 0)
	for _, session := range f.sessions {
		if session.UserID != userID {
			continue
		}
		copy := *session
		result = append(result, copy)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].LastSeen.After(result[j].LastSeen)
	})
	return result, nil
}

func (f *fakeSessionRepository) UpdateLastSeen(ctx context.Context, sessionID string, ip *string, userAgent *string) error {
	return nil
}

func (f *fakeSessionRepository) Revoke(ctx context.Context, sessionID string, reason string) error {
	session, ok := f.sessions[sessionID]
	if !ok {
		return repository.ErrNotFound
	}
	now := time.Now().UTC()
	if f.now != nil {
		now = f.now()
	}
	session.RevokedAt = &now
	session.RevokeReason = &reason
	f.revokeCalls = append(f.revokeCalls, sessionID)
	return nil
}

func (f *fakeSessionRepository) RevokeByFamily(ctx context.Context, familyID string, reason string) (int, error) {
	return 0, nil
}

func (f *fakeSessionRepository) RevokeAllForUser(ctx context.Context, userID string, reason string) (int, error) {
	count := 0
	for _, session := range f.sessions {
		if session.UserID != userID {
			continue
		}
		_ = f.Revoke(ctx, session.ID, reason)
		count++
	}
	return count, nil
}

func (f *fakeSessionRepository) StoreEvent(ctx context.Context, event domain.SessionEvent) error {
	f.storeEventCalls = append(f.storeEventCalls, event)
	return nil
}

func (f *fakeSessionRepository) RevokeSessionAccessTokens(ctx context.Context, sessionID string, reason string) (int, error) {
	if count, ok := f.tokenCounts[sessionID]; ok {
		return count, nil
	}
	return 0, nil
}

type fakeEventPublisher struct {
	sessionRevoked []domain.SessionRevokedEvent
	fail           error
}

func (f *fakeEventPublisher) PublishUserRegistered(ctx context.Context, event domain.UserRegisteredEvent) error {
	return nil
}

func (f *fakeEventPublisher) PublishPasswordChanged(ctx context.Context, event domain.PasswordChangedEvent) error {
	return nil
}

func (f *fakeEventPublisher) PublishPasswordResetRequested(ctx context.Context, event domain.PasswordResetRequestedEvent) error {
	return nil
}

func (f *fakeEventPublisher) PublishRolesAssigned(ctx context.Context, event domain.RolesAssignedEvent) error {
	return nil
}

func (f *fakeEventPublisher) PublishSessionRevoked(ctx context.Context, event domain.SessionRevokedEvent) error {
	if f.fail != nil {
		return f.fail
	}
	f.sessionRevoked = append(f.sessionRevoked, event)
	return nil
}

func TestSessionService_ListSessions(t *testing.T) {
	t.Helper()

	base := time.Date(2025, 10, 19, 12, 0, 0, 0, time.UTC)
	revokedAt := base.Add(-30 * time.Minute)
	expiredAt := base.Add(-5 * time.Minute)
	deviceLabel := "Chrome"

	sessions := []domain.Session{
		{
			ID:        "sess-active",
			UserID:    "user-1",
			LastSeen:  base.Add(-5 * time.Minute),
			CreatedAt: base.Add(-2 * time.Hour),
			ExpiresAt: base.Add(2 * time.Hour),
		},
		{
			ID:          "sess-revoked",
			UserID:      "user-1",
			LastSeen:    base.Add(-10 * time.Minute),
			CreatedAt:   base.Add(-3 * time.Hour),
			ExpiresAt:   base.Add(3 * time.Hour),
			RevokedAt:   &revokedAt,
			DeviceLabel: &deviceLabel,
		},
		{
			ID:        "sess-expired",
			UserID:    "user-1",
			LastSeen:  base.Add(-1 * time.Hour),
			CreatedAt: base.Add(-4 * time.Hour),
			ExpiresAt: expiredAt,
		},
	}

	repo := newFakeSessionRepository(sessions...)
	svc := NewSessionService(repo, nil, nil, nil)
	svc.WithClock(func() time.Time { return base })

	ctx := context.Background()

	allSessions, err := svc.ListSessions(ctx, "user-1", false)
	if err != nil {
		t.Fatalf("ListSessions returned error: %v", err)
	}
	if len(allSessions) != 3 {
		t.Fatalf("expected 3 sessions, got %d", len(allSessions))
	}
	if allSessions[0].LastSeen.Before(allSessions[1].LastSeen) {
		t.Fatalf("expected sessions ordered by last seen descending")
	}

	activeOnly, err := svc.ListSessions(ctx, "user-1", true)
	if err != nil {
		t.Fatalf("ListSessions(activeOnly) returned error: %v", err)
	}
	if len(activeOnly) != 1 {
		t.Fatalf("expected 1 active session, got %d", len(activeOnly))
	}
	if activeOnly[0].ID != "sess-active" {
		t.Fatalf("expected sess-active to remain, got %s", activeOnly[0].ID)
	}

	if _, err := svc.ListSessions(ctx, "", false); err == nil {
		t.Fatalf("expected error when user id missing")
	}

	repoEmpty := newFakeSessionRepository()
	repoEmpty.listErr = repository.ErrNotFound
	svcEmpty := NewSessionService(repoEmpty, nil, nil, nil)
	if _, err := svcEmpty.ListSessions(ctx, "user-404", true); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}
