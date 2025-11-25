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
	versionCalls    []struct {
		sessionID string
		reason    string
	}
}

func newFakeSessionRepository(sessions ...domain.Session) *fakeSessionRepository {
	repo := &fakeSessionRepository{
		sessions:    make(map[string]*domain.Session),
		tokenCounts: make(map[string]int),
	}
	for i := range sessions {
		sessionCopy := sessions[i]
		if sessionCopy.Version <= 0 {
			sessionCopy.Version = 1
		}
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

func (f *fakeSessionRepository) GetVersion(ctx context.Context, sessionID string) (int64, error) {
	session, ok := f.sessions[sessionID]
	if !ok {
		return 0, repository.ErrNotFound
	}
	return session.Version, nil
}

func (f *fakeSessionRepository) IncrementVersion(ctx context.Context, sessionID string, reason string) (int64, error) {
	session, ok := f.sessions[sessionID]
	if !ok {
		return 0, repository.ErrNotFound
	}
	if session.Version <= 0 {
		session.Version = 1
	} else {
		session.Version++
	}
	f.versionCalls = append(f.versionCalls, struct {
		sessionID string
		reason    string
	}{sessionID: sessionID, reason: reason})
	return session.Version, nil
}

func (f *fakeSessionRepository) SetVersion(ctx context.Context, sessionID string, version int64) error {
	session, ok := f.sessions[sessionID]
	if !ok {
		return repository.ErrNotFound
	}
	if version <= 0 {
		session.Version = 1
	} else {
		session.Version = version
	}
	return nil
}

type fakeEventPublisher struct {
	sessionRevoked       []domain.SessionRevokedEvent
	sessionVersionBumped []domain.SessionVersionBumpedEvent
	subjectVersionBumped []domain.SubjectVersionBumpedEvent
	fail                 error
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

func (f *fakeEventPublisher) PublishRolesRevoked(ctx context.Context, event domain.RolesRevokedEvent) error {
	return nil
}

func (f *fakeEventPublisher) PublishSessionRevoked(ctx context.Context, event domain.SessionRevokedEvent) error {
	if f.fail != nil {
		return f.fail
	}
	f.sessionRevoked = append(f.sessionRevoked, event)
	return nil
}

func (f *fakeEventPublisher) PublishSessionVersionBumped(ctx context.Context, event domain.SessionVersionBumpedEvent) error {
	if f.fail != nil {
		return f.fail
	}
	f.sessionVersionBumped = append(f.sessionVersionBumped, event)
	return nil
}

func (f *fakeEventPublisher) PublishSubjectVersionBumped(ctx context.Context, event domain.SubjectVersionBumpedEvent) error {
	if f.fail != nil {
		return f.fail
	}
	f.subjectVersionBumped = append(f.subjectVersionBumped, event)
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
			Version:   1,
			LastSeen:  base.Add(-5 * time.Minute),
			CreatedAt: base.Add(-2 * time.Hour),
			ExpiresAt: base.Add(2 * time.Hour),
		},
		{
			ID:          "sess-revoked",
			UserID:      "user-1",
			Version:     1,
			LastSeen:    base.Add(-10 * time.Minute),
			CreatedAt:   base.Add(-3 * time.Hour),
			ExpiresAt:   base.Add(3 * time.Hour),
			RevokedAt:   &revokedAt,
			DeviceLabel: &deviceLabel,
		},
		{
			ID:        "sess-expired",
			UserID:    "user-1",
			Version:   1,
			LastSeen:  base.Add(-1 * time.Hour),
			CreatedAt: base.Add(-4 * time.Hour),
			ExpiresAt: expiredAt,
		},
	}

	repo := newFakeSessionRepository(sessions...)
	svc := NewSessionService(repo, nil, nil, nil)
	svc.WithClock(func() time.Time { return base })
	cache := &stubSessionVersionCache{values: map[string]int64{"sess-active": 5}}
	svc.WithSessionVersionCache(cache, time.Minute)

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
	var foundVersion bool
	for _, session := range allSessions {
		if session.ID == "sess-active" {
			if session.Version != 5 {
				t.Fatalf("expected cached session version 5, got %d", session.Version)
			}
			foundVersion = true
		}
	}
	if !foundVersion {
		t.Fatalf("sess-active not found in results: %+v", allSessions)
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
	if activeOnly[0].Version != 5 {
		t.Fatalf("expected active session to expose cached version 5, got %d", activeOnly[0].Version)
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

func TestSessionService_BumpSessionVersionPublishesEvent(t *testing.T) {
	t.Helper()

	base := time.Date(2025, 10, 20, 9, 0, 0, 0, time.UTC)
	deviceID := "device-1"
	deviceLabel := "Safari on iOS"
	ip := "198.51.100.25"
	ua := "Mozilla/5.0"

	session := domain.Session{
		ID:          "session-evt-1",
		UserID:      "user-evt-1",
		FamilyID:    "family-evt",
		Version:     1,
		DeviceID:    &deviceID,
		DeviceLabel: &deviceLabel,
		IPLast:      &ip,
		UserAgent:   &ua,
		CreatedAt:   base.Add(-2 * time.Hour),
		LastSeen:    base.Add(-10 * time.Minute),
		ExpiresAt:   base.Add(6 * time.Hour),
	}

	repo := newFakeSessionRepository(session)
	repo.now = func() time.Time { return base }
	publisher := &fakeEventPublisher{}
	svc := NewSessionService(repo, nil, publisher, nil)
	svc.WithClock(func() time.Time { return base })

	metadata := map[string]any{"actor": "unit-test"}
	version, err := svc.BumpSessionVersion(context.Background(), &session, "Refresh Rotation", metadata)
	if err != nil {
		t.Fatalf("BumpSessionVersion returned error: %v", err)
	}
	if version != 2 {
		t.Fatalf("expected bumped version 2, got %d", version)
	}
	if session.Version != 2 {
		t.Fatalf("expected session struct to reflect version 2, got %d", session.Version)
	}
	if len(repo.versionCalls) != 1 {
		t.Fatalf("expected single repository version increment, got %d", len(repo.versionCalls))
	}
	if repo.versionCalls[0].sessionID != "session-evt-1" || repo.versionCalls[0].reason != "refresh_rotation" {
		t.Fatalf("unexpected version call payload: %+v", repo.versionCalls[0])
	}
	if len(publisher.sessionVersionBumped) != 1 {
		t.Fatalf("expected one published event, got %d", len(publisher.sessionVersionBumped))
	}
	event := publisher.sessionVersionBumped[0]
	if event.SessionID != "session-evt-1" || event.UserID != "user-evt-1" {
		t.Fatalf("unexpected event payload: %+v", event)
	}
	if event.Version != 2 {
		t.Fatalf("expected event version 2, got %d", event.Version)
	}
	if event.Reason != "refresh_rotation" {
		t.Fatalf("expected normalized reason refresh_rotation, got %s", event.Reason)
	}
	if !event.BumpedAt.Equal(base) {
		t.Fatalf("expected event timestamp %s, got %s", base, event.BumpedAt)
	}
	if event.Metadata == nil {
		t.Fatalf("expected metadata to include actor, got nil")
	}
	if got := event.Metadata["actor"]; got != "unit-test" {
		t.Fatalf("expected metadata actor=unit-test, got %v", got)
	}
	if got := event.Metadata["device_label"]; got != deviceLabel {
		t.Fatalf("expected metadata device_label=%s, got %v", deviceLabel, got)
	}
	if got := event.Metadata["device_id"]; got != deviceID {
		t.Fatalf("expected metadata device_id=%s, got %v", deviceID, got)
	}
	if got := event.Metadata["family_id"]; got != session.FamilyID {
		t.Fatalf("expected metadata family_id=%s, got %v", session.FamilyID, got)
	}
	if got := event.Metadata["ip"]; got != ip {
		t.Fatalf("expected metadata ip=%s, got %v", ip, got)
	}
	if got := event.Metadata["user_agent"]; got != ua {
		t.Fatalf("expected metadata user_agent=%s, got %v", ua, got)
	}
}
