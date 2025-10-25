package postgres

import (
	"context"
	"testing"
	"time"

	pgxmock "github.com/pashagolub/pgxmock/v2"

	"github.com/arklim/social-platform-iam/internal/core/domain"
)

func TestSessionRepository_Create(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool: %v", err)
	}
	defer mock.Close()

	repo := NewSessionRepository(mock)

	createdAt := time.Now().UTC()
	deviceID := "device-123"
	session := domain.Session{
		ID:        "session-123",
		UserID:    "user-123",
		FamilyID:  "family-123",
		CreatedAt: createdAt,
		LastSeen:  createdAt,
		ExpiresAt: createdAt.Add(24 * time.Hour),
		DeviceID:  &deviceID,
	}

	mock.ExpectExec(`INSERT INTO iam\.sessions`).
		WithArgs(
			session.ID,
			session.UserID,
			session.FamilyID,
			nil,
			deviceID,
			nil,
			nil,
			nil,
			nil,
			session.CreatedAt,
			session.LastSeen,
			session.ExpiresAt,
			nil,
			nil,
		).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	if err := repo.Create(context.Background(), session); err != nil {
		t.Fatalf("Create returned error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestSessionRepository_Get(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool: %v", err)
	}
	defer mock.Close()

	repo := NewSessionRepository(mock)

	createdAt := time.Now().UTC()
	expiresAt := createdAt.Add(30 * time.Minute)
	refreshID := "refresh-1"
	deviceLabel := "Chrome"
	ip := "198.51.100.10"

	rows := pgxmock.NewRows([]string{
		"id", "user_id", "family_id", "refresh_token_id", "device_id", "device_label", "ip_first", "ip_last", "user_agent", "created_at", "last_seen", "expires_at", "revoked_at", "revoke_reason",
	}).AddRow(
		"session-1", "user-1", "family-1", refreshID, nil, deviceLabel, ip, ip, "UA", createdAt, createdAt, expiresAt, nil, nil,
	)

	mock.ExpectQuery(`SELECT .*FROM iam\.sessions`).WithArgs("session-1").WillReturnRows(rows)

	session, err := repo.Get(context.Background(), "session-1")
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if session.ID != "session-1" {
		t.Fatalf("expected session id session-1, got %s", session.ID)
	}
	if session.RefreshTokenID == nil || *session.RefreshTokenID != refreshID {
		t.Fatalf("expected refresh token pointer populated")
	}
	if session.DeviceLabel == nil || *session.DeviceLabel != deviceLabel {
		t.Fatalf("expected device label to match")
	}
	if session.IPFirst == nil || *session.IPFirst != ip || session.IPLast == nil || *session.IPLast != ip {
		t.Fatalf("expected ip metadata to match")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestSessionRepository_ListByUser(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool: %v", err)
	}
	defer mock.Close()

	repo := NewSessionRepository(mock)

	now := time.Now().UTC()

	rows := pgxmock.NewRows([]string{
		"id", "user_id", "family_id", "refresh_token_id", "device_id", "device_label", "ip_first", "ip_last", "user_agent", "created_at", "last_seen", "expires_at", "revoked_at", "revoke_reason",
	}).AddRow(
		"session-1", "user-1", "family-1", nil, nil, nil, nil, nil, nil, now, now, now.Add(time.Hour), nil, nil,
	).AddRow(
		"session-2", "user-1", "family-2", nil, nil, nil, nil, nil, nil, now, now, now.Add(2*time.Hour), nil, nil,
	)

	mock.ExpectQuery(`SELECT .*FROM iam\.sessions`).WithArgs("user-1").WillReturnRows(rows)

	sessions, err := repo.ListByUser(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("ListByUser returned error: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("expected two sessions, got %d", len(sessions))
	}
	if sessions[0].ID != "session-1" || sessions[1].ID != "session-2" {
		t.Fatalf("unexpected session order: %+v", sessions)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestSessionRepository_UpdateLastSeen(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool: %v", err)
	}
	defer mock.Close()

	repo := NewSessionRepository(mock)

	sessionID := "session-5"
	ip := "203.0.113.5"
	ua := "GoTest/1.0"

	mock.ExpectExec(`UPDATE iam\.sessions`).
		WithArgs(sessionID, pgxmock.AnyArg(), ip, ua).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	ipPtr := ip
	uaPtr := ua
	if err := repo.UpdateLastSeen(context.Background(), sessionID, &ipPtr, &uaPtr); err != nil {
		t.Fatalf("UpdateLastSeen returned error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestSessionRepository_Revoke(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool: %v", err)
	}
	defer mock.Close()

	repo := NewSessionRepository(mock)

	mock.ExpectExec(`SELECT iam\.session_revoke`).
		WithArgs("session-7", "manual").
		WillReturnResult(pgxmock.NewResult("SELECT", 1))

	if err := repo.Revoke(context.Background(), "session-7", "manual"); err != nil {
		t.Fatalf("Revoke returned error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestSessionRepository_StoreEvent(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool: %v", err)
	}
	defer mock.Close()

	repo := NewSessionRepository(mock)

	event := domain.SessionEvent{
		ID:        "event-1",
		SessionID: "session-1",
		Kind:      "login",
		At:        time.Now().UTC(),
		Details: map[string]any{
			"device": "macbook",
		},
	}

	mock.ExpectExec(`INSERT INTO iam\.session_events`).
		WithArgs(
			event.ID,
			event.SessionID,
			event.Kind,
			event.At,
			nil,
			nil,
			pgxmock.AnyArg(),
		).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	if err := repo.StoreEvent(context.Background(), event); err != nil {
		t.Fatalf("StoreEvent returned error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
