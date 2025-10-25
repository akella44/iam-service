package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	pgxmock "github.com/pashagolub/pgxmock/v2"

	"github.com/arklim/social-platform-iam/internal/repository"
)

func TestSessionRepository_Revoke_UsesFallbackReason(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool: %v", err)
	}
	defer mock.Close()

	repo := NewSessionRepository(mock)

	mock.ExpectExec(`SELECT iam\.session_revoke`).
		WithArgs("session-1", "manual_revoke").
		WillReturnResult(pgxmock.NewResult("SELECT", 1))

	if err := repo.Revoke(context.Background(), "session-1", ""); err != nil {
		t.Fatalf("Revoke returned error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestSessionRepository_RevokeByFamily(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool: %v", err)
	}
	defer mock.Close()

	repo := NewSessionRepository(mock)

	rows := pgxmock.NewRows([]string{"id"}).
		AddRow("session-1").
		AddRow("session-2")

	mock.ExpectQuery(`SELECT id FROM iam\.sessions WHERE family_id = \$1 AND revoked_at IS NULL`).
		WithArgs("family-1").
		WillReturnRows(rows)

	mock.ExpectExec(`SELECT iam\.session_revoke`).
		WithArgs("session-1", "family_revoked").
		WillReturnResult(pgxmock.NewResult("SELECT", 1))

	mock.ExpectExec(`SELECT iam\.session_revoke`).
		WithArgs("session-2", "family_revoked").
		WillReturnResult(pgxmock.NewResult("SELECT", 1))

	revoked, err := repo.RevokeByFamily(context.Background(), "family-1", "")
	if err != nil {
		t.Fatalf("RevokeByFamily returned error: %v", err)
	}
	if revoked != 2 {
		t.Fatalf("expected 2 sessions revoked, got %d", revoked)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestSessionRepository_RevokeByFamily_NotFound(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool: %v", err)
	}
	defer mock.Close()

	repo := NewSessionRepository(mock)

	rows := pgxmock.NewRows([]string{"id"})

	mock.ExpectQuery(`SELECT id FROM iam\.sessions WHERE family_id = \$1 AND revoked_at IS NULL`).
		WithArgs("family-404").
		WillReturnRows(rows)

	revoked, err := repo.RevokeByFamily(context.Background(), "family-404", "")
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	if revoked != 0 {
		t.Fatalf("expected 0 revoked, got %d", revoked)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestSessionRepository_RevokeAllForUser(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool: %v", err)
	}
	defer mock.Close()

	repo := NewSessionRepository(mock)

	mock.ExpectQuery(`SELECT iam\.session_revoke_all_for_user`).
		WithArgs("user-1", "global_signout").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(3))

	count, err := repo.RevokeAllForUser(context.Background(), "user-1", "")
	if err != nil {
		t.Fatalf("RevokeAllForUser returned error: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected count 3, got %d", count)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestSessionRepository_RevokeAllForUser_NotFound(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool: %v", err)
	}
	defer mock.Close()

	repo := NewSessionRepository(mock)

	mock.ExpectQuery(`SELECT iam\.session_revoke_all_for_user`).
		WithArgs("user-404", "global_signout").
		WillReturnError(pgx.ErrNoRows)

	_, err = repo.RevokeAllForUser(context.Background(), "user-404", "")
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestSessionRepository_RevokeSessionAccessTokens(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool: %v", err)
	}
	defer mock.Close()

	repo := NewSessionRepository(mock)

	mock.ExpectQuery(`SELECT iam\.revoke_session_access_tokens`).
		WithArgs("session-1", "session_revoked").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(5))

	count, err := repo.RevokeSessionAccessTokens(context.Background(), "session-1", "")
	if err != nil {
		t.Fatalf("RevokeSessionAccessTokens returned error: %v", err)
	}
	if count != 5 {
		t.Fatalf("expected count 5, got %d", count)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
