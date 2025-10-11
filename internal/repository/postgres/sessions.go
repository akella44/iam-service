package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	squirrel "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/core/port"
	"github.com/arklim/social-platform-iam/internal/repository"
)

// SessionRepository implements port.SessionRepository for PostgreSQL.
type SessionRepository struct {
	pool    *pgxpool.Pool
	builder squirrel.StatementBuilderType
}

// NewSessionRepository constructs a SessionRepository.
func NewSessionRepository(pool *pgxpool.Pool) *SessionRepository {
	return &SessionRepository{
		pool:    pool,
		builder: squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar),
	}
}

// Create inserts a session record.
func (r *SessionRepository) Create(ctx context.Context, session domain.Session) error {
	sql, args, err := r.builder.Insert("iam.sessions").
		Columns(
			"id",
			"user_id",
			"refresh_token_id",
			"device_id",
			"device_label",
			"ip_first",
			"ip_last",
			"user_agent",
			"created_at",
			"last_seen",
			"expires_at",
			"revoked_at",
			"revoke_reason",
		).
		Values(
			session.ID,
			session.UserID,
			session.RefreshTokenID,
			session.DeviceID,
			session.DeviceLabel,
			session.IPFirst,
			session.IPLast,
			session.UserAgent,
			session.CreatedAt,
			session.LastSeen,
			session.ExpiresAt,
			session.RevokedAt,
			session.RevokeReason,
		).
		ToSql()
	if err != nil {
		return fmt.Errorf("build insert session sql: %w", err)
	}

	if _, err := r.pool.Exec(ctx, sql, args...); err != nil {
		return fmt.Errorf("insert session: %w", err)
	}

	return nil
}

// Touch updates session last seen information using helper SQL function.
func (r *SessionRepository) Touch(ctx context.Context, sessionID string, ip *string, userAgent *string) error {
	if _, err := r.pool.Exec(ctx, "SELECT iam.session_touch($1, $2, $3)", sessionID, ip, userAgent); err != nil {
		return fmt.Errorf("touch session: %w", err)
	}
	return nil
}

// Revoke marks a session (and linked refresh token) as revoked.
func (r *SessionRepository) Revoke(ctx context.Context, sessionID string, reason string) error {
	if _, err := r.pool.Exec(ctx, "SELECT iam.session_revoke($1, $2)", sessionID, reason); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

// RevokeAllForUser revokes all active sessions for a user.
func (r *SessionRepository) RevokeAllForUser(ctx context.Context, userID string, reason string) (int, error) {
	var count int
	if err := r.pool.QueryRow(ctx, "SELECT iam.session_revoke_all_for_user($1, $2)", userID, reason).Scan(&count); err != nil {
		if err == pgx.ErrNoRows {
			return 0, repository.ErrNotFound
		}
		return 0, fmt.Errorf("revoke sessions for user: %w", err)
	}
	return count, nil
}

// StoreEvent persists a session event record.
func (r *SessionRepository) StoreEvent(ctx context.Context, event domain.SessionEvent) error {
	details, err := marshalSessionEventDetails(event.Details)
	if err != nil {
		return err
	}

	sql, args, err := r.builder.Insert("iam.session_events").
		Columns(
			"id",
			"session_id",
			"kind",
			"at",
			"ip",
			"user_agent",
			"details",
		).
		Values(
			event.ID,
			event.SessionID,
			event.Kind,
			event.At,
			event.IP,
			event.UserAgent,
			details,
		).
		ToSql()
	if err != nil {
		return fmt.Errorf("build insert session event sql: %w", err)
	}

	if _, err := r.pool.Exec(ctx, sql, args...); err != nil {
		return fmt.Errorf("insert session event: %w", err)
	}

	return nil
}

// RevokeSessionAccessTokens adds issued access token JTIs for a session to the blacklist.
func (r *SessionRepository) RevokeSessionAccessTokens(ctx context.Context, sessionID string, reason string) (int, error) {
	var count int
	if err := r.pool.QueryRow(ctx, "SELECT iam.revoke_session_access_tokens($1, $2)", sessionID, reason).Scan(&count); err != nil {
		if err == pgx.ErrNoRows {
			return 0, repository.ErrNotFound
		}
		return 0, fmt.Errorf("revoke session JTIs: %w", err)
	}
	return count, nil
}

// GetByID returns a session by identifier.
func (r *SessionRepository) GetByID(ctx context.Context, sessionID string) (*domain.Session, error) {
	sql, args, err := r.builder.
		Select(
			"id",
			"user_id",
			"refresh_token_id",
			"device_id",
			"device_label",
			"ip_first",
			"ip_last",
			"user_agent",
			"created_at",
			"last_seen",
			"expires_at",
			"revoked_at",
			"revoke_reason",
		).
		From("iam.sessions").
		Where(squirrel.Eq{"id": sessionID}).
		Limit(1).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("build select session by id sql: %w", err)
	}

	row := r.pool.QueryRow(ctx, sql, args...)

	var session domain.Session
	if err := row.Scan(
		&session.ID,
		&session.UserID,
		&session.RefreshTokenID,
		&session.DeviceID,
		&session.DeviceLabel,
		&session.IPFirst,
		&session.IPLast,
		&session.UserAgent,
		&session.CreatedAt,
		&session.LastSeen,
		&session.ExpiresAt,
		&session.RevokedAt,
		&session.RevokeReason,
	); err != nil {
		if err == pgx.ErrNoRows {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("scan session by id: %w", err)
	}

	return &session, nil
}

// ListActiveByUser returns non-revoked, non-expired sessions for the user.
func (r *SessionRepository) ListActiveByUser(ctx context.Context, userID string) ([]domain.Session, error) {
	now := time.Now().UTC()
	sql, args, err := r.builder.
		Select(
			"id",
			"user_id",
			"refresh_token_id",
			"device_id",
			"device_label",
			"ip_first",
			"ip_last",
			"user_agent",
			"created_at",
			"last_seen",
			"expires_at",
			"revoked_at",
			"revoke_reason",
		).
		From("iam.sessions").
		Where(squirrel.Eq{"user_id": userID}).
		Where("revoked_at IS NULL").
		Where(squirrel.Gt{"expires_at": now}).
		OrderBy("last_seen DESC").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("build list sessions sql: %w", err)
	}

	rows, err := r.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("query sessions: %w", err)
	}
	defer rows.Close()

	var sessions []domain.Session
	for rows.Next() {
		var session domain.Session
		if err := rows.Scan(
			&session.ID,
			&session.UserID,
			&session.RefreshTokenID,
			&session.DeviceID,
			&session.DeviceLabel,
			&session.IPFirst,
			&session.IPLast,
			&session.UserAgent,
			&session.CreatedAt,
			&session.LastSeen,
			&session.ExpiresAt,
			&session.RevokedAt,
			&session.RevokeReason,
		); err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		sessions = append(sessions, session)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sessions: %w", err)
	}

	return sessions, nil
}

func marshalSessionEventDetails(details map[string]any) ([]byte, error) {
	if details == nil {
		return nil, nil
	}

	payload, err := json.Marshal(details)
	if err != nil {
		return nil, fmt.Errorf("marshal session event details: %w", err)
	}
	return payload, nil
}

var _ port.SessionRepository = (*SessionRepository)(nil)
