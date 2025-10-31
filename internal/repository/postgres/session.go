package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	squirrel "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/core/port"
	"github.com/arklim/social-platform-iam/internal/repository"
)

type pgExecutor interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// SessionRepository implements port.SessionRepository backed by PostgreSQL.
type SessionRepository struct {
	pool    *pgxpool.Pool
	exec    pgExecutor
	builder squirrel.StatementBuilderType
}

// NewSessionRepository constructs a repository backed by any executor that satisfies pgExecutor.
func NewSessionRepository(exec pgExecutor) *SessionRepository {
	repo := &SessionRepository{
		exec:    exec,
		builder: squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar),
	}
	if pool, ok := exec.(*pgxpool.Pool); ok {
		repo.pool = pool
	}
	return repo
}

// WithTx returns a repository instance that executes statements within the supplied transaction.
func (r *SessionRepository) WithTx(tx pgx.Tx) *SessionRepository {
	if tx == nil {
		return r
	}
	return &SessionRepository{
		pool:    r.pool,
		exec:    tx,
		builder: r.builder,
	}
}

// Create persists a new session aggregate.
func (r *SessionRepository) Create(ctx context.Context, session domain.Session) error {
	version := session.Version
	if version <= 0 {
		version = 1
	}
	sqlStmt, args, err := r.builder.Insert("iam.sessions").
		Columns(
			"id",
			"user_id",
			"family_id",
			"session_version",
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
			session.FamilyID,
			version,
			optionalString(session.RefreshTokenID),
			optionalString(session.DeviceID),
			optionalString(session.DeviceLabel),
			optionalString(session.IPFirst),
			optionalString(session.IPLast),
			optionalString(session.UserAgent),
			session.CreatedAt,
			session.LastSeen,
			session.ExpiresAt,
			optionalTime(session.RevokedAt),
			optionalString(session.RevokeReason),
		).
		ToSql()
	if err != nil {
		return fmt.Errorf("build insert session sql: %w", err)
	}

	if _, err := r.exec.Exec(ctx, sqlStmt, args...); err != nil {
		return fmt.Errorf("insert session: %w", err)
	}

	return nil
}

// Get fetches a session by its identifier.
func (r *SessionRepository) Get(ctx context.Context, sessionID string) (*domain.Session, error) {
	stmt, args, err := r.builder.
		Select(
			"s.id",
			"s.user_id",
			"s.family_id",
			"s.session_version",
			"s.refresh_token_id",
			"s.device_id",
			"s.device_label",
			"s.ip_first",
			"s.ip_last",
			"s.user_agent",
			"s.created_at",
			"s.last_seen",
			"s.expires_at",
			"s.revoked_at",
			"s.revoke_reason",
			"rt.issued_version",
		).
		From("iam.sessions AS s").
		LeftJoin("iam.refresh_tokens AS rt ON rt.id = s.refresh_token_id").
		Where(squirrel.Eq{"s.id": sessionID}).
		Limit(1).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("build select session sql: %w", err)
	}

	row := r.exec.QueryRow(ctx, stmt, args...)
	session, err := scanSession(row)
	if err != nil {
		if err == repository.ErrNotFound {
			return nil, err
		}
		return nil, fmt.Errorf("scan session: %w", err)
	}

	return session, nil
}

// ListByUser retrieves all sessions owned by the supplied user ordered by last activity.
func (r *SessionRepository) ListByUser(ctx context.Context, userID string) ([]domain.Session, error) {
	stmt, args, err := r.builder.
		Select(
			"s.id",
			"s.user_id",
			"s.family_id",
			"s.session_version",
			"s.refresh_token_id",
			"s.device_id",
			"s.device_label",
			"s.ip_first",
			"s.ip_last",
			"s.user_agent",
			"s.created_at",
			"s.last_seen",
			"s.expires_at",
			"s.revoked_at",
			"s.revoke_reason",
			"rt.issued_version",
		).
		From("iam.sessions AS s").
		LeftJoin("iam.refresh_tokens AS rt ON rt.id = s.refresh_token_id").
		Where(squirrel.Eq{"s.user_id": userID}).
		OrderBy("s.last_seen DESC").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("build list sessions sql: %w", err)
	}

	rows, err := r.exec.Query(ctx, stmt, args...)
	if err != nil {
		return nil, fmt.Errorf("query sessions: %w", err)
	}
	defer rows.Close()

	sessions := make([]domain.Session, 0)
	for rows.Next() {
		session, err := scanSession(rows)
		if err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		sessions = append(sessions, *session)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sessions: %w", err)
	}

	return sessions, nil
}

// UpdateLastSeen refreshes last_seen, ip metadata, and user agent when activity is detected.
func (r *SessionRepository) UpdateLastSeen(ctx context.Context, sessionID string, ip *string, userAgent *string) error {
	now := time.Now().UTC()
	ipValue := optionalString(ip)
	userAgentValue := optionalString(userAgent)

	stmt := `
        UPDATE iam.sessions
           SET last_seen = $2,
               ip_last = CASE WHEN $3::inet IS NULL THEN ip_last ELSE $3::inet END,
               ip_first = CASE WHEN $3::inet IS NULL THEN ip_first ELSE COALESCE(ip_first, $3::inet) END,
               user_agent = CASE WHEN $4::text IS NULL OR $4::text = '' THEN user_agent ELSE $4::text END
         WHERE id = $1
    `

	tag, err := r.exec.Exec(ctx, stmt, sessionID, now, ipValue, userAgentValue)
	if err != nil {
		return fmt.Errorf("update session last seen: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// Revoke marks the session as revoked and cascades refresh token revocation.
func (r *SessionRepository) Revoke(ctx context.Context, sessionID string, reason string) error {
	normalized := normalizeReason(reason, "manual_revoke")
	if _, err := r.exec.Exec(ctx, "SELECT iam.session_revoke($1, $2)", sessionID, normalized); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

// RevokeByFamily revokes all active sessions within the same token family.
func (r *SessionRepository) RevokeByFamily(ctx context.Context, familyID string, reason string) (int, error) {
	rows, err := r.exec.Query(ctx, "SELECT id FROM iam.sessions WHERE family_id = $1 AND revoked_at IS NULL", familyID)
	if err != nil {
		return 0, fmt.Errorf("list sessions by family: %w", err)
	}
	defer rows.Close()

	normalized := normalizeReason(reason, "family_revoked")
	revoked := 0
	for rows.Next() {
		var sessionID string
		if err := rows.Scan(&sessionID); err != nil {
			return revoked, fmt.Errorf("scan session id: %w", err)
		}
		if err := r.Revoke(ctx, sessionID, normalized); err != nil {
			return revoked, err
		}
		revoked++
	}

	if err := rows.Err(); err != nil {
		return revoked, fmt.Errorf("iterate family sessions: %w", err)
	}

	if revoked == 0 {
		return 0, repository.ErrNotFound
	}

	return revoked, nil
}

// RevokeAllForUser revokes every active session for the supplied user.
func (r *SessionRepository) RevokeAllForUser(ctx context.Context, userID string, reason string) (int, error) {
	normalized := normalizeReason(reason, "global_signout")
	var count int
	if err := r.exec.QueryRow(ctx, "SELECT iam.session_revoke_all_for_user($1, $2)", userID, normalized).Scan(&count); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, repository.ErrNotFound
		}
		return 0, fmt.Errorf("revoke sessions for user: %w", err)
	}
	return count, nil
}

// StoreEvent persists lifecycle events for auditability.
func (r *SessionRepository) StoreEvent(ctx context.Context, event domain.SessionEvent) error {
	details, err := marshalSessionEventDetails(event.Details)
	if err != nil {
		return err
	}

	sqlStmt, args, err := r.builder.Insert("iam.session_events").
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
			optionalString(event.IP),
			optionalString(event.UserAgent),
			details,
		).
		ToSql()
	if err != nil {
		return fmt.Errorf("build insert session event sql: %w", err)
	}

	if _, err := r.exec.Exec(ctx, sqlStmt, args...); err != nil {
		return fmt.Errorf("insert session event: %w", err)
	}

	return nil
}

// RevokeSessionAccessTokens blacklists active access tokens issued for the session.
func (r *SessionRepository) RevokeSessionAccessTokens(ctx context.Context, sessionID string, reason string) (int, error) {
	normalized := normalizeReason(reason, "session_revoked")
	var count int
	if err := r.exec.QueryRow(ctx, "SELECT iam.revoke_session_access_tokens($1, $2)", sessionID, normalized).Scan(&count); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, repository.ErrNotFound
		}
		return 0, fmt.Errorf("revoke session access tokens: %w", err)
	}

	return count, nil
}

// GetVersion returns the authoritative session_version from PostgreSQL.
func (r *SessionRepository) GetVersion(ctx context.Context, sessionID string) (int64, error) {
	var version int64
	if err := r.exec.QueryRow(ctx, "SELECT session_version FROM iam.sessions WHERE id = $1", sessionID).Scan(&version); err != nil {
		if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, sql.ErrNoRows) {
			return 0, repository.ErrNotFound
		}
		return 0, fmt.Errorf("get session version: %w", err)
	}
	return version, nil
}

// IncrementVersion bumps the counter atomically via the session_bump_version helper.
func (r *SessionRepository) IncrementVersion(ctx context.Context, sessionID string, reason string) (int64, error) {
	normalized := normalizeReason(reason, "session_version_bump")
	var version int64
	if err := r.exec.QueryRow(ctx, "SELECT iam.session_bump_version($1, $2)", sessionID, normalized).Scan(&version); err != nil {
		if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, sql.ErrNoRows) {
			return 0, repository.ErrNotFound
		}
		return 0, fmt.Errorf("increment session version: %w", err)
	}
	return version, nil
}

// SetVersion forcefully overwrites the session version counter.
func (r *SessionRepository) SetVersion(ctx context.Context, sessionID string, version int64) error {
	if version <= 0 {
		return fmt.Errorf("version must be positive")
	}
	tag, err := r.exec.Exec(ctx, "UPDATE iam.sessions SET session_version = $2 WHERE id = $1", sessionID, version)
	if err != nil {
		return fmt.Errorf("set session version: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return repository.ErrNotFound
	}
	return nil
}

func scanSession(row pgx.Row) (*domain.Session, error) {
	var (
		session        domain.Session
		refreshTokenID sql.NullString
		deviceID       sql.NullString
		deviceLabel    sql.NullString
		ipFirst        sql.NullString
		ipLast         sql.NullString
		userAgent      sql.NullString
		revokedAt      sql.NullTime
		revokeReason   sql.NullString
		issuedVersion  sql.NullInt64
	)

	if err := row.Scan(
		&session.ID,
		&session.UserID,
		&session.FamilyID,
		&session.Version,
		&refreshTokenID,
		&deviceID,
		&deviceLabel,
		&ipFirst,
		&ipLast,
		&userAgent,
		&session.CreatedAt,
		&session.LastSeen,
		&session.ExpiresAt,
		&revokedAt,
		&revokeReason,
		&issuedVersion,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, err
	}

	session.RefreshTokenID = nullableStringPtr(refreshTokenID)
	session.DeviceID = nullableStringPtr(deviceID)
	session.DeviceLabel = nullableStringPtr(deviceLabel)
	session.IPFirst = nullableStringPtr(ipFirst)
	session.IPLast = nullableStringPtr(ipLast)
	session.UserAgent = nullableStringPtr(userAgent)
	session.RevokedAt = nullableTimePtr(revokedAt)
	session.RevokeReason = nullableStringPtr(revokeReason)
	session.IssuedVersion = nullableInt64Ptr(issuedVersion)

	return &session, nil
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

func optionalString(value *string) any {
	if value == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*value)
	if trimmed == "" {
		return nil
	}
	return trimmed
}

func optionalTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return (*value).UTC()
}

func nullableStringPtr(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	v := strings.TrimSpace(value.String)
	if v == "" {
		return nil
	}
	return &v
}

func nullableTimePtr(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	t := value.Time.UTC()
	return &t
}

func nullableInt64Ptr(value sql.NullInt64) *int64 {
	if !value.Valid {
		return nil
	}
	v := value.Int64
	return &v
}

func normalizeReason(candidate string, fallback string) string {
	trimmed := strings.TrimSpace(candidate)
	if trimmed == "" {
		return fallback
	}
	return trimmed
}

var _ port.SessionRepository = (*SessionRepository)(nil)
