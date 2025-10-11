package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	squirrel "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/core/port"
	"github.com/arklim/social-platform-iam/internal/repository"
)

// TokenRepository implements port.TokenRepository using PostgreSQL tables.
type TokenRepository struct {
	pool    *pgxpool.Pool
	builder squirrel.StatementBuilderType
}

// NewTokenRepository constructs a new token repository.
func NewTokenRepository(pool *pgxpool.Pool) *TokenRepository {
	return &TokenRepository{
		pool:    pool,
		builder: squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar),
	}
}

// CreateVerification inserts a new verification token record.
func (r *TokenRepository) CreateVerification(ctx context.Context, token domain.VerificationToken) error {
	metadata, err := marshalMetadata(token.Metadata)
	if err != nil {
		return fmt.Errorf("prepare verification metadata: %w", err)
	}

	sql, args, err := r.builder.Insert("iam.verification_tokens").
		Columns(
			"id",
			"user_id",
			"token_hash",
			"purpose",
			"new_email",
			"ip",
			"user_agent",
			"created_at",
			"expires_at",
			"used_at",
			"revoked_at",
			"metadata",
		).
		Values(
			token.ID,
			token.UserID,
			token.TokenHash,
			token.Purpose,
			token.NewEmail,
			token.IP,
			token.UserAgent,
			token.CreatedAt,
			token.ExpiresAt,
			token.UsedAt,
			token.RevokedAt,
			metadata,
		).
		ToSql()
	if err != nil {
		return fmt.Errorf("build insert verification token sql: %w", err)
	}

	if _, err := r.pool.Exec(ctx, sql, args...); err != nil {
		return fmt.Errorf("insert verification token: %w", err)
	}

	return nil
}

// GetVerificationByHash retrieves a verification token by its hashed value.
func (r *TokenRepository) GetVerificationByHash(ctx context.Context, hash string) (*domain.VerificationToken, error) {
	stmt, args, err := r.builder.Select(
		"id",
		"user_id",
		"token_hash",
		"purpose",
		"new_email",
		"ip",
		"user_agent",
		"created_at",
		"expires_at",
		"used_at",
		"revoked_at",
		"metadata",
	).
		From("iam.verification_tokens").
		Where(squirrel.Eq{"token_hash": hash}).
		Limit(1).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("build select verification token sql: %w", err)
	}

	row := r.pool.QueryRow(ctx, stmt, args...)

	var (
		token     domain.VerificationToken
		newEmail  sql.NullString
		ip        sql.NullString
		userAgent sql.NullString
		usedAt    sql.NullTime
		revokedAt sql.NullTime
		metadata  []byte
	)

	if err := row.Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&token.Purpose,
		&newEmail,
		&ip,
		&userAgent,
		&token.CreatedAt,
		&token.ExpiresAt,
		&usedAt,
		&revokedAt,
		&metadata,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("scan verification token: %w", err)
	}

	if newEmail.Valid {
		token.NewEmail = &newEmail.String
	}
	if ip.Valid {
		value := ip.String
		token.IP = &value
	}
	if userAgent.Valid {
		value := userAgent.String
		token.UserAgent = &value
	}
	if usedAt.Valid {
		t := usedAt.Time
		token.UsedAt = &t
	}
	if revokedAt.Valid {
		t := revokedAt.Time
		token.RevokedAt = &t
	}
	if len(metadata) > 0 {
		meta, err := unmarshalMetadata(metadata)
		if err != nil {
			return nil, fmt.Errorf("unmarshal verification metadata: %w", err)
		}
		token.Metadata = meta
	}

	return &token, nil
}

// ConsumeVerification marks a verification token as used.
func (r *TokenRepository) ConsumeVerification(ctx context.Context, id string) error {
	sql, args, err := r.builder.Update("iam.verification_tokens").
		Set("used_at", time.Now().UTC()).
		Where(squirrel.Eq{"id": id}).
		ToSql()
	if err != nil {
		return fmt.Errorf("build consume verification sql: %w", err)
	}

	ct, err := r.pool.Exec(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("consume verification token: %w", err)
	}

	if ct.RowsAffected() == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// CreatePasswordReset inserts a password reset token row.
func (r *TokenRepository) CreatePasswordReset(ctx context.Context, token domain.PasswordResetToken) error {
	metadata, err := marshalMetadata(token.Metadata)
	if err != nil {
		return fmt.Errorf("prepare password reset metadata: %w", err)
	}

	sql, args, err := r.builder.Insert("iam.password_reset_tokens").
		Columns(
			"id",
			"user_id",
			"token_hash",
			"ip",
			"user_agent",
			"created_at",
			"expires_at",
			"used_at",
			"revoked_at",
			"metadata",
		).
		Values(
			token.ID,
			token.UserID,
			token.TokenHash,
			token.IP,
			token.UserAgent,
			token.CreatedAt,
			token.ExpiresAt,
			token.UsedAt,
			token.RevokedAt,
			metadata,
		).
		ToSql()
	if err != nil {
		return fmt.Errorf("build insert password reset sql: %w", err)
	}

	if _, err := r.pool.Exec(ctx, sql, args...); err != nil {
		return fmt.Errorf("insert password reset token: %w", err)
	}

	return nil
}

// GetPasswordResetByHash fetches a password reset token by its hash.
func (r *TokenRepository) GetPasswordResetByHash(ctx context.Context, hash string) (*domain.PasswordResetToken, error) {
	stmt, args, err := r.builder.Select(
		"id",
		"user_id",
		"token_hash",
		"ip",
		"user_agent",
		"created_at",
		"expires_at",
		"used_at",
		"revoked_at",
		"metadata",
	).
		From("iam.password_reset_tokens").
		Where(squirrel.Eq{"token_hash": hash}).
		Limit(1).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("build select password reset sql: %w", err)
	}

	row := r.pool.QueryRow(ctx, stmt, args...)

	var (
		token     domain.PasswordResetToken
		ip        sql.NullString
		userAgent sql.NullString
		usedAt    sql.NullTime
		revokedAt sql.NullTime
		metadata  []byte
	)

	if err := row.Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&ip,
		&userAgent,
		&token.CreatedAt,
		&token.ExpiresAt,
		&usedAt,
		&revokedAt,
		&metadata,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("scan password reset token: %w", err)
	}

	if ip.Valid {
		value := ip.String
		token.IP = &value
	}
	if userAgent.Valid {
		value := userAgent.String
		token.UserAgent = &value
	}
	if usedAt.Valid {
		t := usedAt.Time
		token.UsedAt = &t
	}
	if revokedAt.Valid {
		t := revokedAt.Time
		token.RevokedAt = &t
	}
	if len(metadata) > 0 {
		meta, err := unmarshalMetadata(metadata)
		if err != nil {
			return nil, fmt.Errorf("unmarshal password reset metadata: %w", err)
		}
		token.Metadata = meta
	}

	return &token, nil
}

// ConsumePasswordReset marks a reset token as used.
func (r *TokenRepository) ConsumePasswordReset(ctx context.Context, id string) error {
	sql, args, err := r.builder.Update("iam.password_reset_tokens").
		Set("used_at", time.Now().UTC()).
		Where(squirrel.Eq{"id": id}).
		ToSql()
	if err != nil {
		return fmt.Errorf("build consume password reset sql: %w", err)
	}

	ct, err := r.pool.Exec(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("consume password reset token: %w", err)
	}

	if ct.RowsAffected() == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// CreateRefreshToken inserts a refresh token hash for a user.
func (r *TokenRepository) CreateRefreshToken(ctx context.Context, token domain.RefreshToken) error {
	metadata, err := marshalMetadata(token.Metadata)
	if err != nil {
		return fmt.Errorf("prepare refresh token metadata: %w", err)
	}

	sql, args, err := r.builder.Insert("iam.refresh_tokens").
		Columns(
			"id",
			"user_id",
			"token_hash",
			"client_id",
			"ip",
			"user_agent",
			"created_at",
			"expires_at",
			"revoked_at",
			"metadata",
		).
		Values(
			token.ID,
			token.UserID,
			token.TokenHash,
			token.ClientID,
			token.IP,
			token.UserAgent,
			token.CreatedAt,
			token.ExpiresAt,
			token.RevokedAt,
			metadata,
		).
		ToSql()
	if err != nil {
		return fmt.Errorf("build insert refresh token sql: %w", err)
	}

	if _, err := r.pool.Exec(ctx, sql, args...); err != nil {
		return fmt.Errorf("insert refresh token: %w", err)
	}

	return nil
}

// GetRefreshTokenByHash retrieves a refresh token record by its hashed value.
func (r *TokenRepository) GetRefreshTokenByHash(ctx context.Context, hash string) (*domain.RefreshToken, error) {
	stmt, args, err := r.builder.Select(
		"id",
		"user_id",
		"token_hash",
		"client_id",
		"ip",
		"user_agent",
		"created_at",
		"expires_at",
		"revoked_at",
		"metadata",
	).
		From("iam.refresh_tokens").
		Where(squirrel.Eq{"token_hash": hash}).
		Limit(1).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("build select refresh token sql: %w", err)
	}

	row := r.pool.QueryRow(ctx, stmt, args...)

	var (
		token     domain.RefreshToken
		clientID  sql.NullString
		ip        sql.NullString
		userAgent sql.NullString
		revokedAt sql.NullTime
		metadata  []byte
	)

	if err := row.Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&clientID,
		&ip,
		&userAgent,
		&token.CreatedAt,
		&token.ExpiresAt,
		&revokedAt,
		&metadata,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("scan refresh token: %w", err)
	}

	if clientID.Valid {
		token.ClientID = &clientID.String
	}
	if ip.Valid {
		value := ip.String
		token.IP = &value
	}
	if userAgent.Valid {
		value := userAgent.String
		token.UserAgent = &value
	}
	if revokedAt.Valid {
		value := revokedAt.Time
		token.RevokedAt = &value
	}
	if len(metadata) > 0 {
		meta, err := unmarshalMetadata(metadata)
		if err != nil {
			return nil, fmt.Errorf("unmarshal refresh metadata: %w", err)
		}
		token.Metadata = meta
	}

	return &token, nil
}

// RevokeRefreshToken marks a single refresh token hash as revoked.
func (r *TokenRepository) RevokeRefreshToken(ctx context.Context, refreshTokenID string) error {
	sql, args, err := r.builder.Update("iam.refresh_tokens").
		Set("revoked_at", time.Now().UTC()).
		Where(squirrel.Eq{"id": refreshTokenID}).
		ToSql()
	if err != nil {
		return fmt.Errorf("build revoke refresh token sql: %w", err)
	}

	ct, err := r.pool.Exec(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("revoke refresh token: %w", err)
	}

	if ct.RowsAffected() == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// RevokeRefreshTokensForUser revokes all active refresh tokens for a user.
func (r *TokenRepository) RevokeRefreshTokensForUser(ctx context.Context, userID string) error {
	sql, args, err := r.builder.Update("iam.refresh_tokens").
		Set("revoked_at", time.Now().UTC()).
		Where(squirrel.Eq{"user_id": userID}).
		Where("revoked_at IS NULL").
		ToSql()
	if err != nil {
		return fmt.Errorf("build revoke refresh tokens sql: %w", err)
	}

	if _, err := r.pool.Exec(ctx, sql, args...); err != nil {
		return fmt.Errorf("revoke refresh tokens: %w", err)
	}

	return nil
}

// StoreAccessTokenJTI records an issued JWT identifier for potential revocation.
func (r *TokenRepository) StoreAccessTokenJTI(ctx context.Context, record domain.AccessTokenJTI) error {
	sql, args, err := r.builder.Insert("iam.access_token_jti").
		Columns(
			"jti",
			"user_id",
			"session_id",
			"issued_at",
			"expires_at",
		).
		Values(
			record.JTI,
			record.UserID,
			record.SessionID,
			record.IssuedAt,
			record.ExpiresAt,
		).
		ToSql()
	if err != nil {
		return fmt.Errorf("build insert access token jti sql: %w", err)
	}

	if _, err := r.pool.Exec(ctx, sql, args...); err != nil {
		return fmt.Errorf("insert access token jti: %w", err)
	}

	return nil
}

// BlacklistAccessTokenJTI inserts or updates a revoked access token identifier.
func (r *TokenRepository) BlacklistAccessTokenJTI(ctx context.Context, revoked domain.RevokedAccessTokenJTI) error {
	revokedAt := revoked.RevokedAt
	if revokedAt.IsZero() {
		revokedAt = time.Now().UTC()
	}

	sql, args, err := r.builder.Insert("iam.revoked_access_token_jti").
		Columns("jti", "revoked_at", "reason").
		Values(revoked.JTI, revokedAt, revoked.Reason).
		Suffix("ON CONFLICT (jti) DO UPDATE SET revoked_at = EXCLUDED.revoked_at, reason = COALESCE(EXCLUDED.reason, revoked_access_token_jti.reason)").
		ToSql()
	if err != nil {
		return fmt.Errorf("build upsert revoked access token jti sql: %w", err)
	}

	if _, err := r.pool.Exec(ctx, sql, args...); err != nil {
		return fmt.Errorf("upsert revoked access token jti: %w", err)
	}

	return nil
}

// IsAccessTokenJTIRevoked checks whether a given JTI is blacklisted.
func (r *TokenRepository) IsAccessTokenJTIRevoked(ctx context.Context, jti string) (bool, error) {
	row := r.pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM iam.revoked_access_token_jti WHERE jti = $1)", jti)
	var exists bool
	if err := row.Scan(&exists); err != nil {
		return false, fmt.Errorf("check revoked access token jti: %w", err)
	}
	return exists, nil
}

func marshalMetadata(meta map[string]any) ([]byte, error) {
	if meta == nil {
		return nil, nil
	}

	payload, err := json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("marshal metadata: %w", err)
	}
	return payload, nil
}

func unmarshalMetadata(payload []byte) (map[string]any, error) {
	if len(payload) == 0 {
		return nil, nil
	}

	var meta map[string]any
	if err := json.Unmarshal(payload, &meta); err != nil {
		return nil, err
	}
	return meta, nil
}

var _ port.TokenRepository = (*TokenRepository)(nil)
