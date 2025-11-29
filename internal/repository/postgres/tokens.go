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
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/core/port"
	"github.com/arklim/social-platform-iam/internal/repository"
)

// TokenRepository implements port.TokenRepository using PostgreSQL tables.
type TokenRepository struct {
	pool    *pgxpool.Pool
	exec    pgExecutor
	builder squirrel.StatementBuilderType
}

// NewTokenRepository constructs a new token repository.
func NewTokenRepository(pool *pgxpool.Pool) *TokenRepository {
	return &TokenRepository{
		pool:    pool,
		exec:    pool,
		builder: squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar),
	}
}

// WithTx returns a repository instance executing within the provided transaction.
func (r *TokenRepository) WithTx(tx pgx.Tx) *TokenRepository {
	if tx == nil {
		return r
	}
	return &TokenRepository{
		pool:    r.pool,
		exec:    tx,
		builder: r.builder,
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

	if _, err := r.exec.Exec(ctx, sql, args...); err != nil {
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

	row := r.exec.QueryRow(ctx, stmt, args...)

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

	ct, err := r.exec.Exec(ctx, sql, args...)
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

	if _, err := r.exec.Exec(ctx, sql, args...); err != nil {
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

	row := r.exec.QueryRow(ctx, stmt, args...)

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

	ct, err := r.exec.Exec(ctx, sql, args...)
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

	familyID := strings.TrimSpace(token.FamilyID)
	var familyValue any
	if familyID == "" {
		familyValue = squirrel.Expr("DEFAULT")
	} else {
		familyValue = familyID
	}

	issuedVersion := token.IssuedVersion
	if issuedVersion < 0 {
		issuedVersion = 0
	}
	if token.SessionID != nil && issuedVersion <= 0 {
		issuedVersion = 1
	}

	sql, args, err := r.builder.Insert("iam.refresh_tokens").
		Columns(
			"id",
			"user_id",
			"session_id",
			"family_id",
			"issued_version",
			"token_hash",
			"client_id",
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
			optionalString(token.SessionID),
			familyValue,
			issuedVersion,
			token.TokenHash,
			optionalString(token.ClientID),
			optionalString(token.IP),
			optionalString(token.UserAgent),
			token.CreatedAt,
			token.ExpiresAt,
			optionalTime(token.UsedAt),
			optionalTime(token.RevokedAt),
			metadata,
		).
		ToSql()
	if err != nil {
		return fmt.Errorf("build insert refresh token sql: %w", err)
	}

	if _, err := r.exec.Exec(ctx, sql, args...); err != nil {
		return fmt.Errorf("insert refresh token: %w", err)
	}

	return nil
}

// GetRefreshTokenByHash retrieves a refresh token record by its hashed value.
func (r *TokenRepository) GetRefreshTokenByHash(ctx context.Context, hash string) (*domain.RefreshToken, error) {
	stmt, args, err := r.builder.Select(
		"id",
		"user_id",
		"session_id",
		"family_id",
		"issued_version",
		"token_hash",
		"client_id",
		"ip",
		"user_agent",
		"created_at",
		"expires_at",
		"used_at",
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

	row := r.exec.QueryRow(ctx, stmt, args...)

	var (
		token         domain.RefreshToken
		sessionID     sql.NullString
		clientID      sql.NullString
		ip            sql.NullString
		userAgent     sql.NullString
		usedAt        sql.NullTime
		revokedAt     sql.NullTime
		metadata      []byte
		issuedVersion sql.NullInt64
	)

	if err := row.Scan(
		&token.ID,
		&token.UserID,
		&sessionID,
		&token.FamilyID,
		&issuedVersion,
		&token.TokenHash,
		&clientID,
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
		return nil, fmt.Errorf("scan refresh token: %w", err)
	}

	token.SessionID = nullableStringPtr(sessionID)
	token.ClientID = nullableStringPtr(clientID)
	token.IP = nullableStringPtr(ip)
	token.UserAgent = nullableStringPtr(userAgent)
	token.UsedAt = nullableTimePtr(usedAt)
	token.RevokedAt = nullableTimePtr(revokedAt)
	if issuedVersion.Valid {
		token.IssuedVersion = issuedVersion.Int64
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

	ct, err := r.exec.Exec(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("revoke refresh token: %w", err)
	}

	if ct.RowsAffected() == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// UpdateRefreshTokenIssuedVersion overwrites the stored issued_version for a refresh token record.
func (r *TokenRepository) UpdateRefreshTokenIssuedVersion(ctx context.Context, refreshTokenID string, version int64) error {
	if version <= 0 {
		return fmt.Errorf("version must be positive")
	}
	sql, args, err := r.builder.Update("iam.refresh_tokens").
		Set("issued_version", version).
		Where(squirrel.Eq{"id": refreshTokenID}).
		ToSql()
	if err != nil {
		return fmt.Errorf("build update refresh token version sql: %w", err)
	}

	ct, err := r.exec.Exec(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("update refresh token issued version: %w", err)
	}

	if ct.RowsAffected() == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// MarkRefreshTokenUsed updates the used_at timestamp for a refresh token if it has not been consumed yet.
func (r *TokenRepository) MarkRefreshTokenUsed(ctx context.Context, refreshTokenID string, usedAt time.Time) error {
	usedAt = usedAt.UTC()

	sql, args, err := r.builder.Update("iam.refresh_tokens").
		Set("used_at", usedAt).
		Where(squirrel.Eq{"id": refreshTokenID}).
		Where("used_at IS NULL").
		ToSql()
	if err != nil {
		return fmt.Errorf("build mark refresh token used sql: %w", err)
	}

	ct, err := r.exec.Exec(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("mark refresh token used: %w", err)
	}

	if ct.RowsAffected() == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// RevokeRefreshTokensByFamily revokes all active refresh tokens within the supplied family.
func (r *TokenRepository) RevokeRefreshTokensByFamily(ctx context.Context, familyID string, reason string) (int, error) {
	reason = strings.TrimSpace(reason)

	stmt := `
		WITH updated AS (
			UPDATE iam.refresh_tokens
			   SET revoked_at = COALESCE(revoked_at, now()),
			       metadata = CASE
			           WHEN $2::text IS NULL THEN metadata
			           ELSE jsonb_set(
			                   COALESCE(metadata, '{}'::jsonb),
			                   '{revoked_reason}',
			                   to_jsonb($2::text),
			                   true
			               )
			       END
			 WHERE family_id = $1
			   AND revoked_at IS NULL
			 RETURNING 1
		)
		SELECT count(*) FROM updated;
	`

	var reasonArg any
	if reason == "" {
		reasonArg = nil
	} else {
		reasonArg = reason
	}

	var count int
	if err := r.exec.QueryRow(ctx, stmt, familyID, reasonArg).Scan(&count); err != nil {
		return 0, fmt.Errorf("revoke refresh tokens by family: %w", err)
	}

	if count == 0 {
		return 0, repository.ErrNotFound
	}

	return count, nil
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

	if _, err := r.exec.Exec(ctx, sql, args...); err != nil {
		return fmt.Errorf("revoke refresh tokens: %w", err)
	}

	return nil
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
