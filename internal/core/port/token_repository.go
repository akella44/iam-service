package port

import (
	"context"
	"time"

	"github.com/arklim/social-platform-iam/internal/core/domain"
)

// TokenRepository manages verification, reset, refresh, and access token records.
type TokenRepository interface {
	CreateVerification(ctx context.Context, token domain.VerificationToken) error
	GetVerificationByHash(ctx context.Context, hash string) (*domain.VerificationToken, error)
	ConsumeVerification(ctx context.Context, id string) error
	CreatePasswordReset(ctx context.Context, token domain.PasswordResetToken) error
	GetPasswordResetByHash(ctx context.Context, hash string) (*domain.PasswordResetToken, error)
	ConsumePasswordReset(ctx context.Context, id string) error
	CreateRefreshToken(ctx context.Context, token domain.RefreshToken) error
	GetRefreshTokenByHash(ctx context.Context, hash string) (*domain.RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, refreshTokenID string) error
	MarkRefreshTokenUsed(ctx context.Context, refreshTokenID string, usedAt time.Time) error
	RevokeRefreshTokensByFamily(ctx context.Context, familyID string, reason string) (int, error)
	RevokeRefreshTokensForUser(ctx context.Context, userID string) error
	TrackJTI(ctx context.Context, record domain.AccessTokenJTI) error
	RevokeJTI(ctx context.Context, revoked domain.RevokedAccessTokenJTI) error
	RevokeJTIsBySession(ctx context.Context, sessionID string, reason string) (int, error)
	RevokeJTIsForUser(ctx context.Context, userID string, reason string) (int, error)
	IsJTIRevoked(ctx context.Context, jti string) (bool, error)
	CleanupExpiredJTIs(ctx context.Context, expiresBefore time.Time) (int, error)
}
