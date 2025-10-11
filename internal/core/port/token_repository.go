package port

import (
	"context"

	"github.com/arklim/social-platform-iam/internal/core/domain"
)

// TokenRepository manages verification and password reset tokens.
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
	RevokeRefreshTokensForUser(ctx context.Context, userID string) error
	StoreAccessTokenJTI(ctx context.Context, record domain.AccessTokenJTI) error
	BlacklistAccessTokenJTI(ctx context.Context, revoked domain.RevokedAccessTokenJTI) error
	IsAccessTokenJTIRevoked(ctx context.Context, jti string) (bool, error)
}
