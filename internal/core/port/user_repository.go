package port

import (
	"context"
	"time"

	"github.com/arklim/social-platform-iam/internal/core/domain"
)

// UserRepository exposes persistence behavior for users.
type UserRepository interface {
	Create(ctx context.Context, user domain.User) error
	GetByID(ctx context.Context, id string) (*domain.User, error)
	GetByIdentifier(ctx context.Context, identifier string) (*domain.User, error)
	UpdateStatus(ctx context.Context, id string, status domain.UserStatus) error
	UpdatePassword(ctx context.Context, id string, passwordHash string, passwordAlgo string, changedAt time.Time) error
}
