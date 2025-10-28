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
	Update(ctx context.Context, user domain.User) error
	UpdateStatus(ctx context.Context, id string, status domain.UserStatus) error
	UpdatePassword(ctx context.Context, id string, passwordHash string, passwordAlgo string, changedAt time.Time) error
	SoftDelete(ctx context.Context, id string) error
	List(ctx context.Context, filter UserFilter) ([]domain.User, error)
	Count(ctx context.Context, filter UserFilter) (int, error)
	AssignRoles(ctx context.Context, userID string, roleIDs []string) error
	RevokeRoles(ctx context.Context, userID string, roleIDs []string) error
	GetUserRoles(ctx context.Context, userID string) ([]domain.UserRole, error)
	ListPasswordHistory(ctx context.Context, userID string, limit int) ([]domain.UserPasswordHistory, error)
	AddPasswordHistory(ctx context.Context, entry domain.UserPasswordHistory) error
	TrimPasswordHistory(ctx context.Context, userID string, maxEntries int) error
}

// UserFilter provides controls for listing users.
type UserFilter struct {
	Status   domain.UserStatus
	IsActive *bool
	Limit    int
	Offset   int
}
