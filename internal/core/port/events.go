package port

import (
	"context"

	"github.com/arklim/social-platform-iam/internal/core/domain"
)

// EventPublisher publishes domain events to the message bus.
type EventPublisher interface {
	PublishUserRegistered(ctx context.Context, event domain.UserRegisteredEvent) error
	PublishPasswordChanged(ctx context.Context, event domain.PasswordChangedEvent) error
	PublishPasswordResetRequested(ctx context.Context, event domain.PasswordResetRequestedEvent) error
	PublishRolesAssigned(ctx context.Context, event domain.RolesAssignedEvent) error
	PublishRolesRevoked(ctx context.Context, event domain.RolesRevokedEvent) error
	PublishSessionRevoked(ctx context.Context, event domain.SessionRevokedEvent) error
}
