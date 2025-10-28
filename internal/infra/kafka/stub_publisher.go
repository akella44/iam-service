package kafka

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/core/port"
)

// StubPublisher logs events instead of sending them to Kafka. Useful for development environments.
type StubPublisher struct {
	logger *zap.Logger
}

// NewStubPublisher constructs a development-friendly event publisher.
func NewStubPublisher(logger *zap.Logger) *StubPublisher {
	return &StubPublisher{logger: logger}
}

func (p *StubPublisher) logEvent(eventType, userID string, at time.Time, payload any) {
	if at.IsZero() {
		at = time.Now().UTC()
	}

	p.logger.Info("Stub event published",
		zap.String("event_type", eventType),
		zap.String("user_id", userID),
		zap.Time("timestamp", at.UTC()),
		zap.Any("payload", payload),
	)
}

// PublishUserRegistered logs iam.user.registered events.
func (p *StubPublisher) PublishUserRegistered(_ context.Context, event domain.UserRegisteredEvent) error {
	payload := map[string]any{
		"user_id":             event.UserID,
		"username":            event.Username,
		"email":               event.Email,
		"phone":               event.Phone,
		"status":              event.Status,
		"registered_at":       event.RegisteredAt,
		"registration_method": event.RegistrationMethod,
		"metadata":            event.Metadata,
	}
	p.logEvent("iam.user.registered", event.UserID, event.RegisteredAt, payload)
	return nil
}

// PublishPasswordChanged logs iam.user.password.changed events.
func (p *StubPublisher) PublishPasswordChanged(_ context.Context, event domain.PasswordChangedEvent) error {
	payload := map[string]any{
		"user_id":           event.UserID,
		"changed_at":        event.ChangedAt,
		"changed_by":        event.ChangedBy,
		"sessions_revoked":  event.SessionsRevoked,
		"notification_sent": event.NotificationSent,
		"metadata":          event.Metadata,
	}
	p.logEvent("iam.user.password.changed", event.UserID, event.ChangedAt, payload)
	return nil
}

// PublishPasswordResetRequested logs iam.user.password.reset_requested events.
func (p *StubPublisher) PublishPasswordResetRequested(_ context.Context, event domain.PasswordResetRequestedEvent) error {
	payload := map[string]any{
		"user_id":            event.UserID,
		"request_id":         event.RequestID,
		"requested_at":       event.RequestedAt,
		"delivery_method":    event.DeliveryMethod,
		"destination":        event.Destination,
		"masked_destination": event.MaskedDestination,
		"ip_address":         event.IPAddress,
		"expires_at":         event.ExpiresAt,
		"metadata":           event.Metadata,
	}
	p.logEvent("iam.user.password.reset_requested", event.UserID, event.RequestedAt, payload)
	return nil
}

// PublishRolesAssigned logs iam.user.roles.assigned events.
func (p *StubPublisher) PublishRolesAssigned(_ context.Context, event domain.RolesAssignedEvent) error {
	payload := map[string]any{
		"user_id":     event.UserID,
		"roles_added": event.RolesAdded,
		"assigned_by": event.AssignedBy,
		"assigned_at": event.AssignedAt,
		"metadata":    event.Metadata,
	}
	p.logEvent("iam.user.roles.assigned", event.UserID, event.AssignedAt, payload)
	return nil
}

// PublishRolesRevoked logs iam.user.roles.revoked events.
func (p *StubPublisher) PublishRolesRevoked(_ context.Context, event domain.RolesRevokedEvent) error {
	payload := map[string]any{
		"user_id":       event.UserID,
		"roles_removed": event.RolesRemoved,
		"revoked_by":    event.RevokedBy,
		"revoked_at":    event.RevokedAt,
		"reason":        event.Reason,
		"metadata":      event.Metadata,
	}
	p.logEvent("iam.user.roles.revoked", event.UserID, event.RevokedAt, payload)
	return nil
}

// PublishSessionRevoked logs iam.session.revoked events.
func (p *StubPublisher) PublishSessionRevoked(_ context.Context, event domain.SessionRevokedEvent) error {
	payload := map[string]any{
		"session_id":     event.SessionID,
		"user_id":        event.UserID,
		"device_label":   event.DeviceLabel,
		"revoked_at":     event.RevokedAt,
		"revoked_by":     event.RevokedBy,
		"reason":         event.Reason,
		"tokens_revoked": event.TokensRevoked,
		"ip_address":     event.IPAddress,
		"metadata":       event.Metadata,
	}
	p.logEvent("iam.session.revoked", event.UserID, event.RevokedAt, payload)
	return nil
}

var _ port.EventPublisher = (*StubPublisher)(nil)
