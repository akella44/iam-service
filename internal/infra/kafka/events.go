package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/IBM/sarama"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"

	"github.com/arklim/social-platform-iam/internal/core/domain"
	"github.com/arklim/social-platform-iam/internal/core/port"
	"github.com/arklim/social-platform-iam/internal/infra/config"
)

const schemaVersion = "1.0"

// EventPublisher implements port.EventPublisher using Kafka.
type EventPublisher struct {
	producer *Producer
	logger   *zap.Logger
	appCfg   config.AppSettings
}

// NewEventPublisher constructs a Kafka-backed event publisher.
func NewEventPublisher(producer *Producer, appCfg config.AppSettings, logger *zap.Logger) *EventPublisher {
	return &EventPublisher{producer: producer, appCfg: appCfg, logger: logger}
}

type envelopeMetadata map[string]string

type eventEnvelope struct {
	EventID   string           `json:"event_id"`
	EventType string           `json:"event_type"`
	UserID    string           `json:"user_id,omitempty"`
	Timestamp time.Time        `json:"timestamp"`
	Version   string           `json:"version"`
	Payload   any              `json:"payload"`
	Metadata  envelopeMetadata `json:"metadata,omitempty"`
}

func (p *EventPublisher) publish(ctx context.Context, eventID, eventType, userID string, ts time.Time, payload any) error {
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	id := eventID
	if id == "" {
		id = uuid.NewString()
	}

	metadata := envelopeMetadata{
		"service":     p.appCfg.Name,
		"environment": p.appCfg.Env,
	}

	if span := trace.SpanFromContext(ctx); span != nil {
		if sc := span.SpanContext(); sc.IsValid() {
			metadata["trace_id"] = sc.TraceID().String()
		}
	}

	envelope := eventEnvelope{
		EventID:   id,
		EventType: eventType,
		UserID:    userID,
		Timestamp: ts.UTC(),
		Version:   schemaVersion,
		Payload:   payload,
		Metadata:  metadata,
	}

	bytes, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("marshal event envelope: %w", err)
	}

	message := &sarama.ProducerMessage{
		Topic: p.producer.TopicName(eventType),
		Value: sarama.ByteEncoder(bytes),
	}

	select {
	case p.producer.Producer().Input() <- message:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// PublishUserRegistered publishes iam.user.registered events.
func (p *EventPublisher) PublishUserRegistered(ctx context.Context, event domain.UserRegisteredEvent) error {
	payload := struct {
		UserID             string         `json:"user_id"`
		Username           string         `json:"username"`
		Email              *string        `json:"email,omitempty"`
		Phone              *string        `json:"phone,omitempty"`
		Status             string         `json:"status"`
		RegisteredAt       time.Time      `json:"registered_at"`
		RegistrationMethod string         `json:"registration_method"`
		Metadata           map[string]any `json:"metadata,omitempty"`
	}{
		UserID:             event.UserID,
		Username:           event.Username,
		Email:              event.Email,
		Phone:              event.Phone,
		Status:             event.Status,
		RegisteredAt:       event.RegisteredAt.UTC(),
		RegistrationMethod: event.RegistrationMethod,
		Metadata:           event.Metadata,
	}

	return p.publish(ctx, event.EventID, "iam.user.registered", event.UserID, event.RegisteredAt, payload)
}

// PublishPasswordChanged publishes iam.user.password.changed events.
func (p *EventPublisher) PublishPasswordChanged(ctx context.Context, event domain.PasswordChangedEvent) error {
	payload := struct {
		UserID           string         `json:"user_id"`
		ChangedAt        time.Time      `json:"changed_at"`
		ChangedBy        string         `json:"changed_by"`
		SessionsRevoked  int            `json:"sessions_revoked"`
		NotificationSent bool           `json:"notification_sent"`
		Metadata         map[string]any `json:"metadata,omitempty"`
	}{
		UserID:           event.UserID,
		ChangedAt:        event.ChangedAt.UTC(),
		ChangedBy:        event.ChangedBy,
		SessionsRevoked:  event.SessionsRevoked,
		NotificationSent: event.NotificationSent,
		Metadata:         event.Metadata,
	}

	return p.publish(ctx, event.EventID, "iam.user.password.changed", event.UserID, event.ChangedAt, payload)
}

// PublishPasswordResetRequested publishes iam.user.password.reset_requested events.
func (p *EventPublisher) PublishPasswordResetRequested(ctx context.Context, event domain.PasswordResetRequestedEvent) error {
	payload := struct {
		UserID            string         `json:"user_id"`
		RequestID         string         `json:"request_id"`
		RequestedAt       time.Time      `json:"requested_at"`
		DeliveryMethod    string         `json:"delivery_method"`
		Destination       string         `json:"destination,omitempty"`
		MaskedDestination string         `json:"masked_destination,omitempty"`
		IPAddress         *string        `json:"ip_address,omitempty"`
		ExpiresAt         time.Time      `json:"expires_at"`
		Metadata          map[string]any `json:"metadata,omitempty"`
	}{
		UserID:            event.UserID,
		RequestID:         event.RequestID,
		RequestedAt:       event.RequestedAt.UTC(),
		DeliveryMethod:    event.DeliveryMethod,
		Destination:       event.Destination,
		MaskedDestination: event.MaskedDestination,
		IPAddress:         event.IPAddress,
		ExpiresAt:         event.ExpiresAt.UTC(),
		Metadata:          event.Metadata,
	}

	timestamp := event.RequestedAt
	if timestamp.IsZero() {
		timestamp = event.ExpiresAt
	}

	return p.publish(ctx, event.EventID, "iam.user.password.reset_requested", event.UserID, timestamp, payload)
}

// PublishRolesAssigned publishes iam.user.roles.assigned events.
func (p *EventPublisher) PublishRolesAssigned(ctx context.Context, event domain.RolesAssignedEvent) error {
	roles := make([]map[string]string, 0, len(event.RolesAdded))
	for _, assignment := range event.RolesAdded {
		role := map[string]string{
			"role_id":   assignment.RoleID,
			"role_name": assignment.RoleName,
		}
		roles = append(roles, role)
	}

	payload := struct {
		UserID     string              `json:"user_id"`
		RolesAdded []map[string]string `json:"roles_added"`
		AssignedBy string              `json:"assigned_by"`
		AssignedAt time.Time           `json:"assigned_at"`
		Metadata   map[string]any      `json:"metadata,omitempty"`
	}{
		UserID:     event.UserID,
		RolesAdded: roles,
		AssignedBy: event.AssignedBy,
		AssignedAt: event.AssignedAt.UTC(),
		Metadata:   event.Metadata,
	}

	return p.publish(ctx, event.EventID, "iam.user.roles.assigned", event.UserID, event.AssignedAt, payload)
}

// PublishRolesRevoked publishes iam.user.roles.revoked events.
func (p *EventPublisher) PublishRolesRevoked(ctx context.Context, event domain.RolesRevokedEvent) error {
	roles := make([]map[string]string, 0, len(event.RolesRemoved))
	for _, assignment := range event.RolesRemoved {
		role := map[string]string{
			"role_id":   assignment.RoleID,
			"role_name": assignment.RoleName,
		}
		roles = append(roles, role)
	}

	payload := struct {
		UserID       string              `json:"user_id"`
		RolesRemoved []map[string]string `json:"roles_removed"`
		RevokedBy    string              `json:"revoked_by"`
		RevokedAt    time.Time           `json:"revoked_at"`
		Reason       string              `json:"reason,omitempty"`
		Metadata     map[string]any      `json:"metadata,omitempty"`
	}{
		UserID:       event.UserID,
		RolesRemoved: roles,
		RevokedBy:    event.RevokedBy,
		RevokedAt:    event.RevokedAt.UTC(),
		Reason:       event.Reason,
		Metadata:     event.Metadata,
	}

	return p.publish(ctx, event.EventID, "iam.user.roles.revoked", event.UserID, event.RevokedAt, payload)
}

// PublishSessionRevoked publishes iam.session.revoked events.
func (p *EventPublisher) PublishSessionRevoked(ctx context.Context, event domain.SessionRevokedEvent) error {
	payload := struct {
		SessionID     string         `json:"session_id"`
		UserID        string         `json:"user_id"`
		DeviceLabel   *string        `json:"device_label,omitempty"`
		RevokedAt     time.Time      `json:"revoked_at"`
		RevokedBy     string         `json:"revoked_by"`
		Reason        string         `json:"reason"`
		TokensRevoked int            `json:"tokens_revoked"`
		IPAddress     *string        `json:"ip_address,omitempty"`
		Metadata      map[string]any `json:"metadata,omitempty"`
	}{
		SessionID:     event.SessionID,
		UserID:        event.UserID,
		DeviceLabel:   event.DeviceLabel,
		RevokedAt:     event.RevokedAt.UTC(),
		RevokedBy:     event.RevokedBy,
		Reason:        event.Reason,
		TokensRevoked: event.TokensRevoked,
		IPAddress:     event.IPAddress,
		Metadata:      event.Metadata,
	}

	return p.publish(ctx, event.EventID, "iam.session.revoked", event.UserID, event.RevokedAt, payload)
}

var _ port.EventPublisher = (*EventPublisher)(nil)
