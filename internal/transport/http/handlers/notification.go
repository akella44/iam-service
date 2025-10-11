package handlers

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// NotificationDispatcher fans out security-critical events to downstream notifiers.
type NotificationDispatcher interface {
	SendRegistrationVerification(ctx context.Context, payload RegistrationNotification) error
	SendPasswordReset(ctx context.Context, payload PasswordResetNotification) error
}

// RegistrationNotification captures data needed to deliver registration verification credentials.
type RegistrationNotification struct {
	Delivery string
	Contact  string
	Username string
	Email    string
	Phone    string
	DevToken string
	DevCode  string
	Expires  time.Time
}

// PasswordResetNotification captures data needed to deliver password reset credentials.
type PasswordResetNotification struct {
	Delivery string
	Contact  string
	DevToken string
	DevCode  string
	Expires  time.Time
}

type noopDispatcher struct{}

func (noopDispatcher) SendRegistrationVerification(ctx context.Context, payload RegistrationNotification) error {
	return nil
}

func (noopDispatcher) SendPasswordReset(ctx context.Context, payload PasswordResetNotification) error {
	return nil
}

// LoggingNotificationDispatcher records credential dispatch events for observability without delivering them.
type LoggingNotificationDispatcher struct {
	logger *zap.Logger
}

// NewLoggingNotificationDispatcher constructs a notification dispatcher backed by structured logging.
func NewLoggingNotificationDispatcher(logger *zap.Logger) NotificationDispatcher {
	if logger == nil {
		return noopDispatcher{}
	}
	return &LoggingNotificationDispatcher{logger: logger}
}

func (d *LoggingNotificationDispatcher) SendRegistrationVerification(ctx context.Context, payload RegistrationNotification) error {
	if d == nil || d.logger == nil {
		return nil
	}

	fields := []zap.Field{
		zap.String("delivery", payload.Delivery),
		zap.String("contact", payload.Contact),
		zap.Time("expires_at", payload.Expires),
	}

	if payload.Username != "" {
		fields = append(fields, zap.String("username", payload.Username))
	}

	if payload.Email != "" {
		fields = append(fields, zap.String("email", payload.Email))
	}
	if payload.Phone != "" {
		fields = append(fields, zap.String("phone", payload.Phone))
	}
	if payload.DevToken != "" {
		fields = append(fields, zap.String("dev_token", payload.DevToken))
	}
	if payload.DevCode != "" {
		fields = append(fields, zap.String("dev_code", payload.DevCode))
	}

	d.logger.Info("dispatch registration verification", fields...)
	return nil
}

func (d *LoggingNotificationDispatcher) SendPasswordReset(ctx context.Context, payload PasswordResetNotification) error {
	if d == nil || d.logger == nil {
		return nil
	}

	fields := []zap.Field{
		zap.String("delivery", payload.Delivery),
		zap.String("contact", payload.Contact),
		zap.Time("expires_at", payload.Expires),
	}

	if payload.DevToken != "" {
		fields = append(fields, zap.String("dev_token", payload.DevToken))
	}
	if payload.DevCode != "" {
		fields = append(fields, zap.String("dev_code", payload.DevCode))
	}

	d.logger.Info("dispatch password reset", fields...)
	return nil
}
