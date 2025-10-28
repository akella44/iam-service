package domain

import "time"

// UserRegisteredEvent represents the payload for iam.user.registered messages.
type UserRegisteredEvent struct {
	EventID            string
	UserID             string
	Username           string
	Email              *string
	Phone              *string
	Status             string
	RegisteredAt       time.Time
	RegistrationMethod string
	Metadata           map[string]any
}

// PasswordChangedEvent represents the payload for iam.user.password.changed messages.
type PasswordChangedEvent struct {
	EventID          string
	UserID           string
	ChangedAt        time.Time
	ChangedBy        string
	SessionsRevoked  int
	NotificationSent bool
	Metadata         map[string]any
}

// PasswordResetRequestedEvent represents the payload for iam.user.password.reset_requested messages.
type PasswordResetRequestedEvent struct {
	EventID           string
	UserID            string
	RequestID         string
	RequestedAt       time.Time
	DeliveryMethod    string
	Destination       string
	MaskedDestination string
	IPAddress         *string
	ExpiresAt         time.Time
	Metadata          map[string]any
}

// RoleAssignment captures individual role changes associated with an event.
type RoleAssignment struct {
	RoleID   string
	RoleName string
}

// RolesAssignedEvent represents the payload for iam.user.roles.assigned messages.
type RolesAssignedEvent struct {
	EventID    string
	UserID     string
	RolesAdded []RoleAssignment
	AssignedBy string
	AssignedAt time.Time
	Metadata   map[string]any
}

// RolesRevokedEvent represents the payload for iam.user.roles.revoked messages.
type RolesRevokedEvent struct {
	EventID      string
	UserID       string
	RolesRemoved []RoleAssignment
	RevokedBy    string
	RevokedAt    time.Time
	Reason       string
	Metadata     map[string]any
}

// SessionRevokedEvent represents the payload for iam.session.revoked messages.
type SessionRevokedEvent struct {
	EventID       string
	SessionID     string
	UserID        string
	DeviceLabel   *string
	RevokedAt     time.Time
	RevokedBy     string
	Reason        string
	TokensRevoked int
	IPAddress     *string
	Metadata      map[string]any
}
