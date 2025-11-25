package domain

import "time"

// Session represents a persisted login session bound to a device and token family.
type Session struct {
	ID             string
	FamilyID       string
	UserID         string
	Version        int64
	RefreshTokenID *string
	IssuedVersion  *int64
	DeviceID       *string
	DeviceLabel    *string
	IPFirst        *string
	IPLast         *string
	UserAgent      *string
	CreatedAt      time.Time
	LastSeen       time.Time
	ExpiresAt      time.Time
	RevokedAt      *time.Time
	RevokeReason   *string
}

// IsActive reports whether the session is still valid (not revoked and not expired at the supplied moment).
func (s Session) IsActive(at time.Time) bool {
	if s.RevokedAt != nil {
		return false
	}
	return s.ExpiresAt.After(at)
}

// Touch updates last-seen metadata for the session when activity occurs.
func (s *Session) Touch(at time.Time, ip, userAgent *string) {
	s.LastSeen = at
	if s.IPFirst == nil && ip != nil {
		ipCopy := *ip
		s.IPFirst = &ipCopy
	}
	if ip != nil {
		ipCopy := *ip
		s.IPLast = &ipCopy
	}
	if userAgent != nil {
		uaCopy := *userAgent
		s.UserAgent = &uaCopy
	}
}

// Revoke marks the session (and downstream refresh tokens) as revoked.
// Returns true when the session changed state.
func (s *Session) Revoke(at time.Time, reason string) bool {
	if s.RevokedAt != nil {
		return false
	}
	s.RevokedAt = &at
	s.RevokeReason = &reason
	return true
}

// IncrementVersion bumps the in-memory session version counter and returns the new value.
func (s *Session) IncrementVersion() int64 {
	if s.Version < 0 {
		s.Version = 1
		return s.Version
	}
	s.Version++
	return s.Version
}

// SessionEvent captures lifecycle changes for sessions.
type SessionEvent struct {
	ID        string
	SessionID string
	Kind      string
	At        time.Time
	IP        *string
	UserAgent *string
	Details   map[string]any
}

// SubjectVersion represents the authoritative version contract for a subject.
type SubjectVersion struct {
	SubjectID      string
	CurrentVersion int64
	NotBefore      *time.Time
	UpdatedAt      time.Time
	UpdatedBy      string
	Reason         *string
}

// SubjectVersionChange captures previous and current state for audit and event emission.
type SubjectVersionChange struct {
	Previous *SubjectVersion
	Current  SubjectVersion
}

// SubjectVersionMutation describes the intent to modify a subject's version or not-before timestamp.
type SubjectVersionMutation struct {
	SubjectID  string
	Actor      string
	Reason     string
	NewVersion *int64
	NotBefore  *time.Time
	Metadata   map[string]any
	AppliedAt  time.Time
}

// SubjectVersionAuditEntry records immutable audit log rows for version changes.
type SubjectVersionAuditEntry struct {
	EventID           string
	SubjectID         string
	PreviousVersion   *int64
	NewVersion        int64
	PreviousNotBefore *time.Time
	NewNotBefore      *time.Time
	Actor             string
	Reason            string
	CreatedAt         time.Time
}
