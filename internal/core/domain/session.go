package domain

import "time"

// Session represents a persisted login session bound to a device and token family.
type Session struct {
	ID             string
	FamilyID       string
	UserID         string
	RefreshTokenID *string
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
