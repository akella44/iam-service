package domain

import "time"

// Session represents a persisted login session.
type Session struct {
	ID             string
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

// AccessTokenJTI tracks issued access tokens for revocation support.
type AccessTokenJTI struct {
	JTI       string
	UserID    string
	SessionID *string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// RevokedAccessTokenJTI stores blacklisted access token identifiers.
type RevokedAccessTokenJTI struct {
	JTI       string
	RevokedAt time.Time
	Reason    *string
}
