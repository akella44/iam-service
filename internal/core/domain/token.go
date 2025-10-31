package domain

import "time"

// RefreshToken represents a long-lived refresh token with rotation support.
type RefreshToken struct {
	ID            string
	UserID        string
	SessionID     *string
	TokenHash     string
	FamilyID      string
	IssuedVersion int64
	ClientID      *string
	IP            *string
	UserAgent     *string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	UsedAt        *time.Time
	RevokedAt     *time.Time
	Metadata      map[string]any
}

// IsExpired reports whether the token has elapsed its validity window.
func (t RefreshToken) IsExpired(at time.Time) bool {
	return !t.ExpiresAt.After(at)
}

// IsRevoked reports whether the token has been explicitly revoked.
func (t RefreshToken) IsRevoked() bool {
	return t.RevokedAt != nil
}

// IsActive returns true when the token can still be presented for rotation.
func (t RefreshToken) IsActive(at time.Time) bool {
	if t.IsRevoked() || t.UsedAt != nil {
		return false
	}
	return !t.IsExpired(at)
}

// MarkUsed records the moment the refresh token was exchanged.
// Returns true if the value changed (i.e. token was previously unused).
func (t *RefreshToken) MarkUsed(at time.Time) bool {
	if t.UsedAt != nil {
		return false
	}
	timeCopy := at
	t.UsedAt = &timeCopy
	return true
}

// Revoke marks the token as revoked.
// Returns true if the token transitioned to the revoked state.
func (t *RefreshToken) Revoke(at time.Time) bool {
	if t.RevokedAt != nil {
		return false
	}
	timeCopy := at
	t.RevokedAt = &timeCopy
	return true
}

// IsStale reports whether the refresh token was issued against an older session version.
func (t RefreshToken) IsStale(currentSessionVersion int64) bool {
	if currentSessionVersion <= 0 {
		return false
	}
	return t.IssuedVersion > 0 && t.IssuedVersion < currentSessionVersion
}

// AccessTokenJTI represents a tracked access token identifier.
type AccessTokenJTI struct {
	JTI       string
	UserID    string
	SessionID *string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// IsExpired reports whether the JTI record has elapsed its lifetime.
func (j AccessTokenJTI) IsExpired(at time.Time) bool {
	return !j.ExpiresAt.After(at)
}

// RevokedAccessTokenJTI models a blacklisted access token identifier.
type RevokedAccessTokenJTI struct {
	JTI       string
	RevokedAt time.Time
	Reason    *string
}

// VerificationToken represents email/phone verification artifacts.
type VerificationToken struct {
	ID        string
	UserID    string
	TokenHash string
	Purpose   string
	NewEmail  *string
	IP        *string
	UserAgent *string
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    *time.Time
	RevokedAt *time.Time
	Metadata  map[string]any
}

// IsExpired reports whether the verification token can still be redeemed.
func (t VerificationToken) IsExpired(at time.Time) bool {
	return !t.ExpiresAt.After(at)
}

// Consume marks the verification token as used.
// Returns true when the token transitions from unused to used.
func (t *VerificationToken) Consume(at time.Time) bool {
	if t.UsedAt != nil {
		return false
	}
	timeCopy := at
	t.UsedAt = &timeCopy
	return true
}

// Revoke marks the verification token as revoked.
func (t *VerificationToken) Revoke(at time.Time) bool {
	if t.RevokedAt != nil {
		return false
	}
	timeCopy := at
	t.RevokedAt = &timeCopy
	return true
}

// PasswordResetToken models password reset artifacts across delivery channels.
type PasswordResetToken struct {
	ID        string
	UserID    string
	TokenHash string
	IP        *string
	UserAgent *string
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    *time.Time
	RevokedAt *time.Time
	Metadata  map[string]any
}

// IsExpired reports whether the password reset token can still be redeemed.
func (t PasswordResetToken) IsExpired(at time.Time) bool {
	return !t.ExpiresAt.After(at)
}

// Consume marks the password reset token as used.
func (t *PasswordResetToken) Consume(at time.Time) bool {
	if t.UsedAt != nil {
		return false
	}
	timeCopy := at
	t.UsedAt = &timeCopy
	return true
}

// Revoke marks the password reset token as revoked.
func (t *PasswordResetToken) Revoke(at time.Time) bool {
	if t.RevokedAt != nil {
		return false
	}
	timeCopy := at
	t.RevokedAt = &timeCopy
	return true
}
