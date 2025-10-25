package domain

import "time"

// UserStatus enumerates possible account states.
type UserStatus string

const (
	UserStatusPending  UserStatus = "pending"
	UserStatusActive   UserStatus = "active"
	UserStatusLocked   UserStatus = "locked"
	UserStatusDisabled UserStatus = "disabled"
)

// User mirrors the persisted representation in the users table.
type User struct {
	ID                 string
	Username           string
	Email              string
	Phone              *string
	PasswordHash       string
	PasswordAlgo       string
	Status             UserStatus
	IsActive           bool
	RegisteredAt       time.Time
	LastLogin          *time.Time
	LastPasswordChange time.Time
}

// UserPasswordHistory tracks historical password hashes for reuse prevention.
type UserPasswordHistory struct {
	ID           string
	UserID       string
	PasswordHash string
	SetAt        time.Time
}

// LoginAttempt records authentication attempts for throttling and audit.
type LoginAttempt struct {
	ID              string
	UserID          *string
	UsernameOrEmail string
	Succeeded       bool
	IP              *string
	UserAgent       *string
	CreatedAt       time.Time
}

// PasswordContext carries identifying information to strengthen password policy checks.
type PasswordContext struct {
	Username string
	Email    string
	Phone    *string
}
