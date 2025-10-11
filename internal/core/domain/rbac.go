package domain

import "time"

// Role defines a set of permissions.
type Role struct {
	ID          string
	Name        string
	Description *string
}

// Permission defines a named capability.
type Permission struct {
	ID          string
	Name        string
	Description *string
}

// RolePermission links a role with a permission.
type RolePermission struct {
	RoleID       string
	PermissionID string
}

// UserRole assigns a role to a user.
type UserRole struct {
	UserID     string
	RoleID     string
	AssignedAt time.Time
}
