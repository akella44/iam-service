package domain

import (
	"fmt"
	"time"
)

// Role defines a set of permissions.
type Role struct {
	ID          string
	Name        string
	Description *string
}

// Permission defines a named capability.
type Permission struct {
	ID               string
	Name             string
	ServiceNamespace string
	Action           string
	Description      *string
}

// CanonicalName returns the namespace:action composite identifier used across the system.
func (p Permission) CanonicalName() string {
	if p.Name != "" {
		return p.Name
	}
	return fmt.Sprintf("%s:%s", p.ServiceNamespace, p.Action)
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
