package usecase

import (
	"strings"

	"github.com/arklim/social-platform-iam/internal/core/domain"
)

const (
	sessionReasonUserDisabled        = "user_disabled"
	sessionReasonRolesRevoked        = "user_roles_revoked"
	sessionReasonElevatedPermissions = "elevated_permissions_assigned"
)

var forcedReauthPermissionNames = map[string]struct{}{
	strings.ToLower(PermissionUserManage):            {},
	strings.ToLower(PermissionUserPasswordChangeAny): {},
	strings.ToLower(PermissionRoleAssign):            {},
	strings.ToLower(PermissionRoleCreate):            {},
}

func isForcedReauthPermission(name string) bool {
	canonical := strings.ToLower(strings.TrimSpace(name))
	if canonical == "" {
		return false
	}
	_, forced := forcedReauthPermissionNames[canonical]
	return forced
}

func permissionsRequireForcedReauth(perms []domain.Permission) bool {
	for _, perm := range perms {
		if isForcedReauthPermission(perm.CanonicalName()) {
			return true
		}
	}
	return false
}
