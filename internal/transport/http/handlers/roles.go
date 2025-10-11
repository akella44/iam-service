package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/arklim/social-platform-iam/internal/transport/http/middleware"
	"github.com/arklim/social-platform-iam/internal/usecase"
)

type RoleHandler struct {
	roles *usecase.RoleService
	auth  *usecase.AuthService
}

func NewRoleHandler(roles *usecase.RoleService, auth *usecase.AuthService) *RoleHandler {
	return &RoleHandler{roles: roles, auth: auth}
}

func (h *RoleHandler) RegisterRoutes(r *gin.RouterGroup) {
	r.POST("", h.CreateRole)
}

// CreateRole godoc
// @Summary Create a new role
// @Description Creates a role, optionally seeding permissions and assigning users.
// @Tags Roles
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Param request body RoleCreateRequest true "Role create request"
// @Success 201 {object} RoleCreateResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/roles [post]
func (h *RoleHandler) CreateRole(c *gin.Context) {
	if h.roles == nil {
		c.JSON(http.StatusInternalServerError, NewErrorResponse(c, "role handler not fully configured"))
		return
	}

	// Get authenticated user ID from middleware
	actorIDStr, ok := middleware.GetAuthenticatedUserID(c)
	if !ok || actorIDStr == "" {
		c.JSON(http.StatusUnauthorized, NewErrorResponse(c, "invalid authentication"))
		return
	}

	var req RoleCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, NewErrorResponse(c, "invalid role payload"))
		return
	}

	input := usecase.CreateRoleInput{
		Name:          strings.TrimSpace(req.Name),
		Permissions:   make([]usecase.PermissionInput, 0, len(req.Permissions)),
		AssignUserIDs: make([]string, 0, len(req.AssignUserIDs)),
	}

	if req.Description != nil {
		trimmed := strings.TrimSpace(*req.Description)
		if trimmed != "" {
			descCopy := trimmed
			input.Description = &descCopy
		}
	}

	for _, perm := range req.Permissions {
		permName := strings.TrimSpace(perm.Name)
		if permName == "" {
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: "permission name cannot be empty"})
			return
		}

		var descPtr *string
		if perm.Description != nil {
			trimmed := strings.TrimSpace(*perm.Description)
			if trimmed != "" {
				descCopy := trimmed
				descPtr = &descCopy
			}
		}

		input.Permissions = append(input.Permissions, usecase.PermissionInput{
			Name:        permName,
			Description: descPtr,
		})
	}

	for _, userID := range req.AssignUserIDs {
		trimmed := strings.TrimSpace(userID)
		if trimmed != "" {
			input.AssignUserIDs = append(input.AssignUserIDs, trimmed)
		}
	}

	result, err := h.roles.CreateRole(c.Request.Context(), actorIDStr, input)
	if err != nil {
		RespondWithMappedError(c, err, []ErrorCase{
			{Err: usecase.ErrPermissionDenied, Status: http.StatusForbidden, Message: "insufficient permissions"},
			{Err: usecase.ErrRoleExists, Status: http.StatusConflict, Message: "role already exists"},
			{Err: usecase.ErrUserNotFound, Status: http.StatusBadRequest, Message: "user not found"},
		}, http.StatusInternalServerError, "failed to create role")
		return
	}

	permissions := make([]PermissionPayload, 0, len(result.Permissions))
	for _, permission := range result.Permissions {
		permissions = append(permissions, PermissionPayload{
			ID:          permission.ID,
			Name:        permission.Name,
			Description: permission.Description,
		})
	}

	rolePayload := RolePayload{
		ID:          result.Role.ID,
		Name:        result.Role.Name,
		Description: result.Role.Description,
	}

	c.JSON(http.StatusCreated, RoleCreateResponse{
		Role:            rolePayload,
		Permissions:     permissions,
		AssignedUserIDs: result.AssignedUserIDs,
	})
}
