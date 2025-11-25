package handlers

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/arklim/social-platform-iam/internal/repository"
	"github.com/arklim/social-platform-iam/internal/transport/http/middleware"
	"github.com/arklim/social-platform-iam/internal/usecase"
)

// SubjectVersionHandler exposes administrative endpoints for subject version management.
type SubjectVersionHandler struct {
	service *usecase.SubjectVersionService
}

// NewSubjectVersionHandler constructs a new handler instance.
func NewSubjectVersionHandler(service *usecase.SubjectVersionService) *SubjectVersionHandler {
	return &SubjectVersionHandler{service: service}
}

// BumpSubjectVersion godoc
// @Summary Bump a subject session version
// @Description Increments a subject's session version or adjusts the not-before timestamp for revocation workflows.
// @Tags Subjects
// @Security Bearer
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Param subjectId path string true "Subject identifier"
// @Param request body SubjectVersionBumpRequest true "Subject version bump request"
// @Success 202 {object} SubjectVersionBumpResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/admin/subjects/{subjectId}/session-version [post]
// BumpSubjectVersion handles POST /admin/subjects/{subjectId}/session-version requests.
func (h *SubjectVersionHandler) BumpSubjectVersion(c *gin.Context) {
	if h.service == nil {
		c.JSON(http.StatusServiceUnavailable, NewErrorResponse(c, "subject version service unavailable"))
		return
	}

	subjectID := strings.TrimSpace(c.Param("subjectId"))
	if subjectID == "" {
		c.JSON(http.StatusBadRequest, NewErrorResponse(c, "subjectId is required"))
		return
	}

	var req SubjectVersionBumpRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, NewErrorResponse(c, "invalid request payload"))
		return
	}

	newVersion := req.NewVersion
	if newVersion != nil && *newVersion <= 0 {
		c.JSON(http.StatusBadRequest, NewErrorResponse(c, "new_version must be positive"))
		return
	}

	var notBeforePtr *time.Time
	if req.NotBefore != nil {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(*req.NotBefore))
		if err != nil {
			c.JSON(http.StatusBadRequest, NewErrorResponse(c, "not_before must be an RFC3339 timestamp"))
			return
		}
		notBefore := parsed.UTC()
		notBeforePtr = &notBefore
	}

	if newVersion == nil && notBeforePtr == nil {
		c.JSON(http.StatusBadRequest, NewErrorResponse(c, "new_version or not_before is required"))
		return
	}

	actor := strings.TrimSpace(req.Actor)
	if actor == "" {
		if userID, ok := middleware.GetAuthenticatedUserID(c); ok {
			actor = strings.TrimSpace(userID)
		}
	}
	if actor == "" {
		c.JSON(http.StatusBadRequest, NewErrorResponse(c, "actor is required"))
		return
	}

	reason := strings.TrimSpace(req.Reason)

	metadata := map[string]any{
		"source": "http_api",
	}
	if trace, _ := c.Get("trace_id"); trace != nil {
		if id, ok := trace.(string); ok && id != "" {
			metadata["trace_id"] = id
		}
	}

	change, err := h.service.BumpSubjectVersion(c.Request.Context(), subjectID, newVersion, notBeforePtr, actor, reason, metadata)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrSubjectIDRequired), errors.Is(err, usecase.ErrActorRequired):
			c.JSON(http.StatusBadRequest, NewErrorResponse(c, err.Error()))
		case errors.Is(err, repository.ErrNotFound):
			c.JSON(http.StatusNotFound, NewErrorResponse(c, "subject not found"))
		default:
			c.JSON(http.StatusInternalServerError, NewErrorResponse(c, "failed to bump subject version"))
		}
		return
	}

	response := SubjectVersionBumpResponse{
		SubjectID:    change.Current.SubjectID,
		NewVersion:   change.Current.CurrentVersion,
		NotBefore:    change.Current.NotBefore,
		PropagatedAt: time.Now().UTC(),
	}

	c.JSON(http.StatusAccepted, response)
}
