package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/arklim/social-platform-iam/internal/transport/http/middleware"
)

// ErrorCase maps a sentinel error to an HTTP status code and response message.
type ErrorCase struct {
	Err           error
	Status        int
	Message       string
	ProblemType   string
	ProblemTitle  string
	ProblemDetail string
	Extensions    map[string]any
}

// RespondWithMappedError resolves the provided error against known cases or falls back to a generic response.
func RespondWithMappedError(c *gin.Context, err error, cases []ErrorCase, fallbackStatus int, fallbackMessage string) {
	if err == nil {
		c.Status(http.StatusOK)
		return
	}

	for _, cs := range cases {
		if cs.Err == nil {
			continue
		}
		if errors.Is(err, cs.Err) {
			status := cs.Status
			if status <= 0 {
				status = fallbackStatus
			}
			if cs.ProblemType != "" {
				detail := cs.ProblemDetail
				if detail == "" {
					detail = cs.Message
				}
				title := cs.ProblemTitle
				if title == "" {
					title = http.StatusText(status)
				}
				instance := c.FullPath()
				if instance == "" {
					instance = c.Request.URL.Path
				}
				problem := middleware.ProblemDetails{
					Type:     cs.ProblemType,
					Title:    title,
					Status:   status,
					Detail:   detail,
					Instance: instance,
					TraceID:  middleware.GetTraceID(c),
				}
				if len(cs.Extensions) > 0 {
					problem.Extensions = cs.Extensions
				}
				c.JSON(status, problem)
				return
			}
			c.JSON(status, NewErrorResponse(c, cs.Message))
			return
		}
	}

	c.JSON(fallbackStatus, NewErrorResponse(c, fallbackMessage))
}
