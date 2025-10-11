package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

// ErrorCase maps a sentinel error to an HTTP status code and response message.
type ErrorCase struct {
	Err     error
	Status  int
	Message string
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
			c.JSON(cs.Status, NewErrorResponse(c, cs.Message))
			return
		}
	}

	c.JSON(fallbackStatus, NewErrorResponse(c, fallbackMessage))
}
