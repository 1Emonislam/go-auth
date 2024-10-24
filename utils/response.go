// backend/utils/response.go
package utils

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type response struct {
	Message string      `json:"message"`
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
}

func Response(c *gin.Context, status int, message string, success bool, data interface{}) {
	c.JSON(status, response{
		Message: message,
		Success: success,
		Data:    data,
	})
}

func ResponseSuccess(c *gin.Context, message string, data interface{}) {
	Response(c, http.StatusOK, message, true, data)
}

func ResponseError(c *gin.Context, status int, message string) {
	Response(c, status, message, false, nil)
}
