// backend/handlers/userHandler.go
package handlers

import (
	"net/http"

	"toolsedenauth/database"
	"toolsedenauth/models"

	"github.com/gin-gonic/gin"
)

func CreateUserHandler(c *gin.Context) {
	body, _ := c.Get("body")
	user, _ := body.(models.User)

	// Add user role
	user.Role = models.UserRole

	if err := database.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(http.StatusCreated, user)
}

func GetUsersHandler(c *gin.Context) {
	var users []models.User
	if err := database.DB.Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve users"})
		return
	}
	c.JSON(http.StatusOK, users)
}
