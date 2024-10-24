// backend/auth/auth.go
package auth

import (
	"fmt"
	"strings"

	"toolsedenauth/config"
	// Ensure you have a service for Redis operations
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

// VerifyToken checks the validity of the token and returns the user ID
func VerifyToken(c *gin.Context) (string, error) {
	tokenString := ExtractToken(c)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("invalid signing method")
		}
		return []byte(config.LoadConfig().JWTSecret), nil
	})
	if err != nil {
		return "", err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return "", fmt.Errorf("invalid token")
	}
	userID, ok := claims["id"].(string) // Get user ID from claims
	if !ok {
		return "", fmt.Errorf("invalid user ID")
	}
	return userID, nil
}

// ExtractToken extracts the token from the authorization header
func ExtractToken(c *gin.Context) string {
	bearerToken := c.GetHeader("Authorization")
	if len(strings.Split(bearerToken, " ")) == 2 {
		return strings.Split(bearerToken, " ")[1]
	}
	return ""
}
