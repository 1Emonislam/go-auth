package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"toolsedenauth/config"
	"toolsedenauth/services"
	"toolsedenauth/utils"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// AuthMiddleware is the middleware for authenticating requests
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		config := config.LoadConfig()

		if authHeader == "" {
			utils.ResponseError(c, http.StatusUnauthorized, "Missing Authorization header")
			c.Abort()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			utils.ResponseError(c, http.StatusUnauthorized, "Invalid Authorization header format")
			c.Abort()
			return
		}
		tokenString := parts[1]

		// Parse the token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(config.JWTSecret), nil
		})

		if err != nil || !token.Valid {
			utils.ResponseError(c, http.StatusUnauthorized, "Invalid token")
			c.Abort()
			return
		}

		clientId := ""
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			clientId = fmt.Sprint(claims["id"])
		}

		if clientId == "" {
			utils.ResponseError(c, http.StatusUnauthorized, "Invalid Payload")
			c.Abort()
			return
		}

		// Fetch user info from Redis
		redisService := services.NewRedisService()
		authInfo, err := redisService.GetUserAuth(clientId)
		if err != nil {
			utils.ResponseError(c, http.StatusUnauthorized, "Please re-login")
			c.Abort()
			return
		}

		if authInfo.JwtToken != tokenString {
			utils.ResponseError(c, http.StatusUnauthorized, "Please re-login!")
			c.Abort()
			return
		}

		// Set user info in the context (make sure authInfo.User is of correct type)
		c.Set("user", &authInfo.User)

		// Proceed to the next middleware
		c.Next()
	}
}
