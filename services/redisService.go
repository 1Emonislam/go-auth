// backend/services/redisService.go
package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"toolsedenauth/database"
	"toolsedenauth/models"
)

type RedisService interface {
	SetUserAuth(userId, jwtToken string, user models.User) error
	GetUserAuth(userId string) (*UserAuthInfo, error)
	DelUserAuth(userId string) error // Added method for deleting user auth info
}

type redisService struct {
}

// NewRedisService creates a new instance of redisService
func NewRedisService() *redisService {
	return &redisService{}
}

// UserAuthInfo structure to hold JWT token and user info
type UserAuthInfo struct {
	JwtToken string      `json:"jwtToken"`
	User     models.User `json:"user"`
}

// SetUserAuth sets the user authentication info in Redis
func (r *redisService) SetUserAuth(userId, jwtToken string, user models.User) error {
	jsonData, err := json.Marshal(UserAuthInfo{
		JwtToken: jwtToken,
		User:     user,
	})
	if err != nil {
		log.Fatalf("Error encoding JSON: %s", err)
		return errors.New("error encoding auth info")
	}

	ctx := context.Background() // Create a background context
	return database.RedisClient.Set(ctx, fmt.Sprintf("auth::user::%s", userId), string(jsonData), time.Hour*7*24).Err()
}

// GetUserAuth retrieves the user authentication info from Redis
func (r *redisService) GetUserAuth(userId string) (*UserAuthInfo, error) {
	ctx := context.Background() // Create a background context
	val, err := database.RedisClient.Get(ctx, fmt.Sprintf("auth::user::%s", userId)).Result()
	authInfo := UserAuthInfo{}
	if err == nil {
		err = json.Unmarshal([]byte(val), &authInfo)
		if err != nil {
			return nil, err
		}
		return &authInfo, nil
	}
	return nil, err
}

// DelUserAuth deletes the user authentication info from Redis
func (r *redisService) DelUserAuth(userId string) error {
	ctx := context.Background() // Create a background context
	return database.RedisClient.Del(ctx, fmt.Sprintf("auth::user::%s", userId)).Err()
}
