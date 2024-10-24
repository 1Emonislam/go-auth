package repository

import (
	"errors"
	"fmt"

	"toolsedenauth/database"
	"toolsedenauth/models"

	"gorm.io/gorm"
)

// UserRepository is the interface for the user repository
type UserRepository interface {
	CreateUser(user *models.User) error
	GetUserById(userId string) (*models.User, error)
	GetUserByEmail(email string) (*models.User, error)
	UpdateUser(user *models.User) error
}

// userRepository is the implementation of the UserRepository interface
type userRepository struct{}

// NewUserRepository creates a new user repository
func NewUserRepository() UserRepository {
	return &userRepository{}
}

// CreateUser creates a user
func (r *userRepository) CreateUser(user *models.User) error {
	return database.DB.Create(user).Error
}

// GetUserById retrieves a user by its ID
func (r *userRepository) GetUserById(userId string) (*models.User, error) {
	user := models.User{}
	err := database.DB.Where("id = ?", userId).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user with ID %s not found", userId)
		}
		return nil, fmt.Errorf("error retrieving user: %v", err)
	}
	return &user, nil
}

// GetUserByEmail retrieves a user by its email
func (r *userRepository) GetUserByEmail(email string) (*models.User, error) {
	user := models.User{}
	err := database.DB.Where("email = ?", email).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user with email %s not found", email)
		}
		return nil, fmt.Errorf("error retrieving user: %v", err)
	}
	return &user, nil
}

// UpdateUser updates a user
func (r *userRepository) UpdateUser(user *models.User) error {
	return database.DB.Save(user).Error
}
