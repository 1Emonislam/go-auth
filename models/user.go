package models

import (
	"crypto/rand"
	"encoding/base64"
	"log"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// Constants for roles, salt length, and max password length
const (
	AdminRole         = "admin"
	UserRole          = "user"
	SaltLength        = 16
	MaxPasswordLength = 72
)

// Model struct to hold common fields
type Model struct {
	ID        uint           `json:"id" gorm:"primaryKey"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"deleted_at" gorm:"index"`
}
type GoogleUser struct {
	ID              string `json:"id"`
	FirstName       string `json:"given_name"`
	LastName        string `json:"family_name"`
	Avatar          string `json:"picture"`
	Email           string `json:"email"`
	IsEmailVerified bool   `json:"is_email_verified"`
}

// User represents a user in the system.
type User struct {
	Model
	FirstName       string `json:"firstName" gorm:"default:null"`
	LastName        string `json:"lastName" gorm:"default:null"`
	Avatar          string `json:"avatar" gorm:"default:https://upload.wikimedia.org/wikipedia/commons/2/2c/Default_pfp.svg"`
	Email           string `json:"email" gorm:"unique;not null" validate:"required,email"`
	Password        string `json:"password" gorm:"not null" validate:"required,min=8"`
	Role            string `json:"role" gorm:"not null" validate:"required"`
	IsEmailVerified bool   `json:"is_email_verified" gorm:"default:false"`
}

// BeforeCreate is a hook that is called before creating a user
func (u *User) BeforeCreate(tx *gorm.DB) error {
	hashedPassword, err := HashPassword(u.Password)
	if err != nil {
		return err
	}
	u.Password = hashedPassword
	return nil
}

// HashPassword hashes a password
func HashPassword(password string) (string, error) {
	salt, err := GenerateSalt(SaltLength)
	if err != nil {
		return "", err
	}

	passwordWithSalt := password + salt
	hash, err := bcrypt.GenerateFromPassword([]byte(passwordWithSalt), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(hash) + ":" + salt, nil
}

// CheckPasswordHash checks if the provided password matches the hashed password
func CheckPasswordHash(password, hash string) bool {
	parts := strings.Split(hash, ":")
	if len(parts) != 2 {
		return false
	}
	hashBytes, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}

	passwordWithSalt := password + parts[1]
	err = bcrypt.CompareHashAndPassword(hashBytes, []byte(passwordWithSalt))
	return err == nil
}

// GenerateSalt generates a random salt of the given length
func GenerateSalt(length int) (string, error) {
	salt := make([]byte, length)
	if _, err := rand.Read(salt); err != nil {
		log.Printf("Failed to generate salt: %v", err)
		return "", err
	}
	return base64.StdEncoding.EncodeToString(salt), nil
}

// SignupRequest represents the structure for user registration
type SignupRequest struct {
	Email     string `json:"email" binding:"required,email"`
	Password  string `json:"password" binding:"required,min=8"`
	FirstName string `json:"first_name,omitempty"` // optional field
	LastName  string `json:"last_name,omitempty"`  // optional field
	Avatar    string `json:"avatar,omitempty"`     // optional field
}

// LoginRequest represents the structure for user login
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

// OtpRequest represents the structure for sending an OTP
type OtpRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// VerifyOtpRequest represents the structure for verifying an OTP
type VerifyOtpRequest struct {
	Code string `json:"code" binding:"required"`
}

// ResetPasswordRequest represents the structure for resetting a password
type ResetPasswordRequest struct {
	Code      string `json:"code" binding:"required"`
	Password  string `json:"password" binding:"required,min=8"`
	Password2 string `json:"password2" binding:"required,min=8"`
}

// ChangePasswordRequest represents the structure for changing a password
type ChangePasswordRequest struct {
	OldPassword string `json:"oldPassword" binding:"required,min=8"`
	Password    string `json:"password" binding:"required,min=8"`
	Password2   string `json:"password2" binding:"required,min=8"`
}
type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}
