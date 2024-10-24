package helpers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
	"toolsedenauth/config"
	"toolsedenauth/database" // Import your database package
	"toolsedenauth/models"
	"toolsedenauth/services"

	"github.com/dgrijalva/jwt-go"
)

// GenerateUserAuthToken generates a user authentication token
func GenerateUserAuthToken(user models.User) (string, error) {
	// Create a new token
	token := jwt.New(jwt.SigningMethodHS256)
	config := config.LoadConfig()

	// Set claims
	claims := token.Claims.(jwt.MapClaims)
	claims["id"] = user.ID
	claims["email"] = user.Email
	claims["role"] = user.Role
	claims["firstName"] = user.FirstName
	claims["lastName"] = user.LastName
	claims["avatar"] = user.Avatar
	claims["is_email_verified"] = user.IsEmailVerified

	// Generate encoded token and send it as response
	t, err := token.SignedString([]byte(config.JWTSecret))
	if err != nil {
		return "", err
	}
	redisService := services.NewRedisService()
	err = redisService.SetUserAuth(fmt.Sprint(user.ID), t, user)
	if err != nil {
		return "", err
	}
	return t, nil
}

// OTPData represents the structure of the OTP data
type OTPData struct {
	Code  string      `json:"code"`
	Email string      `json:"email"` // Email associated with the OTP
	Data  interface{} `json:"data"`  // Additional data
}

// GenerateOTP generates an OTP and stores it in Redis
func GenerateOTP(otp string, email string, data interface{}, otpTTL int) (string, error) {
	ctx := context.Background()
	otpKey := "otp:" + otp

	// Check if OTP already generated within the last 10 minutes
	existingOTP, err := database.RedisClient.Get(ctx, otpKey).Result()
	if err == nil && existingOTP != "" {
		return "", errors.New("OTP already generated for this customer within the last 5 minutes")
	}

	otpData := OTPData{
		Code:  otp,
		Email: email,
		Data:  data,
	}

	// Set the OTP in Redis with an expiration time
	if err := database.RedisClient.SetEX(ctx, otpKey, toJSON(otpData), time.Duration(otpTTL)*time.Second).Err(); err != nil {
		return "", err
	}

	fmt.Println("OTP code is", otpData)
	return otp, nil
}

// VerifyOTP verifies an OTP from Redis
func VerifyOTP(code string) (OTPData, error) {
	ctx := context.Background()
	otpKey := "otp:" + code

	// Retrieve the stored OTP from Redis
	storedOTP, err := database.RedisClient.Get(ctx, otpKey).Result()
	if err != nil {
		return OTPData{}, errors.New("invalid OTP")
	}

	var otpData OTPData
	if err := json.Unmarshal([]byte(storedOTP), &otpData); err != nil {
		return OTPData{}, err
	}

	// Check if the entered OTP matches the stored OTP
	if otpData.Code == code {
		// OTP is valid; delete it from Redis
		if err := database.RedisClient.Del(ctx, otpKey).Err(); err != nil {
			return OTPData{}, err
		}
		fmt.Printf("OTP is valid for user %s\n", otpData.Email)
		return otpData, nil
	}

	// OTP is invalid
	fmt.Printf("Invalid OTP for user %s\n", otpData.Email)
	return OTPData{}, errors.New("invalid OTP")
}

// GenerateOTPCode generates a random 6-digit OTP code
func GenerateOTPCode() (string, error) {
	const otpLength = 6
	code := make([]byte, otpLength)

	// Generate random bytes
	if _, err := rand.Read(code); err != nil {
		return "", err
	}

	// Convert the random bytes to a string of digits
	for i := 0; i < otpLength; i++ {
		code[i] = '0' + (code[i] % 10) // Map bytes to digits (0-9)
	}

	return string(code), nil
}

// GenerateUniqueCode generates a unique code and stores it in Redis
func GenerateUniqueCode(email string, data interface{}) (string, error) {
	otp, err := GenerateOTPCode() // Get the OTP code
	if err != nil {
		return "", fmt.Errorf("failed to generate OTP code: %w", err) // Error handling
	}

	code, err := GenerateOTP(otp, email, data, 600) // 600 seconds TTL
	if err != nil {
		return "", fmt.Errorf("failed to generate OTP: %w", err) // Error handling
	}
	return code, nil
}

// IsExpired checks if an expiry date has passed
func IsExpired(expiryDate time.Time) bool {
	return time.Now().After(expiryDate)
}

// toJSON converts an interface to JSON string
func toJSON(data interface{}) string {
	jsonData, _ := json.Marshal(data)
	return string(jsonData)
}

func generateRandomString(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("length must be greater than 0")
	}
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	// Use base64.RawURLEncoding to avoid padding and ensure the result is URL safe
	return base64.RawURLEncoding.EncodeToString(b)[:length], nil
}

// GenerateGoogleOAuthState generates a random state for Google OAuth and stores it in an environment variable.
func GenerateGoogleOAuthState() error {
	state, err := generateRandomString(16)
	if err != nil {
		return fmt.Errorf("failed to generate GOOGLE_OAUTH_STATE: %w", err)
	}
	return os.Setenv("GOOGLE_OAUTH_STATE", state)
}
