// handlers/authHandler.go
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"toolsedenauth/helpers"
	"toolsedenauth/models"
	"toolsedenauth/repository"
	"toolsedenauth/services" // Updated import for services package
	"toolsedenauth/utils"    // Import for common response utils

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// AuthHandler is the interface for authentication handler methods
type AuthHandler interface {
	Signup(c *gin.Context)
	Login(c *gin.Context)
	SendOTP(c *gin.Context)
	VerifyOTP(c *gin.Context)
	ResetPasswordVerify(c *gin.Context)
	ForgotPasswordSend(c *gin.Context)
	ChangePassword(c *gin.Context)
	Logout(c *gin.Context)
}

type authHandler struct {
	userRepo     repository.UserRepository
	redisService services.RedisService
	oauthConfig  *oauth2.Config
}

func NewAuthHandler(userRepo repository.UserRepository, redisService services.RedisService) *authHandler {
	return &authHandler{
		userRepo:     userRepo,
		redisService: redisService,
		oauthConfig: &oauth2.Config{
			ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
			ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
			RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.profile",
				"https://www.googleapis.com/auth/userinfo.email",
			},
			Endpoint: google.Endpoint,
		},
	}
}

// Signup handles user registration
func (h *authHandler) Signup(c *gin.Context) {
	var signupRequest models.SignupRequest
	if err := c.ShouldBindJSON(&signupRequest); err != nil {
		utils.ResponseError(c, http.StatusBadRequest, err.Error())
		return
	}

	// Check if the user already exists
	existingUser, err := h.userRepo.GetUserByEmail(signupRequest.Email)

	if existingUser != nil {
		// User with this email already exists
		utils.ResponseError(c, http.StatusConflict, "User already exists!")
		return
	}

	// Proceed to create the new user
	user := &models.User{
		Email:     signupRequest.Email,
		Password:  signupRequest.Password, // Ensure to hash the password before storing
		FirstName: signupRequest.FirstName,
		LastName:  signupRequest.LastName,
		Avatar:    signupRequest.Avatar,
		Role:      models.UserRole,
	}

	if err := h.userRepo.CreateUser(user); err != nil {
		utils.ResponseError(c, http.StatusInternalServerError, "Failed to create user")
		return
	}

	if !user.IsEmailVerified {
		otp, err := helpers.GenerateOTPCode()
		if err != nil {
			utils.ResponseError(c, http.StatusInternalServerError, fmt.Sprintf("Error generating OTP code: %v", err))
			return
		}

		code, err := helpers.GenerateOTP(otp, user.Email, nil, 600) // 600 seconds TTL
		if err != nil {
			utils.ResponseError(c, http.StatusInternalServerError, fmt.Sprintf("Error generating OTP: %v", err))
			return
		}

		emailService := services.NewEmailService()
		// Send the OTP via email
		if err := emailService.SendOTPEmail(user.Email, code); err != nil {
			utils.ResponseError(c, http.StatusInternalServerError, "Could not send OTP email")
			return
		}

		// Inform the user to check their email for the OTP
		utils.ResponseSuccess(c, "User registration successfully. Please check your email for the OTP.", gin.H{"is_email_verified": user.IsEmailVerified})
		return
	}

	// Generate the authentication token if the email is verified
	token, err := helpers.GenerateUserAuthToken(*user)
	if err != nil {
		utils.ResponseError(c, http.StatusInternalServerError, "Could not generate token")
		return
	}

	utils.ResponseSuccess(c, "User created successfully", gin.H{"token": token,"is_email_verified": user.IsEmailVerified})
}

// Login handles user login
func (h *authHandler) Login(c *gin.Context) {
	var loginRequest models.LoginRequest
	if err := c.ShouldBindJSON(&loginRequest); err != nil {
		utils.ResponseError(c, http.StatusBadRequest, err.Error())
		return
	}

	user, err := h.userRepo.GetUserByEmail(loginRequest.Email)
	if err != nil {
		// Log the error for debugging
		fmt.Printf("Error fetching user by email: %v", err)
		utils.ResponseError(c, http.StatusUnauthorized, "Invalid email or password")
		return
	}

	if user == nil || !models.CheckPasswordHash(loginRequest.Password, user.Password) {
		utils.ResponseError(c, http.StatusUnauthorized, "Invalid email or password")
		return
	}

	if !user.IsEmailVerified {
		otp, err := helpers.GenerateOTPCode()
		if err != nil {
			utils.ResponseError(c, http.StatusInternalServerError, fmt.Sprintf("Error generating OTP code: %v", err))
			return
		}

		code, err := helpers.GenerateOTP(otp, user.Email, nil, 600) // 600 seconds TTL
		if err != nil {
			utils.ResponseError(c, http.StatusInternalServerError, fmt.Sprintf("Error generating OTP: %v", err))
			return
		}
		emailService := services.NewEmailService()
		// Send the OTP via email
		if err := emailService.SendOTPEmail(user.Email, code); err != nil {
			fmt.Printf("Error sending OTP email: %v", err)
			utils.ResponseError(c, http.StatusInternalServerError, "Could not send OTP email")
			return
		}

		utils.ResponseSuccess(c, "Please verify your email with the OTP sent.", gin.H{"is_email_verified": user.IsEmailVerified})
		return
	}

	// Generate the authentication token only if the email is verified
	token, err := helpers.GenerateUserAuthToken(*user)
	if err != nil {
		fmt.Printf("Error generating user auth token: %v", err)
		utils.ResponseError(c, http.StatusInternalServerError, "Could not generate token")
		return
	}

	utils.ResponseSuccess(c, "Login successful", gin.H{"token": token, "is_email_verified": user.IsEmailVerified})
}


// SendOTP handles sending an OTP to the user's email
func (h *authHandler) SendOTP(c *gin.Context) {
	var otpRequest models.OtpRequest
	if err := c.ShouldBindJSON(&otpRequest); err != nil {
		utils.ResponseError(c, http.StatusBadRequest, err.Error())
		return
	}

	user, err := h.userRepo.GetUserByEmail(otpRequest.Email)
	if err != nil || user == nil {
		utils.ResponseError(c, http.StatusNotFound, "User not found")
		return
	}

	otp, err := helpers.GenerateOTPCode()
	if err != nil {
		utils.ResponseError(c, http.StatusInternalServerError, fmt.Sprintf("Error generating OTP code: %v", err))
		return
	}

	code, err := helpers.GenerateOTP(otp, user.Email, nil, 600) // 600 seconds TTL
	if err != nil {
		utils.ResponseError(c, http.StatusInternalServerError, fmt.Sprintf("Error generating OTP: %v", err))
		return
	}

	emailService := services.NewEmailService()
	// Send the OTP via email
	err = emailService.SendOTPEmail(user.Email, code)
	if err != nil {
		utils.ResponseError(c, http.StatusInternalServerError, "Could not send OTP email")
		return
	}

	utils.ResponseSuccess(c, "OTP sent successfully", nil)
}

// VerifyOTP handles OTP verification
func (h *authHandler) VerifyOTP(c *gin.Context) {
	var verifyOtpRequest models.VerifyOtpRequest
	if err := c.ShouldBindJSON(&verifyOtpRequest); err != nil {
		utils.ResponseError(c, http.StatusBadRequest, err.Error())
		return
	}

	data, err := helpers.VerifyOTP(verifyOtpRequest.Code) // Verify OTP using helper function
	if err != nil {
		utils.ResponseError(c, http.StatusUnauthorized, "Invalid OTP")
		return
	}
	fmt.Println(data)

	// Retrieve user by email
	user, err := h.userRepo.GetUserByEmail(data.Email)
	if err != nil || user == nil {
		utils.ResponseError(c, http.StatusNotFound, "User not found")
		return
	}

	// Update user's email verification status
	user.IsEmailVerified = true // Assuming IsEmailVerified is a field in your User model
	if err := h.userRepo.UpdateUser(user); err != nil {
		utils.ResponseError(c, http.StatusInternalServerError, "Could not update user")
		return
	}

	// Generate auth token for the user
	token, err := helpers.GenerateUserAuthToken(*user)
	if err != nil {
		utils.ResponseError(c, http.StatusInternalServerError, "Could not generate token")
		return
	}

	utils.ResponseSuccess(c, "OTP verified successfully", gin.H{"token": token,"is_email_verified": user.IsEmailVerified})
}

// ResetPasswordVerify handles password resetting
func (h *authHandler) ResetPasswordVerify(c *gin.Context) {
	var resetRequest models.ResetPasswordRequest
	if err := c.ShouldBindJSON(&resetRequest); err != nil {
		utils.ResponseError(c, http.StatusBadRequest, "Invalid request: "+err.Error())
		return
	}
	data, err := helpers.VerifyOTP(resetRequest.Code) // Verify OTP using helper function
	if err != nil {
		utils.ResponseError(c, http.StatusUnauthorized, "Invalid OTP")
		return
	}
	fmt.Println(data)

	// Retrieve user by email
	user, err := h.userRepo.GetUserByEmail(data.Email)
	if err != nil || user == nil {
		utils.ResponseError(c, http.StatusNotFound, "User not found")
		return
	}

	if resetRequest.Password != resetRequest.Password2 {
		utils.ResponseError(c, http.StatusBadRequest, "Passwords do not match")
		return
	}

	hashedPassword, err := models.HashPassword(resetRequest.Password)
	if err != nil {
		utils.ResponseError(c, http.StatusInternalServerError, "Could not reset password")
		return
	}
	user.Password = hashedPassword

	// Update user's email verification status
	user.IsEmailVerified = true // Assuming IsEmailVerified is a field in your User model
	if err := h.userRepo.UpdateUser(user); err != nil {
		utils.ResponseError(c, http.StatusInternalServerError, "Could not update user")
		return
	}

	token, err := helpers.GenerateUserAuthToken(*user)
	if err != nil {
		utils.ResponseError(c, http.StatusInternalServerError, "Could not generate token")
		return
	}

	utils.ResponseSuccess(c, "Password reset successfully", gin.H{"token": token,"is_email_verified": user.IsEmailVerified})
}

// ForgotPasswordSend handles sending OTP for password reset
func (h *authHandler) ForgotPasswordSend(c *gin.Context) {
	var forgotRequest models.ForgotPasswordRequest
	if err := c.ShouldBindJSON(&forgotRequest); err != nil {
		utils.ResponseError(c, http.StatusBadRequest, "Invalid request: "+err.Error())
		return
	}

	user, err := h.userRepo.GetUserByEmail(forgotRequest.Email)
	if err != nil || user == nil {
		utils.ResponseError(c, http.StatusNotFound, "User not found")
		return
	}

	otp, err := helpers.GenerateOTPCode()
	if err != nil {
		utils.ResponseError(c, http.StatusInternalServerError, fmt.Sprintf("Error generating OTP code: %v", err))
		return
	}

	code, err := helpers.GenerateOTP(otp, user.Email, nil, 600) // 600 seconds TTL
	if err != nil {
		utils.ResponseError(c, http.StatusInternalServerError, fmt.Sprintf("Error generating OTP: %v", err))
		return
	}

	emailService := services.NewEmailService()
	// Send the OTP via email
	if err := emailService.SendResetPasswordEmail(user.Email, code); err != nil {
		utils.ResponseError(c, http.StatusInternalServerError, "Could not send OTP email")
		return
	}

	utils.ResponseSuccess(c, "OTP sent successfully for password reset", nil)
}

func (h *authHandler) ChangePassword(c *gin.Context) {
	var changeRequest models.ChangePasswordRequest
	if err := c.ShouldBindJSON(&changeRequest); err != nil {
		utils.ResponseError(c, http.StatusBadRequest, "Invalid request: "+err.Error())
		return
	}

	user, exists := c.Get("user") // Get the user info from context
	if !exists {
		utils.ResponseError(c, http.StatusUnauthorized, "Unauthorized access")
		return
	}

	currentUser := user.(*models.User) // Assert to the correct type

	if !models.CheckPasswordHash(changeRequest.OldPassword, currentUser.Password) {
		utils.ResponseError(c, http.StatusUnauthorized, "Invalid email or password")
		return
	}

	if changeRequest.Password != changeRequest.Password2 {
		utils.ResponseError(c, http.StatusBadRequest, "New passwords do not match")
		return
	}

	hashedPassword, err := models.HashPassword(changeRequest.Password)
	if err != nil {
		utils.ResponseError(c, http.StatusInternalServerError, "Could not change password")
		return
	}
	currentUser.Password = hashedPassword
	if err := h.userRepo.UpdateUser(currentUser); err != nil {
		utils.ResponseError(c, http.StatusInternalServerError, "Could not update password")
		return
	}

	token, err := helpers.GenerateUserAuthToken(*currentUser) // or your desired token generator function
	if err != nil {
		utils.ResponseError(c, http.StatusInternalServerError, "Could not generate token")
		return
	}

	utils.ResponseSuccess(c, "Password changed successfully", gin.H{"token": token,"is_email_verified": currentUser.IsEmailVerified})
}
func (h *authHandler) Logout(c *gin.Context) {
	// Check if redisService is nil
	if h.redisService == nil {
		fmt.Println("Redis service not initialized") // Log to server

		// Send an internal server error response to the client
		utils.ResponseError(c, http.StatusInternalServerError, "Logout service is currently unavailable")
		return
	}

	// Get the user info from context (it should be set during authentication)
	user, exists := c.Get("user")
	if !exists {
		utils.ResponseError(c, http.StatusUnauthorized, "Unauthorized access")
		return
	}

	// Assert the user to the correct type
	currentUser, ok := user.(*models.User)
	if !ok {
		utils.ResponseError(c, http.StatusInternalServerError, "Error retrieving user information")
		return
	}

	// Convert the uint ID to string for Redis key
	userID := fmt.Sprintf("%d", currentUser.ID)

	// Attempt to delete the user session from Redis
	err := h.redisService.DelUserAuth(userID)
	if err != nil {
		fmt.Printf("Error deleting user session from Redis for userID %s: %v\n", userID, err) // Log the specific error
		utils.ResponseError(c, http.StatusInternalServerError, "Failed to logout")
		return
	}

	// Log the successful logout
	fmt.Printf("User %s successfully logged out\n", userID)

	// Send a success response
	utils.ResponseSuccess(c, "Successfully logged out", nil)
}
func (h *authHandler) GoogleLogin(c *gin.Context) {
	err := helpers.GenerateGoogleOAuthState()
	if err != nil {
		log.Fatalf("Error generating GOOGLE_OAUTH_STATE: %v", err)
	}
	state := os.Getenv("GOOGLE_OAUTH_STATE") // Use a secure random string in production for CSRF protection
	url := h.oauthConfig.AuthCodeURL(state)
	c.Redirect(http.StatusTemporaryRedirect, url)
}
func (h *authHandler) GoogleCallback(c *gin.Context) {
	code := c.Query("code")
	if code == "" {
		utils.ResponseError(c, http.StatusBadRequest, "Missing authorization code")
		return
	}

	token, err := h.oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		utils.ResponseError(c, http.StatusInternalServerError, "Failed to exchange token: "+err.Error())
		return
	}

	client := h.oauthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v1/userinfo?alt=json")
	if err != nil {
		utils.ResponseError(c, http.StatusInternalServerError, "Failed to get user info: "+err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		utils.ResponseError(c, http.StatusInternalServerError, "Failed to get user info: received status "+resp.Status)
		return
	}

	// Decode Google user info into GoogleUser struct
	var googleUser models.GoogleUser
	if err := json.NewDecoder(resp.Body).Decode(&googleUser); err != nil {
		utils.ResponseError(c, http.StatusInternalServerError, "Failed to decode user info: "+err.Error())
		return
	}

	// Check if user exists in the database
	existingUser, err := h.userRepo.GetUserByEmail(googleUser.Email)
	if err != nil {
		// User not found, create a new user
		newUser := models.User{
			FirstName:       googleUser.FirstName,
			LastName:        googleUser.LastName,
			Avatar:          googleUser.Avatar,
			Email:           googleUser.Email,
			Password:        "", // Password should not be set for Google login
			Role:            "user",
			IsEmailVerified: true,
		}

		// Create a new user in the database
		if err := h.userRepo.CreateUser(&newUser); err != nil {
			utils.ResponseError(c, http.StatusInternalServerError, "Failed to create user: "+err.Error())
			return
		}

		// Generate auth token for the new user
		tokenString, err := helpers.GenerateUserAuthToken(newUser) // Use newUser directly
		if err != nil {
			utils.ResponseError(c, http.StatusInternalServerError, "Could not generate token: "+err.Error())
			return
		}

		utils.ResponseSuccess(c, "User registration successful", gin.H{"token": tokenString,"is_email_verified": newUser.IsEmailVerified})
		return
	}

	// User already exists, update their information
	existingUser.FirstName = googleUser.FirstName
	existingUser.LastName = googleUser.LastName
	existingUser.Avatar = googleUser.Avatar

	if err := h.userRepo.UpdateUser(existingUser); err != nil {
		utils.ResponseError(c, http.StatusInternalServerError, "Failed to update user information: "+err.Error())
		return
	}

	// Generate auth token for the existing user
	tokenString, err := helpers.GenerateUserAuthToken(*existingUser) // Dereference existingUser
	if err != nil {
		utils.ResponseError(c, http.StatusInternalServerError, "Could not generate token: "+err.Error())
		return
	}

	// Send success response after updating the user
	utils.ResponseSuccess(c, "User logged in successfully", gin.H{"token": tokenString,"is_email_verified": existingUser.IsEmailVerified})
}
