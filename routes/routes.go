package routing

import (
	"toolsedenauth/handlers"
	"toolsedenauth/middleware"
	"toolsedenauth/repository" // Import the repository package
	"toolsedenauth/services"

	"github.com/gin-gonic/gin"
)

func RegisterRoutes(router *gin.Engine) {
	// Create a new instance of UserRepository
	// Assuming you already have an instance of UserRepository
	userRepo := repository.NewUserRepository()

	// Create a new instance of RedisService
	redisService := services.NewRedisService()

	// Create a new instance of authHandler by passing both UserRepository and RedisService
	authHandler := handlers.NewAuthHandler(userRepo, redisService)

	// Public routes
	public := router.Group("/api/v1.0")
	{
		public.POST("/users/auth/login", authHandler.Login)
		public.POST("/users/auth/register", authHandler.Signup)
		public.GET("/users/auth/google/login", authHandler.GoogleLogin) // Start Google login process
		public.GET("/users/auth/google/callback", authHandler.GoogleCallback)
		public.POST("/users/otp-verify", authHandler.VerifyOTP)
		public.POST("/users/email-verify", authHandler.VerifyOTP)
		public.POST("/users/resend-otp-request/send", authHandler.SendOTP)
		public.POST("/users/forgot-password/send", authHandler.ForgotPasswordSend)
		public.POST("/users/reset-password/verify", authHandler.ResetPasswordVerify)
		public.POST("/users/change-password", authHandler.ChangePassword)
		public.POST("/users/auth/logout", middleware.AuthMiddleware(), authHandler.Logout)
	}

	// Routes accessible by authenticated admin users
	private := router.Group("/api/v1.0")
	private.Use(middleware.AuthMiddleware()) // Get auth user profile data
	{
		// User routes
		private.GET("/user/profile", middleware.ValidateUser(), handlers.GetUsersHandler)
	}
}
