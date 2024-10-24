package main

import (
	"fmt"
	"log"
	"toolsedenauth/config"
	"toolsedenauth/database"
	"toolsedenauth/models"
	routing "toolsedenauth/routes"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"gorm.io/gorm"
)

func main() {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Error loading .env file: %s", err)
	}

	config.Init()

	router := gin.New()        // Create a new router instance
	router.Use(gin.Logger())   // Use the built-in logger middleware
	router.Use(gin.Recovery()) // Recover from any panics and write a 500 if there was one

	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"https://gmbrevs.com", "http://localhost:3000"},
		AllowMethods:     []string{"GET", "POST", "HEAD", "PUT", "DELETE", "PATCH", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		AllowCredentials: true,
	}))

	routing.RegisterRoutes(router)

	port := ":8000"
	fmt.Printf("Server is starting on http://localhost%s\n", port)

	// Start the server and log any errors
	if err := router.Run(port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	defer func(DB *gorm.DB) {
		// Database cleanup logic...
	}(database.DB)

	log.Println("Database connection initialized successfully")
	fmt.Println("Application started successfully")
}

func CreateAdminUser(username, password string) error {
	adminUser := models.User{
		Email:    username,
		Password: password,
		Role:     models.AdminRole,
	}

	if err := database.DB.Create(&adminUser).Error; err != nil {
		return err
	}

	return nil
}
