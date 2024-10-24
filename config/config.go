package config

import (
	"context"
	"fmt"
	"log"
	"os"

	"toolsedenauth/database"
	"toolsedenauth/models"

	"github.com/go-redis/redis/v8" // Use the v8 package
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Config structure
type Config struct {
	DBHost                string
	DBPort                string
	DBUser                string
	DBPassword            string
	DBName                string
	JWTSecret             string
	RedisConnectionString string
	CorsUrl               string
}

// connectRedis connects to the Redis database
func connectRedis(connectionString string) {
    database.RedisClient = redis.NewClient(&redis.Options{
        Addr: connectionString, // Should be just "localhost:6379"
    })

    // Create a context
    ctx := context.Background()

    // Ping Redis to check the connection
    _, err := database.RedisClient.Ping(ctx).Result() // Use the context
    if err != nil {
        log.Fatalf("Failed to connect to Redis: %v", err) // Log and exit on error
    }
    log.Println("Connected to Redis database")
}


// Init initializes the application
func Init() {
	var err error

	config := LoadConfig()

	// Use PostgreSQL in production
	dsn := fmt.Sprintf("host=%s port=%s user=%s dbname=%s password=%s sslmode=disable",
		config.DBHost, config.DBPort, config.DBUser, config.DBName, config.DBPassword)
	database.DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})

	if err != nil {
		log.Fatal("Failed to connect to the database:", err)
	}
	log.Println("Connected to the database")

	// Connect to Redis
	connectRedis(config.RedisConnectionString)

	// Migrate the database schema
	if err := database.DB.AutoMigrate(&models.User{}); err != nil {
		log.Fatal("Failed to migrate User model:", err)
	}

	log.Println("Database migration completed")
}

// LoadConfig loads the configuration
func LoadConfig() *Config {
    return &Config{
        DBHost:                getEnv("DB_HOST", "localhost"),
        DBPort:                getEnv("DB_PORT", "5432"),
        DBUser:                getEnv("DB_USER", "postgres"),
        DBPassword:            getEnv("DB_PASSWORD", "password"),
        DBName:                getEnv("DB_NAME", "toolsedenauth"),
        JWTSecret:             getEnv("JWT_SECRET", "your-secret-key"),
        RedisConnectionString: getEnv("REDIS_CONNECTION_STRING", "localhost:6379"), // Ensure no redis:// prefix
        CorsUrl:               getEnv("CORS_URL", "http://localhost:5173"),
    }
}

// getEnv gets an environment variable
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
