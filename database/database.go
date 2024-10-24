package database

import (
	"github.com/go-redis/redis/v8" // Use v8 version of redis
	_ "gorm.io/driver/postgres"    // Postgres driver
	_ "gorm.io/driver/sqlite"      // SQLite driver
	"gorm.io/gorm"
)

var (
	// DB is the database connection
	DB *gorm.DB
	// RedisClient is the redis client
	RedisClient *redis.Client
)
