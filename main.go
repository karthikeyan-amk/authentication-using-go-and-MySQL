package main

import (
	"database/sql"
	"log"
	"net/http"
	"context"
	"fmt"
	"time"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
	"github.com/go-redis/redis/v8"
	"github.com/gin-contrib/sessions"
	
)

var (
	db          *sql.DB
	RedisClient *redis.Client
)


 
func main() {
	r := gin.Default()

	// cors
	config := cors.DefaultConfig()
	config.AllowAllOrigins = true                 // Allow all origins
	config.AllowMethods = []string{"GET", "POST"} // Specify what methods are allowed
	config.AllowHeaders = []string{"Origin", "Content-Length", "Content-Type"}

	r.Use(cors.New(config))

	// Database connection
	db, err := sql.Open("mysql", "root:root@tcp(127.0.0.1:3001)/my_database")
	if err != nil {
		panic(err.Error())
	}
	log.Println("Connected to DB")
	defer db.Close()

	//Redis connection
	RedisClient = redis.NewClient(&redis.Options{
        Addr:     "localhost:6379",
        Password: "", // No password
        DB:       0,  // Default DB
    })

    ctx := context.Background()
    pong, err := RedisClient.Ping(ctx).Result()
    if err != nil {
        log.Fatal("Error connecting to Redis:", err)
    }
    log.Println("Connected to Redis:", pong)

	// Register endpoint
	r.POST("/register", func(c *gin.Context) {
		var user User
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		// Check if email is already registered
		var email string
		err := db.QueryRow("SELECT email FROM users WHERE email = ?", user.Email).Scan(&email)
		if err == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Email is already registered"})
			return
		}
		// Hash the password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}

		// Insert user into database
		_, err = db.Exec("INSERT INTO users (email, password) VALUES (?, ?)", user.Email, string(hashedPassword))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to insert user into database"})
			return
		}

		c.JSON(http.StatusCreated, gin.H{"message": "User registered successfully"})
		c.Redirect(http.StatusFound, "/login.html")
	})

	r.POST("/login",func(c* gin.Context){
		var user User
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		var storedPassword string
		err := db.QueryRow("SELECT password FROM users WHERE email = ?", user.Email).Scan(&storedPassword)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(user.Password)); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
			return
		}

		sessionID := fmt.Sprintf("session:%d", time.Now().UnixNano())

	// Set session data in Redis
		err = RedisClient.Set(c, sessionID, user.Email, time.Hour*24).Err()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
			return
		}

	session := sessions.Default(c)
	session.Set("session_id", sessionID)
	session.Save()

		http.SetCookie(c.Writer, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Expires:  time.Now().Add(time.Hour * 24), // Expires in 24 hours
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})


		c.JSON(http.StatusOK, gin.H{"message": "Login successful","session_id": sessionID})
		c.Redirect(http.StatusFound, "/home.html")
	})
	// Run the server
	r.Run(":3002")
}
