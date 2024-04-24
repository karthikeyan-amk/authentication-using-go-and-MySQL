package main

import (
	"database/sql"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	// Initialize Gin router
	r := gin.Default()

	// cors
	config := cors.DefaultConfig()
	config.AllowAllOrigins = true                 // Allow all origins
	config.AllowMethods = []string{"GET", "POST"} // Specify what methods are allowed
	config.AllowHeaders = []string{"Origin", "Content-Length", "Content-Type"}

	r.Use(cors.New(config))

	// Database connection
	db, err := sql.Open("mysql", "root:rootroot@tcp(127.0.0.1:3001)/my_database")
	if err != nil {
		panic(err.Error())
	}
	defer db.Close()

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

	// Run the server
	r.Run(":3000")
}
