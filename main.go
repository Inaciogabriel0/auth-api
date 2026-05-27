package main

import (
	"auth-api/internal/controllers"
	"auth-api/internal/database"
	"auth-api/internal/middleware"
	"auth-api/internal/models"
	"log"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Erro ao carregar o arquivo .env")
	}

	database.Connect()
	database.DB.AutoMigrate(
		&models.User{},
		&models.RefreshToken{},
		&models.PasswordResetToken{},
	)

	r := gin.Default()
	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Api está online!",
		})
	})

	authGroup := r.Group("/auth")
	{
		authGroup.POST("/register", controllers.Register)
		authGroup.POST("/login", controllers.Login)
		authGroup.POST("/refresh", controllers.Refresh)
		authGroup.POST("/logout", controllers.Logout)
		
		// Forgot password com Rate Limit (3 requests / 15 min)
		authGroup.POST("/forgot-password", middleware.RateLimitForgotPassword(), controllers.ForgotPassword)
		authGroup.POST("/reset-password", controllers.ResetPassword)
	}

	// Rotas Protegidas (Exigem JWT)
	protected := r.Group("/")
	protected.Use(middleware.RequireAuth)
	
	protected.GET("/profile", func(c *gin.Context) {
		userID, _ := c.Get("userID")
		userEmail, _ := c.Get("userEmail")
		userRole, _ := c.Get("userRole")

		c.JSON(200, gin.H{
			"message": "Você acessou uma rota protegida com sucesso!",
			"user_id": userID,
			"email":   userEmail,
			"role":    userRole,
		})
	})

	// Exemplos obrigatórios da Etapa 14 (Roles)
	usersGroup := protected.Group("/users")
	{
		// GET /users -> admin, moderator e user
		usersGroup.GET("", middleware.RequireRole("admin", "moderator", "user"), func(c *gin.Context) {
			c.JSON(200, gin.H{"message": "Lista de usuários (acessível por admin, moderator, user)"})
		})

		// PATCH /users/:id/ban -> admin e moderator
		usersGroup.PATCH("/:id/ban", middleware.RequireRole("admin", "moderator"), func(c *gin.Context) {
			c.JSON(200, gin.H{"message": "Usuário banido (acessível por admin, moderator)"})
		})

		// DELETE /users/:id -> apenas admin
		usersGroup.DELETE("/:id", middleware.RequireRole("admin"), func(c *gin.Context) {
			c.JSON(200, gin.H{"message": "Usuário deletado (acessível apenas por admin)"})
		})
	}

	r.Run(":8080")
}