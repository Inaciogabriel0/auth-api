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
	database.DB.AutoMigrate(&models.User{})

	r := gin.Default()
	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Api está online!",
		})
	})

	r.POST("/register", controllers.Register)
	r.POST("/login", controllers.Login)

	// Rotas Protegidas (Exigem JWT)
	protected := r.Group("/")
	protected.Use(middleware.RequireAuth)
	
	protected.GET("/profile", func(c *gin.Context) {
		// Pegamos os dados que o middleware salvou no contexto
		userID, _ := c.Get("userID")
		userEmail, _ := c.Get("userEmail")

		c.JSON(200, gin.H{
			"message": "Você acessou uma rota protegida com sucesso!",
			"user_id": userID,
			"email":   userEmail,
		})
	})

	r.Run(":8080")
}