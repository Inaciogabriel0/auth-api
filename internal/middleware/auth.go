package middleware

import (
	"auth-api/internal/utils"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func RequireAuth(c *gin.Context) {
	// 1. Obter o cabeçalho Authorization
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token não fornecido. Envie o cabeçalho Authorization"})
		c.Abort() // Bloqueia a requisição
		return
	}

	// 2. Verificar o formato "Bearer <token>"
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Formato de token inválido. Use 'Bearer <token>'"})
		c.Abort()
		return
	}

	tokenString := parts[1]

	// 3. Validar o token
	claims, err := utils.ValidateToken(tokenString)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token inválido ou expirado"})
		c.Abort()
		return
	}

	// 4. Armazenar os dados do usuário no contexto para a rota poder usar depois
	c.Set("userID", claims["user_id"])
	c.Set("userEmail", claims["email"])

	// 5. Permitir a continuação da requisição
	c.Next()
}
