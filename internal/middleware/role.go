package middleware

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
)

// RequireRole cria um middleware que verifica se o usuário possui uma das roles permitidas.
func RequireRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Recupera o role do contexto, injetado pelo RequireAuth
		userRole, exists := c.Get("userRole")
		if !exists {
			slog.Warn("Acesso negado: role não encontrada no contexto", "path", c.Request.URL.Path)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Acesso não autorizado"})
			c.Abort()
			return
		}

		roleStr, ok := userRole.(string)
		if !ok {
			slog.Error("Erro interno: tipo do role inválido no contexto", "path", c.Request.URL.Path)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro interno do servidor"})
			c.Abort()
			return
		}

		// Verifica se o role do usuário está na lista de permitidos
		allowed := false
		for _, r := range roles {
			if roleStr == r {
				allowed = true
				break
			}
		}

		if !allowed {
			// Registra a tentativa de acesso sem logar o token ou dados sensíveis
			userID, _ := c.Get("userID")
			slog.Warn("Tentativa de acesso não autorizado",
				"user_id", userID,
				"role_tentado", roleStr,
				"rota", c.Request.URL.Path,
				"metodo", c.Request.Method,
			)

			c.JSON(http.StatusForbidden, gin.H{"error": "acesso negado"})
			c.Abort()
			return
		}

		c.Next()
	}
}
