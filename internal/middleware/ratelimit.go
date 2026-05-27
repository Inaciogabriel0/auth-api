package middleware

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"
)

// RateLimit cria um middleware de limitação de taxa por IP.
func RateLimit(rate limiter.Rate) gin.HandlerFunc {
	store := memory.NewStore()
	instance := limiter.New(store, rate)

	return func(c *gin.Context) {
		// Opcional: considerar o IP do cliente (X-Forwarded-For) se estiver atrás de proxy
		ip := c.ClientIP()
		
		context, err := instance.Get(c, ip)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro interno do servidor"})
			c.Abort()
			return
		}

		if context.Reached {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "Limite de requisições excedido. Tente novamente mais tarde."})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RateLimitForgotPassword retorna o middleware configurado para 3 requests / 15 min.
func RateLimitForgotPassword() gin.HandlerFunc {
	rate := limiter.Rate{
		Period: 15 * time.Minute,
		Limit:  3,
	}
	return RateLimit(rate)
}
