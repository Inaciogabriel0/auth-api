package utils

import (
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var getJwtSecret = func() []byte {
	return []byte(os.Getenv("JWT_SECRET"))
}

func GenerateToken(userID uint, email string) (string, error) {
	// Definir as regras e tempo de expiração do token
	claims := jwt.MapClaims{
		"user_id": userID,
		"email":   email,
		"exp":     time.Now().Add(time.Hour * 24).Unix(), // Expira em 24h
	}

	// Criar o token usando o algoritmo de criptografia HS256
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Assinar o token com o nosso Segredo
	return token.SignedString(getJwtSecret())
}

func ValidateToken(tokenString string) (jwt.MapClaims, error) {
	// Analisar e validar o token que recebemos
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validar se o método de assinatura é o que nós usamos (HMAC)
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("método de assinatura inválido")
		}
		return getJwtSecret(), nil
	})

	if err != nil {
		return nil, err
	}

	// Se for válido, extrair e retornar os dados (claims)
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("token inválido")
}
