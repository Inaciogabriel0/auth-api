 package services

import (
	"auth-api/internal/database"
	"auth-api/internal/models"
	"auth-api/internal/repositories"
	"auth-api/internal/utils"
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	userRepo  *repositories.UserRepository
	tokenRepo *repositories.TokenRepository
	mailSvc   *MailService
}

func NewAuthService() *AuthService {
	return &AuthService{
		userRepo:  repositories.NewUserRepository(),
		tokenRepo: repositories.NewTokenRepository(),
		mailSvc:   NewMailService(),
	}
}

// GenerateAuthTokens gera o AccessToken e o RefreshToken
func (s *AuthService) GenerateAuthTokens(ctx context.Context, user *models.User, family string) (string, string, error) {
	// Access Token
	accessToken, err := utils.GenerateToken(user.ID, user.Email, string(user.Role))
	if err != nil {
		return "", "", err
	}

	// Refresh Token
	refreshTokenRaw, err := utils.GenerateRandomBytes(32)
	if err != nil {
		return "", "", err
	}
	
	if family == "" {
		family = uuid.NewString()
	}

	rt := &models.RefreshToken{
		UserID:    user.ID,
		TokenHash: utils.HashSHA256(refreshTokenRaw),
		ExpiresAt: time.Now().Add(time.Hour * 24 * 7), // 7 dias
		Family:    family,
	}

	if err := s.tokenRepo.CreateRefreshToken(ctx, rt); err != nil {
		return "", "", err
	}

	return accessToken, refreshTokenRaw, nil
}

func (s *AuthService) RefreshToken(ctx context.Context, rawRefreshToken string) (string, string, error) {
	hash := utils.HashSHA256(rawRefreshToken)
	rt, err := s.tokenRepo.FindRefreshTokenByHash(ctx, hash)
	if err != nil {
		return "", "", errors.New("refresh token inválido")
	}

	// Detecção de reuso
	if rt.RevokedAt != nil {
		// Token já foi revogado. Houve um reuso!
		// Revogar toda a família e forçar login
		_ = s.tokenRepo.RevokeFamily(ctx, rt.Family)
		return "", "", errors.New("token comprometido, login necessário")
	}

	// Verifica expiração
	if time.Now().After(rt.ExpiresAt) {
		return "", "", errors.New("refresh token expirado")
	}

	// Revoga o token atual
	if err := s.tokenRepo.RevokeRefreshToken(ctx, rt.ID.String()); err != nil {
		return "", "", err
	}

	// Busca o usuário
	var user models.User
	if err := database.DB.WithContext(ctx).First(&user, rt.UserID).Error; err != nil {
		return "", "", errors.New("usuário não encontrado")
	}

	// Gera novos tokens (rotacionando) na mesma família
	return s.GenerateAuthTokens(ctx, &user, rt.Family)
}

func (s *AuthService) Logout(ctx context.Context, rawRefreshToken string) error {
	hash := utils.HashSHA256(rawRefreshToken)
	rt, err := s.tokenRepo.FindRefreshTokenByHash(ctx, hash)
	if err != nil {
		return nil // Se não achar, já tratamos como deslogado
	}
	return s.tokenRepo.RevokeRefreshToken(ctx, rt.ID.String())
}

func (s *AuthService) ForgotPassword(ctx context.Context, email string) error {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		// Anti-enumeração: não retornamos erro se o e-mail não existir
		return nil
	}

	tokenRaw, err := utils.GenerateRandomBytes(32)
	if err != nil {
		return err
	}

	resetToken := &models.PasswordResetToken{
		UserID:    user.ID,
		TokenHash: utils.HashSHA256(tokenRaw),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	if err := s.tokenRepo.CreatePasswordResetToken(ctx, resetToken); err != nil {
		return err
	}

	// Enviar e-mail de forma assíncrona
	go s.mailSvc.SendPasswordResetEmail(user.Email, tokenRaw)

	return nil
}

func (s *AuthService) ResetPassword(ctx context.Context, tokenRaw, newPassword string) error {
	hash := utils.HashSHA256(tokenRaw)
	token, err := s.tokenRepo.FindPasswordResetTokenByHash(ctx, hash)
	if err != nil || token.UsedAt != nil || time.Now().After(token.ExpiresAt) {
		return errors.New("token inválido ou expirado")
	}

	// Criptografar nova senha
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), 12)
	if err != nil {
		return errors.New("erro ao criptografar senha")
	}

	// Usar uma transaction GORM para garantir a atomicidade
	tx := database.DB.WithContext(ctx).Begin()
	if tx.Error != nil {
		return tx.Error
	}

	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// 1. Atualizar a senha
	if err := tx.Model(&models.User{}).Where("id = ?", token.UserID).Update("password", string(hashedPassword)).Error; err != nil {
		tx.Rollback()
		return err
	}

	// 2. Marcar token como usado
	now := time.Now()
	if err := tx.Model(&models.PasswordResetToken{}).Where("id = ?", token.ID).Update("used_at", now).Error; err != nil {
		tx.Rollback()
		return err
	}

	// 3. Revogar todos os refresh tokens
	if err := tx.Model(&models.RefreshToken{}).Where("user_id = ? AND revoked_at IS NULL", token.UserID).Update("revoked_at", now).Error; err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}
