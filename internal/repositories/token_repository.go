package repositories

import (
	"auth-api/internal/database"
	"auth-api/internal/models"
	"context"
	"time"
)

type TokenRepository struct{}

func NewTokenRepository() *TokenRepository {
	return &TokenRepository{}
}

// Refresh Token
func (r *TokenRepository) CreateRefreshToken(ctx context.Context, token *models.RefreshToken) error {
	return database.DB.WithContext(ctx).Create(token).Error
}

func (r *TokenRepository) FindRefreshTokenByHash(ctx context.Context, hash string) (*models.RefreshToken, error) {
	var token models.RefreshToken
	if err := database.DB.WithContext(ctx).Where("token_hash = ?", hash).First(&token).Error; err != nil {
		return nil, err
	}
	return &token, nil
}

func (r *TokenRepository) RevokeRefreshToken(ctx context.Context, id string) error {
	now := time.Now()
	return database.DB.WithContext(ctx).Model(&models.RefreshToken{}).Where("id = ?", id).Update("revoked_at", now).Error
}

func (r *TokenRepository) RevokeFamily(ctx context.Context, family string) error {
	now := time.Now()
	return database.DB.WithContext(ctx).Model(&models.RefreshToken{}).Where("family = ? AND revoked_at IS NULL", family).Update("revoked_at", now).Error
}

func (r *TokenRepository) RevokeAllUserRefreshTokens(ctx context.Context, userID uint) error {
	now := time.Now()
	return database.DB.WithContext(ctx).Model(&models.RefreshToken{}).Where("user_id = ? AND revoked_at IS NULL", userID).Update("revoked_at", now).Error
}

// Password Reset Token
func (r *TokenRepository) CreatePasswordResetToken(ctx context.Context, token *models.PasswordResetToken) error {
	return database.DB.WithContext(ctx).Create(token).Error
}

func (r *TokenRepository) FindPasswordResetTokenByHash(ctx context.Context, hash string) (*models.PasswordResetToken, error) {
	var token models.PasswordResetToken
	if err := database.DB.WithContext(ctx).Where("token_hash = ?", hash).First(&token).Error; err != nil {
		return nil, err
	}
	return &token, nil
}
