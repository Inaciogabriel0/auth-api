package repositories

import (
	"auth-api/internal/database"
	"auth-api/internal/models"
	"context"
)

// UserRepository gerencia operações de banco para usuários.
type UserRepository struct{}

func NewUserRepository() *UserRepository {
	return &UserRepository{}
}

func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	if err := database.DB.WithContext(ctx).Where("email = ?", email).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) Create(ctx context.Context, user *models.User) error {
	return database.DB.WithContext(ctx).Create(user).Error
}

func (r *UserRepository) UpdatePassword(ctx context.Context, userID uint, newPasswordHash string) error {
	return database.DB.WithContext(ctx).Model(&models.User{}).Where("id = ?", userID).Update("password", newPasswordHash).Error
}
