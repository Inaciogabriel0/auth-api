package models

import "time"

type Role string

const (
	RoleAdmin     Role = "admin"
	RoleModerator Role = "moderator"
	RoleUser      Role = "user"
)

type User struct {
	ID        uint      `gorm:"primaryKey"`
	Name      string
	Email     string    `gorm:"unique"`
	Password  string
	Role      Role      `gorm:"default:user"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
}