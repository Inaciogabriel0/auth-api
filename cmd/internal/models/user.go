package models

import "time"

type User struct {
	ID uint `gorm:"primaryKey"`
	Name string
	Email string `gorm:"unique"`
	Password string	
	Role string `gorm:"default:user"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
}