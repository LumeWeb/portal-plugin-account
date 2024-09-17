package db

import (
	"go.lumeweb.com/portal/db/models"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type APIKey struct {
	gorm.Model
	Name   string
	UUID   datatypes.BinUUID `gorm:"index;colum:uuid"`
	UserID uint
	User   models.User
	Key    string
}
