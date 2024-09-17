package service

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/samber/lo"
	"go.lumeweb.com/portal-plugin-dashboard/internal/api/messages"
	pluginDb "go.lumeweb.com/portal-plugin-dashboard/internal/db"
	"go.lumeweb.com/portal/core"
	"go.lumeweb.com/portal/db"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

var allowedApiKeySortFields = []string{"id", "name", "created_at", "updated_at"}

const API_KEY_SERVICE = "api_key"

type Pagination struct {
	Page     int
	PageSize int
}

type Sorter struct {
	Field string
	Order string
}

type APIKeyService interface {
	core.Service
	CreateAPIKey(userID uint, name string) (*messages.CreateAPIKeyResponse, error)
	GetAPIKeys(userID uint, pagination *Pagination, filters map[string]interface{}, sorters []Sorter) (*messages.ListAPIKeyResponse, error)
	DeleteAPIKey(userID uint, uuid uuid.UUID) error
	ValidateAPIKey(key string) (*pluginDb.APIKey, error)
}

var _ APIKeyService = (*APIKeyServiceDefault)(nil)

type APIKeyServiceDefault struct {
	ctx    core.Context
	db     *gorm.DB
	logger *core.Logger
	user   core.UserService
	auth   core.AuthService
}

func NewAPIKeyService() (core.Service, []core.ContextBuilderOption, error) {
	service := &APIKeyServiceDefault{}

	return service, core.ContextOptions(
		core.ContextWithStartupFunc(func(ctx core.Context) error {
			service.ctx = ctx
			service.db = ctx.DB()
			service.logger = ctx.ServiceLogger(service)
			service.user = core.GetService[core.UserService](ctx, core.USER_SERVICE)
			service.auth = core.GetService[core.AuthService](ctx, core.AUTH_SERVICE)

			return service.db.AutoMigrate(&pluginDb.APIKey{})
		}),
	), nil
}

func (s *APIKeyServiceDefault) ID() string {
	return API_KEY_SERVICE
}

func (s *APIKeyServiceDefault) CreateAPIKey(userID uint, name string) (*messages.CreateAPIKeyResponse, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate API key: %w", err)
	}

	keyString := base64.URLEncoding.EncodeToString(key)

	apiKey := &pluginDb.APIKey{
		UUID:   datatypes.NewBinUUIDv4(),
		Name:   name,
		UserID: userID,
		Key:    keyString,
	}

	err = db.RetryableTransaction(s.ctx, s.db, func(tx *gorm.DB) *gorm.DB {
		return tx.Create(apiKey)
	})

	if err != nil {
		s.logger.Error("failed to create API key", zap.Error(err))
		return nil, fmt.Errorf("failed to create API key: %w", err)
	}

	return &messages.CreateAPIKeyResponse{Key: keyString}, nil
}

func (s *APIKeyServiceDefault) GetAPIKeys(userID uint, pagination *Pagination, filters map[string]interface{}, sorters []Sorter) (*messages.ListAPIKeyResponse, error) {
	var apiKeys []pluginDb.APIKey
	var total int64

	query := s.db.Model(&pluginDb.APIKey{}).Where("user_id = ?", userID)

	// Apply scopes
	query = query.Scopes(
		paginationScope(pagination),
		filterScope(filters),
		sortScope(sorters),
	)

	// Count total before pagination
	if err := query.Count(&total).Error; err != nil {
		s.logger.Error("failed to count API keys", zap.Error(err))
		return nil, fmt.Errorf("failed to count API keys: %w", err)
	}

	// Execute the query
	if err := query.Find(&apiKeys).Error; err != nil {
		s.logger.Error("failed to fetch API keys", zap.Error(err))
		return nil, fmt.Errorf("failed to fetch API keys: %w", err)
	}

	return &messages.ListAPIKeyResponse{
		Data: lo.Map(apiKeys, func(key pluginDb.APIKey, _ int) messages.APIKey {
			return messages.APIKey{
				UUID:      uuid.UUID(key.UUID),
				Name:      key.Name,
				CreatedAt: key.CreatedAt,
			}
		}),
		Total: total,
	}, nil
}

func (s *APIKeyServiceDefault) DeleteAPIKey(userID uint, keyID uuid.UUID) error {
	item := &pluginDb.APIKey{
		UserID: userID,
		UUID:   datatypes.BinUUID(keyID),
	}

	err := db.RetryableTransaction(s.ctx, s.db, func(tx *gorm.DB) *gorm.DB {
		result := tx.Where(item).Delete(item)
		if result.Error != nil {
			return tx
		}
		if result.RowsAffected == 0 {
			_ = tx.AddError(errors.New("API key not found or not owned by the user"))
			return tx
		}
		return tx
	})

	if err != nil {
		s.logger.Error("failed to delete API key", zap.Error(err))
		return fmt.Errorf("failed to delete API key: %w", err)
	}

	return nil
}

func (s *APIKeyServiceDefault) ValidateAPIKey(key string) (*pluginDb.APIKey, error) {
	var apiKey pluginDb.APIKey

	apiKey.Key = key

	err := db.RetryableTransaction(s.ctx, s.db, func(tx *gorm.DB) *gorm.DB {
		return tx.Where(&apiKey).First(&apiKey)
	})

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("invalid API key")
		}
		s.logger.Error("failed to validate API key", zap.Error(err))
		return nil, fmt.Errorf("failed to validate API key: %w", err)
	}

	return &apiKey, nil
}

// GORM Scopes

func paginationScope(p *Pagination) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		if p != nil {
			offset := (p.Page - 1) * p.PageSize
			return db.Offset(offset).Limit(p.PageSize)
		}
		return db
	}
}

func filterScope(filters map[string]interface{}) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		for key, value := range filters {
			db = db.Where(fmt.Sprintf("%s LIKE ?", key), fmt.Sprintf("%%%v%%", value))
		}
		return db
	}
}

func sortScope(sorters []Sorter) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		for _, sorter := range sorters {
			if lo.Contains(allowedApiKeySortFields, sorter.Field) {
				db = db.Order(fmt.Sprintf("%s %s", sorter.Field, sorter.Order))
			}
		}
		return db
	}
}
