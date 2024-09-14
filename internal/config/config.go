package config

import "go.lumeweb.com/portal/config"

var _ config.APIConfig = (*APIConfig)(nil)

type APIConfig struct {
	Subdomain string `mapstructure:"subdomain"`
}

func (A APIConfig) Defaults() map[string]any {
	return map[string]any{
		"subdomain": "account",
	}
}
