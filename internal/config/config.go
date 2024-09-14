package config

import "go.lumeweb.com/portal/config"

var _ config.APIConfig = (*APIConfig)(nil)

type APIConfig struct {
	Subdomain   string      `mapstructure:"subdomain"`
	SocialLogin SocialLogin `mapstructure:"social_login"`
}

func (A APIConfig) Defaults() map[string]any {
	return map[string]any{
		"subdomain": "account",
	}
}
