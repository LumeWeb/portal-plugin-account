package config

import "go.lumeweb.com/portal/config"

var _ config.APIConfig = (*APIConfig)(nil)

type APIConfig struct {
	Subdomain   string      `config:"subdomain"`
	SocialLogin SocialLogin `config:"social_login"`
	AppFolder   string      `config:"app_folder"`
}

func (A APIConfig) Defaults() map[string]any {
	return map[string]any{
		"subdomain": "account",
	}
}
