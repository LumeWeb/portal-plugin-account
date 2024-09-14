package config

import "go.lumeweb.com/portal/config"

var _ config.APIConfig = (*SocialLogin)(nil)

type SocialLogin struct {
	Enabled  bool                      `mapstructure:"enabled"`
	Provider map[string]ProviderConfig `mapstructure:"provider"`
	Order    []string                  `mapstructure:"order"`
}

func (A SocialLogin) Defaults() map[string]any {
	return map[string]any{
		"enabled": false,
	}
}
