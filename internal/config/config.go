package config

import (
	"errors"
	"go.lumeweb.com/portal/config"
)

var _ config.APIConfig = (*APIConfig)(nil)
var _ config.Validator = (*Themes)(nil)

type Themes []Theme

type APIConfig struct {
	Subdomain   string      `config:"subdomain"`
	SocialLogin SocialLogin `config:"social_login"`
	AppFolder   string      `config:"app_folder"`
	Themes      Themes      `config:"themes"`
}

func (A APIConfig) Defaults() map[string]any {
	return map[string]any{
		"subdomain": "account",
		"themes":    defaultThemeConfig(),
	}
}

func (t Themes) Validate() error {
	def := false
	for _, theme := range t {
		if theme.Default {
			if def {
				return errors.New("only one theme can be default")
			}
			def = true
		}
	}
	return nil
}
