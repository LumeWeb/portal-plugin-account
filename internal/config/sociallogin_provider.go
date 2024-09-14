package config

type ProviderConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Key     string `mapstructure:"key"`
	Secret  string `mapstructure:"secret"`
}
