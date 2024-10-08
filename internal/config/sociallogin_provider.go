package config

type ProviderConfig struct {
	Enabled bool   `config:"enabled"`
	Key     string `config:"key"`
	Secret  string `config:"secret"`
}
