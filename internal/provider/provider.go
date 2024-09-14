package provider

import (
	"github.com/markbates/goth"
	pluginConfig "go.lumeweb.com/portal-plugin-dashboard/internal/config"
)

var providerSetup = NewProviderSetup()

func Provider() *ProviderSetup {
	return providerSetup
}

func ProviderName(provider string) string {
	return providerSetup.ProviderName(provider)
}

func ProviderExists(id string) bool {
	return providerSetup.ProviderExists(id)
}

func RegisterProvider(id string, name string, factory ProviderFactory) {
	providerSetup.RegisterProvider(id, name, factory)
}

func ConfigureProvider(name string, config pluginConfig.ProviderConfig) {
	providerSetup.ConfigureProvider(name, config)
}

func SetProviderOrder(order []string) {
	providerSetup.SetProviderOrder(order)
}

func EnabledProviders() []string {
	return providerSetup.EnabledProviders()
}

func CreateProvider(id string) (goth.Provider, error) {
	return providerSetup.CreateProvider(id)
}
