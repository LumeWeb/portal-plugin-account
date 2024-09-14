package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/vk"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("vk", "VK", setupVk)
}

func setupVk(key, secret, callback string) (goth.Provider, error) {
	return vk.New(key, secret, callback), nil
}
