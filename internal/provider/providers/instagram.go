package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/instagram"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("instagram", "Instagram", setupInstagram)
}

func setupInstagram(key, secret, callback string) (goth.Provider, error) {
	return instagram.New(key, secret, callback), nil
}
