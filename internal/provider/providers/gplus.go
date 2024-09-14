package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/gplus"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("gplus", "Google Plus", setupGplus)
}

func setupGplus(key, secret, callback string) (goth.Provider, error) {
	return gplus.New(key, secret, callback), nil
}
