package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/patreon"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("patreon", "Patreon", setupPatreon)
}

func setupPatreon(key, secret, callback string) (goth.Provider, error) {
	return patreon.New(key, secret, callback), nil
}
