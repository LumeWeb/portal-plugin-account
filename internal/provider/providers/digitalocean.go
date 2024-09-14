package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/digitalocean"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("digitalocean", "Digital Ocean", setupDigitalocean)
}

func setupDigitalocean(key, secret, callback string) (goth.Provider, error) {
	return digitalocean.New(key, secret, callback), nil
}
