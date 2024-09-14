package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/intercom"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("intercom", "Intercom", setupIntercom)
}

func setupIntercom(key, secret, callback string) (goth.Provider, error) {
	return intercom.New(key, secret, callback), nil
}
