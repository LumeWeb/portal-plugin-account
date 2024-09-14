package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/onedrive"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("onedrive", "Onedrive", setupOnedrive)
}

func setupOnedrive(key, secret, callback string) (goth.Provider, error) {
	return onedrive.New(key, secret, callback), nil
}
