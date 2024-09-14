package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/xero"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("xero", "Xero", setupXero)
}

func setupXero(key, secret, callback string) (goth.Provider, error) {
	return xero.New(key, secret, callback), nil
}
