package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/wepay"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("wepay", "Wepay", setupWepay)
}

func setupWepay(key, secret, callback string) (goth.Provider, error) {
	return wepay.New(key, secret, callback), nil
}
