package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/yammer"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("yammer", "Yammer", setupYammer)
}

func setupYammer(key, secret, callback string) (goth.Provider, error) {
	return yammer.New(key, secret, callback), nil
}
