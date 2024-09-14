package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/eveonline"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("eveonline", "Eve Online", setupEveonline)
}

func setupEveonline(key, secret, callback string) (goth.Provider, error) {
	return eveonline.New(key, secret, callback), nil
}
