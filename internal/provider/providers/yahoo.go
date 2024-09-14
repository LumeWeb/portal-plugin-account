package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/yahoo"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("yahoo", "Yahoo", setupYahoo)
}

func setupYahoo(key, secret, callback string) (goth.Provider, error) {
	return yahoo.New(key, secret, callback), nil
}
