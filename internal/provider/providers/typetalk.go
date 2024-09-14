package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/typetalk"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("typetalk", "Typetalk", setupTypetalk)
}

func setupTypetalk(key, secret, callback string) (goth.Provider, error) {
	return typetalk.New(key, secret, callback), nil
}
