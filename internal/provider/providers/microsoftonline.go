package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/microsoftonline"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("microsoftonline", "Microsoft Online", setupMicrosoftonline)
}

func setupMicrosoftonline(key, secret, callback string) (goth.Provider, error) {
	return microsoftonline.New(key, secret, callback), nil
}
