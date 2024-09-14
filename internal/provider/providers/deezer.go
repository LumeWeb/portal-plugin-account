package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/deezer"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("deezer", "Deezer", setupDeezer)
}

func setupDeezer(key, secret, callback string) (goth.Provider, error) {
	return deezer.New(key, secret, callback), nil
}
