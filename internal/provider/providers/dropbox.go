package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/dropbox"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("dropbox", "Dropbox", setupDropbox)
}

func setupDropbox(key, secret, callback string) (goth.Provider, error) {
	return dropbox.New(key, secret, callback), nil
}
