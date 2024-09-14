package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/facebook"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("facebook", "Facebook", setupFacebook)
}

func setupFacebook(key, secret, callback string) (goth.Provider, error) {
	return facebook.New(key, secret, callback), nil
}
