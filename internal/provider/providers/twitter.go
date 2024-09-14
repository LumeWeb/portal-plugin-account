package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/twitter"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("twitter", "Twitter", setupTwitter)
}

func setupTwitter(key, secret, callback string) (goth.Provider, error) {
	return twitter.New(key, secret, callback), nil
}
