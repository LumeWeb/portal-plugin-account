package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/twitterv2"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("twitterv2", "Twitter", setupTwitterv2)
}

func setupTwitterv2(key, secret, callback string) (goth.Provider, error) {
	return twitterv2.New(key, secret, callback), nil
}
