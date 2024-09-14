package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/lastfm"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("lastfm", "Last FM", setupLastfm)
}

func setupLastfm(key, secret, callback string) (goth.Provider, error) {
	return lastfm.New(key, secret, callback), nil
}
