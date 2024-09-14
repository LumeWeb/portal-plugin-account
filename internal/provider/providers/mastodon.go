package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/mastodon"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("mastodon", "Mastodon", setupMastodon)
}

func setupMastodon(key, secret, callback string) (goth.Provider, error) {
	return mastodon.New(key, secret, callback), nil
}
