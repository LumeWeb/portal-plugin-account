package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/spotify"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("spotify", "Spotify", setupSpotify)
}

func setupSpotify(key, secret, callback string) (goth.Provider, error) {
	return spotify.New(key, secret, callback), nil
}
