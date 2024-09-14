package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/twitch"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("twitch", "Twitch", setupTwitch)
}

func setupTwitch(key, secret, callback string) (goth.Provider, error) {
	return twitch.New(key, secret, callback), nil
}
