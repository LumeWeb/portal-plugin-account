package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/strava"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("strava", "Strava", setupStrava)
}

func setupStrava(key, secret, callback string) (goth.Provider, error) {
	return strava.New(key, secret, callback), nil
}
