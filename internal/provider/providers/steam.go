package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/steam"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("steam", "Steam", setupSteam)
}

func setupSteam(key, secret, callback string) (goth.Provider, error) {
	return steam.New(key, callback), nil
}
