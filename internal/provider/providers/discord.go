package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/discord"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("discord", "Discord", setupDiscord)
}

func setupDiscord(key, secret, callback string) (goth.Provider, error) {
	return discord.New(key, secret, callback), nil
}
