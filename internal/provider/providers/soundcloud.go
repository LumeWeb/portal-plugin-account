package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/soundcloud"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("soundcloud", "SoundCloud", setupSoundcloud)
}

func setupSoundcloud(key, secret, callback string) (goth.Provider, error) {
	return soundcloud.New(key, secret, callback), nil
}
