package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/tiktok"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("tiktok", "TikTok", setupTiktok)
}

func setupTiktok(key, secret, callback string) (goth.Provider, error) {
	return tiktok.New(key, secret, callback), nil
}
