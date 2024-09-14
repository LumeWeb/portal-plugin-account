package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/zoom"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("zoom", "Zoom", setupZoom)
}

func setupZoom(key, secret, callback string) (goth.Provider, error) {
	return zoom.New(key, secret, callback), nil
}
