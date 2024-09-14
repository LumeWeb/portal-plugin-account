package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/box"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("box", "Box", setupBox)
}

func setupBox(key, secret, callback string) (goth.Provider, error) {
	return box.New(key, secret, callback), nil
}
