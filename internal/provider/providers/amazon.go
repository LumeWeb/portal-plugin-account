package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/amazon"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("amazon", "Amazon", setupAmazon)
}

func setupAmazon(key, secret, callback string) (goth.Provider, error) {
	return amazon.New(key, secret, callback), nil
}
