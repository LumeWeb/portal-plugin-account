package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/bitbucket"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("bitbucket", "Bitbucket", setupBitbucket)
}

func setupBitbucket(key, secret, callback string) (goth.Provider, error) {
	return bitbucket.New(key, secret, callback), nil
}
