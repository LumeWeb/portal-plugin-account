package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/naver"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("naver", "Naver", setupNaver)
}

func setupNaver(key, secret, callback string) (goth.Provider, error) {
	return naver.New(key, secret, callback), nil
}
