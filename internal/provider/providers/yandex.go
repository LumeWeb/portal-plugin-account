package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/yandex"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("yandex", "Yandex", setupYandex)
}

func setupYandex(key, secret, callback string) (goth.Provider, error) {
	return yandex.New(key, secret, callback), nil
}
