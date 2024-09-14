package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/uber"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("uber", "Uber", setupUber)
}

func setupUber(key, secret, callback string) (goth.Provider, error) {
	return uber.New(key, secret, callback), nil
}
