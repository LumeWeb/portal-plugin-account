package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/fitbit"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("fitbit", "Fitbit", setupFitbit)
}

func setupFitbit(key, secret, callback string) (goth.Provider, error) {
	return fitbit.New(key, secret, callback), nil
}
