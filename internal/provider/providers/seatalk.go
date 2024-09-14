package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/seatalk"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("seatalk", "SeaTalk", setupSeatalk)
}

func setupSeatalk(key, secret, callback string) (goth.Provider, error) {
	return seatalk.New(key, secret, callback), nil
}
