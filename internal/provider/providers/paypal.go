package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/paypal"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("paypal", "Paypal", setupPaypal)
}

func setupPaypal(key, secret, callback string) (goth.Provider, error) {
	return paypal.New(key, secret, callback), nil
}
