package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/stripe"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("stripe", "Stripe", setupStripe)
}

func setupStripe(key, secret, callback string) (goth.Provider, error) {
	return stripe.New(key, secret, callback), nil
}
