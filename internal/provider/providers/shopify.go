package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/shopify"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("shopify", "Shopify", setupShopify)
}

func setupShopify(key, secret, callback string) (goth.Provider, error) {
	return shopify.New(key, secret, callback), nil
}
