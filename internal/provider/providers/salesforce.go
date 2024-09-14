package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/salesforce"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("salesforce", "Salesforce", setupSalesforce)
}

func setupSalesforce(key, secret, callback string) (goth.Provider, error) {
	return salesforce.New(key, secret, callback), nil
}
