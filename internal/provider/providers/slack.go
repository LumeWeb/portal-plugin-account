package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/slack"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("slack", "Slack", setupSlack)
}

func setupSlack(key, secret, callback string) (goth.Provider, error) {
	return slack.New(key, secret, callback), nil
}
