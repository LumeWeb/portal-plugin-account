package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/github"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("github", "Github", setupGithub)
}

func setupGithub(key, secret, callback string) (goth.Provider, error) {
	return github.New(key, secret, callback), nil
}
