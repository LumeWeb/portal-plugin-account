package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/gitea"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("gitea", "Gitea", setupGitea)
}

func setupGitea(key, secret, callback string) (goth.Provider, error) {
	return gitea.New(key, secret, callback), nil
}
