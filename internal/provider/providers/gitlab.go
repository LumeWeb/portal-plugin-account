package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/gitlab"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("gitlab", "Gitlab", setupGitlab)
}

func setupGitlab(key, secret, callback string) (goth.Provider, error) {
	return gitlab.New(key, secret, callback), nil
}
