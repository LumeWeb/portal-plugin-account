package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/google"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

var scopes = []string{
	"openid",
	"https://www.googleapis.com/auth/userinfo.email",
	"https://www.googleapis.com/auth/userinfo.profile",
}

func init() {
	provider.RegisterProvider("google", "Google", setupGoogle)
}

func setupGoogle(key, secret, callback string) (goth.Provider, error) {
	pvd := google.New(key, secret, callback, scopes...)
	pvd.SetPrompt("consent")

	return pvd, nil
}
