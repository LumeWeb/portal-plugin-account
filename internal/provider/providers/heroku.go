package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/heroku"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("heroku", "Heroku", setupHeroku)
}

func setupHeroku(key, secret, callback string) (goth.Provider, error) {
	return heroku.New(key, secret, callback), nil
}
