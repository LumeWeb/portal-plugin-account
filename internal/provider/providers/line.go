package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/line"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("line", "LINE", setupLine)
}

func setupLine(key, secret, callback string) (goth.Provider, error) {
	return line.New(key, secret, callback), nil
}
