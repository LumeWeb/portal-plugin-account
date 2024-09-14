package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/battlenet"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("battlenet", "Battle.net", setupBattlenet)
}

func setupBattlenet(key, secret, callback string) (goth.Provider, error) {
	return battlenet.New(key, secret, callback), nil
}
