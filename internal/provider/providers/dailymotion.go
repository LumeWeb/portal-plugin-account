package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/dailymotion"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("dailymotion", "Dailymotion", setupDailymotion)
}

func setupDailymotion(key, secret, callback string) (goth.Provider, error) {
	return dailymotion.New(key, secret, callback), nil
}
