package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/wecom"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
	"os"
)

func init() {
	provider.RegisterProvider("wecom", "WeCom", setupWecom)
}

func setupWecom(key, secret, callback string) (goth.Provider, error) {
	return wecom.New(os.Getenv("WECOM_CORP_ID"), secret, os.Getenv("WECOM_AGENT_ID"), callback), nil
}
