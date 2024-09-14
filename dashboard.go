package dashboard

import (
	"embed"
	_ "embed"
	"go.lumeweb.com/portal-plugin-dashboard/internal"
	"go.lumeweb.com/portal-plugin-dashboard/internal/api"
	"go.lumeweb.com/portal/core"
	"go.lumeweb.com/portal/service"
)

//go:embed templates/*
var mailerTemplates embed.FS

func init() {
	templates, err := service.MailerTemplatesFromEmbed(&mailerTemplates, "")
	if err != nil {
		panic(err)
	}

	core.RegisterPlugin(core.PluginInfo{
		ID: internal.PLUGIN_NAME,
		API: func() (core.API, []core.ContextBuilderOption, error) {
			return api.NewAPI()
		},
		MailerTemplates: templates,
	})
}
