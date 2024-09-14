package dashboard

import (
	"embed"
	_ "embed"
	"go.lumeweb.com/portal-plugin-dashboard/internal"
	"go.lumeweb.com/portal-plugin-dashboard/internal/api"
	pluginConfig "go.lumeweb.com/portal-plugin-dashboard/internal/config"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
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
		Meta: func(ctx core.Context, builder core.PortalMetaBuilder) error {
			pluginCfg := ctx.Config().GetPlugin(internal.PLUGIN_NAME).API.(*pluginConfig.APIConfig)
			if pluginCfg.SocialLogin.Enabled {
				builder.AddFeatureFlag("social_login", true)
				builder.AddPluginMeta(internal.PLUGIN_NAME, "social_providers", provider.EnabledProviders())
			}

			builder.AddPluginMeta(internal.PLUGIN_NAME, "subdomain", pluginCfg.Subdomain)

			return nil
		},
		API: func() (core.API, []core.ContextBuilderOption, error) {
			return api.NewAPI()
		},
		MailerTemplates: templates,
	})
}
