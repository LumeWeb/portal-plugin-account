package dashboard

import (
	"embed"
	_ "embed"
	"go.lumeweb.com/portal-plugin-dashboard/internal"
	"go.lumeweb.com/portal-plugin-dashboard/internal/api"
	pluginConfig "go.lumeweb.com/portal-plugin-dashboard/internal/config"
	pluginDb "go.lumeweb.com/portal-plugin-dashboard/internal/db"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
	pluginService "go.lumeweb.com/portal-plugin-dashboard/internal/service"
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
		Services: func() ([]core.ServiceInfo, error) {
			return []core.ServiceInfo{
				{
					ID: pluginService.API_KEY_SERVICE,
					Factory: func() (core.Service, []core.ContextBuilderOption, error) {
						return pluginService.NewAPIKeyService()
					},
					Depends: []string{core.USER_SERVICE, core.AUTH_SERVICE},
				},
			}, nil
		},
		Models: []any{
			&pluginDb.APIKey{},
		},
		MailerTemplates: templates,
	})
}
