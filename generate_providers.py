import os

# Template for the provider setup file
TEMPLATE = '''package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/{provider_lower}"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
{extra_imports}
)

func init() {{
	provider.RegisterProvider("{provider_lower}", "{provider_name}", setup{provider_title})
}}

func setup{provider_title}(key, secret, callback string) (goth.Provider, error) {{
	return {provider_lower}.New({new_params}), nil
}}
'''

# Provider name mapping
PROVIDER_NAME_MAP = {
    "amazon": "Amazon",
    "apple": "Apple",
    "auth0": "Auth0",
    "azuread": "Azure AD",
    "battlenet": "Battle.net",
    "bitbucket": "Bitbucket",
    "box": "Box",
    "dailymotion": "Dailymotion",
    "deezer": "Deezer",
    "digitalocean": "Digital Ocean",
    "discord": "Discord",
    "dropbox": "Dropbox",
    "eveonline": "Eve Online",
    "facebook": "Facebook",
    "fitbit": "Fitbit",
    "gitea": "Gitea",
    "github": "Github",
    "gitlab": "Gitlab",
    "google": "Google",
    "gplus": "Google Plus",
    "heroku": "Heroku",
    "instagram": "Instagram",
    "intercom": "Intercom",
    "kakao": "Kakao",
    "lastfm": "Last FM",
    "line": "LINE",
    "linkedin": "LinkedIn",
    "mastodon": "Mastodon",
    "meetup": "Meetup.com",
    "microsoftonline": "Microsoft Online",
    "naver": "Naver",
    "nextcloud": "NextCloud",
    "okta": "Okta",
    "onedrive": "Onedrive",
    "openid-connect": "OpenID Connect",
    "patreon": "Patreon",
    "paypal": "Paypal",
    "salesforce": "Salesforce",
    "seatalk": "SeaTalk",
    "shopify": "Shopify",
    "slack": "Slack",
    "soundcloud": "SoundCloud",
    "spotify": "Spotify",
    "steam": "Steam",
    "strava": "Strava",
    "stripe": "Stripe",
    "tiktok": "TikTok",
    "twitch": "Twitch",
    "twitter": "Twitter",
    "twitterv2": "Twitter",
    "typetalk": "Typetalk",
    "uber": "Uber",
    "vk": "VK",
    "wecom": "WeCom",
    "wepay": "Wepay",
    "xero": "Xero",
    "yahoo": "Yahoo",
    "yammer": "Yammer",
    "yandex": "Yandex",
    "zoom": "Zoom",
}

# Tuple structure: (extra_params, extra_imports, custom_new_params)
PROVIDERS = {
    "amazon": ("", "", "key, secret, callback"),
    "apple": (", nil, apple.ScopeName, apple.ScopeEmail", "", "key, secret, callback"),
    "auth0": (", os.Getenv(\"AUTH0_DOMAIN\")", "\t\"os\"", "key, secret, callback"),
    "azuread": (", nil", "", "key, secret, callback"),
    "battlenet": ("", "", "key, secret, callback"),
    "bitbucket": ("", "", "key, secret, callback"),
    "box": ("", "", "key, secret, callback"),
    "dailymotion": (", \"email\"", "", "key, secret, callback"),
    "deezer": (", \"email\"", "", "key, secret, callback"),
    "digitalocean": (", \"read\"", "", "key, secret, callback"),
    "discord": (", discord.ScopeIdentify, discord.ScopeEmail", "", "key, secret, callback"),
    "dropbox": ("", "", "key, secret, callback"),
    "eveonline": ("", "", "key, secret, callback"),
    "facebook": ("", "", "key, secret, callback"),
    "fitbit": ("", "", "key, secret, callback"),
    "gitea": ("", "", "key, secret, callback"),
    "github": ("", "", "key, secret, callback"),
    "gitlab": ("", "", "key, secret, callback"),
    "google": ("", "", "key, secret, callback"),
    "gplus": ("", "", "key, secret, callback"),
    "heroku": ("", "", "key, secret, callback"),
    "instagram": ("", "", "key, secret, callback"),
    "intercom": ("", "", "key, secret, callback"),
    "kakao": ("", "", "key, callback"),
    "lastfm": ("", "", "key, secret, callback"),
    "line": (", \"profile\", \"openid\", \"email\"", "", "key, secret, callback"),
    "linkedin": ("", "", "key, secret, callback"),
    "mastodon": (", \"read:accounts\"", "", "key, secret, callback"),
    "meetup": ("", "", "key, secret, callback"),
    "microsoftonline": ("", "", "key, secret, callback"),
    "naver": ("", "", "key, secret, callback"),
    "nextcloud": ("", "", "key, secret, callback, os.Getenv(\"NEXTCLOUD_URL\")"),
    "okta": (", nil, \"openid\", \"profile\", \"email\"", "", "key, secret, callback"),
    "onedrive": ("", "", "key, secret, callback"),
    "openidConnect": ("", "", "key, secret, callback"),
    "patreon": ("", "", "key, secret, callback"),
    "paypal": ("", "", "key, secret, callback"),
    "salesforce": ("", "", "key, secret, callback"),
    "seatalk": ("", "", "key, secret, callback"),
    "shopify": (", shopify.ScopeReadCustomers, shopify.ScopeReadOrders", "", "key, secret, callback"),
    "slack": ("", "", "key, secret, callback"),
    "soundcloud": ("", "", "key, secret, callback"),
    "spotify": ("", "", "key, secret, callback"),
    "steam": ("", "", "key, callback"),
    "strava": ("", "", "key, secret, callback"),
    "stripe": ("", "", "key, secret, callback"),
    "tiktok": ("", "", "key, secret, callback"),
    "twitch": ("", "", "key, secret, callback"),
    "twitter": ("", "", "key, secret, callback"),
    "twitterv2": ("", "", "key, secret, callback"),
    "typetalk": (", \"my\"", "", "key, secret, callback"),
    "uber": ("", "", "key, secret, callback"),
    "vk": ("", "", "key, secret, callback"),
    "wecom": ("", "\t\"os\"", "os.Getenv(\"WECOM_CORP_ID\"), secret, os.Getenv(\"WECOM_AGENT_ID\"), callback"),
    "wepay": (", \"view_user\"", "", "key, secret, callback"),
    "xero": ("", "", "key, secret, callback"),
    "yahoo": ("", "", "key, secret, callback"),
    "yammer": ("", "", "key, secret, callback"),
    "yandex": ("", "", "key, secret, callback"),
    "zoom": (", \"read:user\"", "", "key, secret, callback"),
}

def generate_provider_files():
    # Create the directory if it doesn't exist
    output_dir = "internal/provider/providers"
    os.makedirs(output_dir, exist_ok=True)

    for provider, (extra_params, extra_imports, new_params) in PROVIDERS.items():
        provider_lower = provider.lower()
        provider_title = provider.title()
        provider_name = PROVIDER_NAME_MAP.get(provider_lower, provider_title)

        content = TEMPLATE.format(
            provider_lower=provider_lower,
            provider_title=provider_title,
            provider_name=provider_name,
            extra_params=extra_params,
            extra_imports=extra_imports,
            new_params=new_params
        )

        filename = os.path.join(output_dir, f"{provider_lower}.go")
        with open(filename, 'w') as f:
            f.write(content)
        print(f"Generated {filename}")

if __name__ == "__main__":
    generate_provider_files()