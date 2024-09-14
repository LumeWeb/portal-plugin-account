package provider

import (
	"fmt"
	"github.com/markbates/goth"
	"github.com/samber/lo"
	"go.lumeweb.com/portal-plugin-dashboard/internal"
	pluginConfig "go.lumeweb.com/portal-plugin-dashboard/internal/config"
	"go.lumeweb.com/portal/core"
	"sort"
	"sync"
)

type ProviderFactory func(key, secret, callback string) (goth.Provider, error)

type ProviderSetup struct {
	factories    map[string]ProviderFactory
	configs      map[string]pluginConfig.ProviderConfig
	names        map[string]string
	order        []string
	enabledCache []string
	mu           sync.RWMutex
	ctx          core.Context
}

// NewProviderSetup creates a new ProviderSetup
func NewProviderSetup() *ProviderSetup {
	return &ProviderSetup{
		factories: make(map[string]ProviderFactory),
		configs:   make(map[string]pluginConfig.ProviderConfig),
		names:     make(map[string]string),
	}
}

// RegisterProvider registers a provider factory
func (ps *ProviderSetup) RegisterProvider(id string, name string, factory ProviderFactory) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.factories[id] = factory
	ps.names[id] = name
}

// ConfigureProvider sets the configuration for a provider
func (ps *ProviderSetup) ConfigureProvider(id string, config pluginConfig.ProviderConfig) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.configs[id] = config
	ps.enabledCache = nil // Invalidate cache
}

// SetProviderOrder sets the custom order for providers
func (ps *ProviderSetup) SetProviderOrder(order []string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.order = order
	ps.enabledCache = nil // Invalidate cache
}

// EnabledProviders returns a list of enabled providers in the specified order
func (ps *ProviderSetup) EnabledProviders() []string {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	if ps.enabledCache != nil {
		return ps.enabledCache
	}

	var enabled []string
	for name, config := range ps.configs {
		if config.Enabled {
			enabled = append(enabled, name)
		}
	}

	if len(ps.order) > 0 {
		sort.Slice(enabled, func(i, j int) bool {
			iIndex := lo.IndexOf(ps.order, enabled[i])
			jIndex := lo.IndexOf(ps.order, enabled[j])
			if iIndex == -1 {
				return false
			}
			if jIndex == -1 {
				return true
			}
			return iIndex < jIndex
		})
	} else {
		sort.Strings(enabled)
	}

	ps.enabledCache = enabled
	return enabled
}

// CreateProvider creates a goth.Provider instance for the given provider name
func (ps *ProviderSetup) CreateProvider(name string) (goth.Provider, error) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	factory, ok := ps.factories[name]
	if !ok {
		return nil, fmt.Errorf("provider %s not registered", name)
	}

	config, ok := ps.configs[name]
	if !ok || !config.Enabled {
		return nil, fmt.Errorf("provider %s not configured or not enabled", name)
	}

	return factory(config.Key, config.Secret, fmt.Sprintf("%s/api/account/auth/sso/%s/callback", core.GetService[core.HTTPService](ps.ctx, core.HTTP_SERVICE).APISubdomain(internal.PLUGIN_NAME, true), name))
}

func (ps *ProviderSetup) ProviderName(name string) string {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	if _, ok := ps.names[name]; !ok {
		return ""
	}

	return ps.names[name]
}

func (ps *ProviderSetup) ProviderExists(id string) bool {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	_, ok := ps.factories[id]
	return ok
}

func (ps *ProviderSetup) SetContext(ctx core.Context) {
	ps.ctx = ctx
}
