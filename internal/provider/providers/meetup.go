package providers

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/meetup"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
)

func init() {
	provider.RegisterProvider("meetup", "Meetup.com", setupMeetup)
}

func setupMeetup(key, secret, callback string) (goth.Provider, error) {
	return meetup.New(key, secret, callback), nil
}
