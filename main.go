//go:generate goagen bootstrap -d github.com/JormungandrK/authorization-server/design

package main

import (
	"github.com/JormungandrK/authorization-server/app"
	svc "github.com/JormungandrK/authorization-server/service"
	"github.com/JormungandrK/microservice-security/oauth2"
	"github.com/goadesign/goa"
	"github.com/goadesign/goa/middleware"
)

func main() {
	// Create service
	service := goa.New("")

	// Mount middleware
	service.Use(middleware.RequestID())
	service.Use(middleware.LogRequest(true))
	service.Use(middleware.ErrorHandler(service, true))
	service.Use(middleware.Recover())

	// Mount "oauth2_provider" controller
	c := NewOauth2ProviderController(service, svc.NewMockOAuth2Provider([]*oauth2.Client{
		&oauth2.Client{
			ClientID:    "test-client-0000000001",
			Name:        "test-client",
			Description: "Test client",
			Website:     "http://localhost:9090",
			Secret:      "super-secret-stuff",
		},
	}))
	app.MountOauth2ProviderController(service, c)

	// Start service
	if err := service.ListenAndServe(":8080"); err != nil {
		service.LogError("startup", "err", err)
	}

}
