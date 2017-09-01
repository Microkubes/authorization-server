//go:generate goagen bootstrap -d github.com/JormungandrK/authorization-server/design

package main

import (
	"github.com/JormungandrK/authorization-server/app"
	"github.com/JormungandrK/authorization-server/security"
	svc "github.com/JormungandrK/authorization-server/service"
	"github.com/JormungandrK/microservice-security/oauth2"
	"github.com/goadesign/goa"
	"github.com/goadesign/goa/middleware"
)

func main() {
	// Create service
	service := goa.New("")

	formLoginMiddleware := security.FormLoginMiddleware(&security.FormLoginScheme{
		PostURL:       "/check_credentials",
		LoginURL:      "/login",
		UsernameField: "username",
		PasswordField: "password",
		CookieSecret:  []byte("secret-key"),
		IgnoreURLs:    []string{"/login", "/oauth/token"},
	}, &svc.DummyUserService{
		Users: map[string]*svc.MockUser{
			"test-user": &svc.MockUser{
				User: oauth2.User{
					ID:            "123456",
					Username:      "test-user",
					Email:         "user@example.com",
					Roles:         []string{"user"},
					Organizations: []string{"org1"},
				},
				Password: "pass",
			},
		},
	})

	// Mount middleware
	service.Use(middleware.RequestID())
	service.Use(middleware.LogRequest(true))
	service.Use(middleware.ErrorHandler(service, true))
	service.Use(middleware.Recover())
	service.Use(formLoginMiddleware)

	// Mount "oauth2_provider" controller
	provider := svc.NewMockOAuth2Provider([]*oauth2.Client{
		&oauth2.Client{
			ClientID:    "test-client-0000000001",
			Name:        "test-client",
			Description: "Test client",
			Website:     "http://localhost:9090",
			Secret:      "super-secret-stuff",
		},
	})
	c := NewOauth2ProviderController(service, provider, provider.ClientService)
	app.MountOauth2ProviderController(service, c)

	publicController := NewPublicController(service)

	app.MountPublicController(service, publicController)

	// Start service
	if err := service.ListenAndServe(":8080"); err != nil {
		service.LogError("startup", "err", err)
	}

}
