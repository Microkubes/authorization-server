package main

import (
	"github.com/JormungandrK/authorization-server/app"
	"github.com/goadesign/goa"
	"github.com/goadesign/oauth2"
)

// Oauth2ProviderController implements the oauth2_provider resource.
type Oauth2ProviderController struct {
	*goa.Controller
	*oauth2.ProviderController
}

// NewOauth2ProviderController creates a oauth2_provider controller.
func NewOauth2ProviderController(service *goa.Service, provider oauth2.Provider) *Oauth2ProviderController {
	return &Oauth2ProviderController{
		Controller:         service.NewController("Oauth2ProviderController"),
		ProviderController: oauth2.NewProviderController(service, provider),
	}
}

// Authorize runs the authorize action.
func (c *Oauth2ProviderController) Authorize(ctx *app.AuthorizeOauth2ProviderContext) error {
	// Oauth2ProviderController_Authorize: start_implement

	return c.ProviderController.Authorize(ctx, ctx.ResponseWriter, ctx.Request)

	// Oauth2ProviderController_Authorize: end_implement
	//return nil
}

// GetToken runs the get_token action.
func (c *Oauth2ProviderController) GetToken(ctx *app.GetTokenOauth2ProviderContext) error {
	// Oauth2ProviderController_GetToken: start_implement

	// Put your logic here
	p := ctx.Payload

	return c.ProviderController.GetToken(ctx, ctx.ResponseWriter, p.GrantType, p.Code, p.RedirectURI, p.RefreshToken, p.Scope)

	// Oauth2ProviderController_GetToken: end_implement
	//res := &app.TokenMedia{}
	//return ctx.OK(res)
}
