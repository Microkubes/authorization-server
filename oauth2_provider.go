package main

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/JormungandrK/authorization-server/app"
	"github.com/JormungandrK/authorization-server/security"
	"github.com/JormungandrK/microservice-security/auth"
	oa2 "github.com/JormungandrK/microservice-security/oauth2"
	"github.com/goadesign/goa"
	"github.com/goadesign/oauth2"
)

// Oauth2ProviderController implements the oauth2_provider resource.
type Oauth2ProviderController struct {
	*goa.Controller
	*oauth2.ProviderController
	oa2.ClientService
	oa2.TokenService
	security.SessionStore
}

// NewOauth2ProviderController creates a oauth2_provider controller.
func NewOauth2ProviderController(service *goa.Service, provider oauth2.Provider, clientService oa2.ClientService, tokenService oa2.TokenService, sessionStore security.SessionStore) *Oauth2ProviderController {
	return &Oauth2ProviderController{
		Controller:         service.NewController("Oauth2ProviderController"),
		ProviderController: oauth2.NewProviderController(service, provider),
		ClientService:      clientService,
		TokenService:       tokenService,
		SessionStore:       sessionStore,
	}
}

// Authorize runs the authorize action.
func (c *Oauth2ProviderController) Authorize(ctx *app.AuthorizeOauth2ProviderContext) error {
	// Oauth2ProviderController_Authorize: start_implement
	fmt.Println("Ajdeee")
	authObj := auth.GetAuth(ctx.Context)
	if authObj == nil {
		fmt.Println("No auth?", authObj)
		return ctx.BadRequest(&app.OAuth2ErrorMedia{
			Error: "Authentication is required",
		})
	}
	fmt.Println("Checking client authorization...")
	// clientAuth, err := c.ClientService.GetClientAuthForUser(authObj.UserID, ctx.ClientID)
	// if err != nil {
	// 	return err
	// }

	userHasConfirmed, _ := c.SessionStore.Get("auth_confirmed", ctx.Request)
	if userHasConfirmed != nil && *userHasConfirmed != "true" {

		// }
		//
		// if clientAuth == nil || !clientAuth.Confirmed {
		fmt.Println("Not authorized. Prompt client...")
		//redirect to confirmation URL
		rw := ctx.ResponseWriter
		//save client id to session (encrypted)
		authorizeOrigURL := fmt.Sprintf("%s?%s", ctx.Request.URL.Path, ctx.Request.URL.Query())
		c.SessionStore.Set("clientId", ctx.ClientID, rw, ctx.Request)
		err := c.SessionStore.Set("orig_authorize", authorizeOrigURL, rw, ctx.Request)
		if err != nil {
			fmt.Println("Error", err)
			return err
		}
		rw.Header().Set("Location", "/auth/authorize-client")
		rw.WriteHeader(302)
		return nil
	}

	err := c.ProviderController.Authorize(ctx, ctx.ResponseWriter, ctx.Request)
	if err != nil {
		return err
	}

	redirectURL := ctx.ResponseWriter.Header().Get("Location")
	fmt.Printf("Redirect URL -> %s\n", redirectURL)
	u, err := url.Parse(redirectURL)
	if err != nil {
		return err
	}
	code := u.Query().Get("code")
	userData, err := json.Marshal(authObj)
	if err != nil {
		return err
	}
	err = c.ClientService.UpdateUserData(ctx.ClientID, code, authObj.UserID, string(userData))

	return err
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
