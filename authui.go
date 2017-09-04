package main

import (
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"

	"github.com/JormungandrK/authorization-server/app"
	"github.com/JormungandrK/authorization-server/security"
	"github.com/JormungandrK/microservice-security/auth"
	"github.com/JormungandrK/microservice-security/oauth2"
	"github.com/goadesign/goa"
)

// AuthUIController implements the authUI resource.
type AuthUIController struct {
	*goa.Controller
	oauth2.ClientService
	security.SessionStore
}

// NewAuthUIController creates a authUI controller.
func NewAuthUIController(service *goa.Service, sessionStore security.SessionStore, clientService oauth2.ClientService) *AuthUIController {
	return &AuthUIController{
		Controller:    service.NewController("AuthUIController"),
		SessionStore:  sessionStore,
		ClientService: clientService,
	}
}

// ConfirmAuthorization runs the confirmAuthorization action.
func (c *AuthUIController) ConfirmAuthorization(ctx *app.ConfirmAuthorizationAuthUIContext) error {

	authObj := auth.GetAuth(ctx.Context)
	clientID, err := c.SessionStore.Get("clientId", ctx.Request)
	if err != nil {
		return ctx.InternalServerError(err)
	}
	if clientID == nil {
		fmt.Println("No client ID")
		return ctx.BadRequest(fmt.Errorf("Invalid client id"))
	}

	// clientAuth, err := c.ClientService.GetClientAuthForUser(authObj.UserID, *clientID)
	// if err != nil {
	// 	return ctx.InternalServerError(err)
	// }
	// if clientAuth == nil {
	// 	fmt.Println("No client auth")
	// 	return ctx.BadRequest(fmt.Errorf("invalid client auth"))
	// }

	if ctx.Confirmed != nil && *ctx.Confirmed {
		backToAuthorize, e := c.SessionStore.Get("orig_authorize", ctx.Request)
		if e != nil {
			return ctx.InternalServerError(err)
		}
		if backToAuthorize == nil {
			fmt.Println("Invalid callback")
			return ctx.BadRequest(fmt.Errorf("invalid-authorize-callback"))
		}
		c.SessionStore.Set("auth_confirmed", "true", ctx.ResponseWriter, ctx.Request)
		_, e = c.ClientService.ConfirmClientAuth(authObj.UserID, *clientID)
		if e != nil {
			return ctx.InternalServerError(err)
		}

		// TODO: clear the session here
		c.SessionStore.Clear("clientId", ctx.ResponseWriter, ctx.Request)
		c.SessionStore.Clear("orig_authorize", ctx.ResponseWriter, ctx.Request)
		// redirect to the client website?
		ctx.ResponseWriter.Header().Set("Location", *backToAuthorize)
		ctx.ResponseWriter.WriteHeader(302)
		return nil
	}

	client, err := c.ClientService.GetClient(*clientID)
	if err != nil {
		return ctx.InternalServerError(err)
	}
	// TODO: clear the session here
	c.SessionStore.Clear("clientId", ctx.ResponseWriter, ctx.Request)
	c.SessionStore.Clear("orig_authorize", ctx.ResponseWriter, ctx.Request)
	// redirect to the client website?
	ctx.ResponseWriter.Header().Set("Location", client.Website)
	ctx.ResponseWriter.WriteHeader(302)
	return nil
}

// PromptAuthorization runs the promptAuthorization action.
func (c *AuthUIController) PromptAuthorization(ctx *app.PromptAuthorizationAuthUIContext) error {
	// AuthUIController_PromptAuthorization: start_implement
	fmt.Println("Promt Auth...")
	authObj := auth.GetAuth(ctx.Context)
	clientID, err := c.SessionStore.Get("clientId", ctx.Request)
	if err != nil {
		return ctx.InternalServerError(err)
	}
	if clientID == nil {
		fmt.Println("No client ID")
		return ctx.BadRequest(fmt.Errorf("Invalid client"))
	}
	client, err := c.ClientService.GetClient(*clientID)
	if err != nil {
		fmt.Println("Err3", err)
		return ctx.InternalServerError(err)
	}
	if client == nil {
		fmt.Println("Client does not exist: ", clientID)
		return ctx.BadRequest(fmt.Errorf("Invalid client"))
	}
	fmt.Println("Rendering template")
	c.renderTemplate("public/auth/prompt-auth.html", map[interface{}]interface{}{
		"client": client,
		"user":   authObj,
	}, ctx.ResponseWriter, ctx.Request)

	// AuthUIController_PromptAuthorization: end_implement
	return nil
}

func (c *AuthUIController) renderTemplate(templateFile string, data interface{}, rw http.ResponseWriter, req *http.Request) error {
	tplContent, err := loadTemplateFile(templateFile)
	if err != nil {
		fmt.Println(err)
		return err
	}
	t, err := template.New(templateFile).Parse(tplContent)
	if err != nil {
		fmt.Println(err)
		return err
	}
	rw.WriteHeader(200)
	rw.Header().Set("Content-Type", "text/html")
	t.Execute(rw, data)
	return nil
}

func loadTemplateFile(fileName string) (string, error) {
	b, err := ioutil.ReadFile(fileName)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
