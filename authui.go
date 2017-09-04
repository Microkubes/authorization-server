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
func NewAuthUIController(service *goa.Service) *AuthUIController {
	return &AuthUIController{Controller: service.NewController("AuthUIController")}
}

// ConfirmAuthorization runs the confirmAuthorization action.
func (c *AuthUIController) ConfirmAuthorization(ctx *app.ConfirmAuthorizationAuthUIContext) error {
	// AuthUIController_ConfirmAuthorization: start_implement
	if ctx.Confirmed != nil && *ctx.Confirmed {
		// redirect back to the authorize URL
		redirect, err := c.SessionStore.Get(security.AUTH_REDIRECT, ctx.Request)
		if err != nil {
			return ctx.InternalServerError(err)
		}
		if redirect == nil {
			return ctx.BadRequest(fmt.Errorf("Cannot proceed to authorization because cannot redirect you properly"))
		}
		c.SessionStore.Clear("clientId", ctx.ResponseWriter, ctx.Request)
		rw := ctx.ResponseWriter
		rw.Header().Set("Location", *redirect)
		rw.WriteHeader(302)
		return nil
	}
	clientID, err := c.SessionStore.Get("clientId", ctx.Request)
	if err != nil {
		return ctx.InternalServerError(err)
	}
	if clientID == nil {
		return ctx.BadRequest(fmt.Errorf("Invalid client"))
	}
	client, err := c.ClientService.GetClient(*clientID)
	if err != nil {
		return ctx.InternalServerError(err)
	}
	if client == nil {
		return ctx.BadRequest(fmt.Errorf("Invalid client"))
	}
	c.SessionStore.Clear("clientId", ctx.ResponseWriter, ctx.Request)
	rw := ctx.ResponseWriter
	rw.Header().Set("Location", client.Website)
	rw.WriteHeader(302)
	// AuthUIController_ConfirmAuthorization: end_implement
	return nil
}

// PromptAuthorization runs the promptAuthorization action.
func (c *AuthUIController) PromptAuthorization(ctx *app.PromptAuthorizationAuthUIContext) error {
	// AuthUIController_PromptAuthorization: start_implement

	authObj := auth.GetAuth(ctx.Context)
	clientID, err := c.SessionStore.Get("clientId", ctx.Request)
	if err != nil {
		return ctx.InternalServerError(err)
	}
	if clientID == nil {
		return ctx.BadRequest(fmt.Errorf("Invalid client"))
	}
	client, err := c.ClientService.GetClient(*clientID)
	if err != nil {
		return ctx.InternalServerError(err)
	}
	if client == nil {
		return ctx.BadRequest(fmt.Errorf("Invalid client"))
	}

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
		return err
	}
	t, err := template.New(templateFile).Parse(tplContent)
	if err != nil {
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
