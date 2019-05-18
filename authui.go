package main

import (
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"

	"github.com/Microkubes/authorization-server/app"
	"github.com/Microkubes/authorization-server/security"
	"github.com/Microkubes/microservice-security/auth"
	"github.com/Microkubes/microservice-security/oauth2"
	"github.com/keitaroinc/goa"
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
	rw := ctx.ResponseWriter
	req := ctx.Request

	confirmation := security.AuthorizeClientData{}

	err := c.SessionStore.GetAs("confirmation", &confirmation, ctx.Request)
	if err != nil {
		c.showError("Invalid parameters. Your confirmation is missing. Please use a browser to login to the system and authroize the client app.", 400, rw, req)
		return nil
	}

	if ctx.Confirmed != nil && *ctx.Confirmed {
		confirmation.Confirmed = true
		c.SessionStore.SetValue("confirmation", confirmation, ctx.ResponseWriter, ctx.Request)

		// Go back to the original authorization URL
		ctx.ResponseWriter.Header().Set("Location", confirmation.AuthorizeRequest)
		ctx.ResponseWriter.WriteHeader(302)
		return nil
	}

	client, err := c.ClientService.GetClient(confirmation.ClientID)
	if err != nil {
		return ctx.InternalServerError(err)
	}
	// clear the session here
	c.SessionStore.Clear("confirmation", ctx.ResponseWriter, ctx.Request)
	// redirect to the client website?
	ctx.ResponseWriter.Header().Set("Location", client.Website)
	ctx.ResponseWriter.WriteHeader(302)
	return nil
}

// PromptAuthorization runs the promptAuthorization action.
func (c *AuthUIController) PromptAuthorization(ctx *app.PromptAuthorizationAuthUIContext) error {
	// AuthUIController_PromptAuthorization: start_implement
	rw := ctx.ResponseWriter
	req := ctx.Request

	authObj := auth.GetAuth(ctx.Context)
	clientID, err := c.SessionStore.Get("clientId", ctx.Request)
	if err != nil {
		c.showError(fmt.Sprintf("A server error has occured. %s", err.Error()), 500, rw, req)
		return nil
	}
	if clientID == nil {
		c.showError("We haven't received the ID of the app.", 400, rw, req)
		return nil
	}
	client, err := c.ClientService.GetClient(*clientID)
	if err != nil {
		c.showError(fmt.Sprintf("A server error has occured. %s", err.Error()), 500, rw, req)
		return nil
	}
	if client == nil {
		c.showError("It seems that you're using a wrong app ID. Please try with the correct app id.", 400, rw, req)
		return nil
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

func (c *AuthUIController) showError(errMsg string, errCode int, rw http.ResponseWriter, req *http.Request) {
	tplContent, err := loadTemplateFile("public/error.html")
	if err != nil {
		rw.Write([]byte(err.Error()))
		rw.WriteHeader(500)
	}
	t, err := template.New("public/error.html").Parse(tplContent)
	if err != nil {
		rw.Write([]byte(err.Error()))
		rw.WriteHeader(500)
	}
	rw.WriteHeader(errCode)
	rw.Header().Set("Content-Type", "text/html")
	t.Execute(rw, map[string]string{
		"message": errMsg,
	})
}

func loadTemplateFile(fileName string) (string, error) {
	b, err := ioutil.ReadFile(fileName)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
