package main

import (
	"fmt"
	"github.com/JormungandrK/authorization-server/client"
	"github.com/JormungandrK/authorization-server/tool/cli"
	goaclient "github.com/goadesign/goa/client"
	"github.com/spf13/cobra"
	"net/http"
	"os"
	"time"
)

func main() {
	// Create command line parser
	app := &cobra.Command{
		Use:   "-cli",
		Short: `CLI client for the  service`,
	}

	// Create client struct
	httpClient := newHTTPClient()
	c := client.New(goaclient.HTTPClientDoer(httpClient))

	// Register global flags
	app.PersistentFlags().StringVarP(&c.Scheme, "scheme", "s", "", "Set the requests scheme")
	app.PersistentFlags().StringVarP(&c.Host, "host", "H", "", "API hostname")
	app.PersistentFlags().DurationVarP(&httpClient.Timeout, "timeout", "t", time.Duration(20)*time.Second, "Set the request timeout")
	app.PersistentFlags().BoolVar(&c.Dump, "dump", false, "Dump HTTP request and response.")

	// Register signer flags
	var user, pass string
	app.PersistentFlags().StringVar(&user, "user", "", "Username used for authentication")
	app.PersistentFlags().StringVar(&pass, "pass", "", "Password used for authentication")
	var token, typ string
	app.PersistentFlags().StringVar(&token, "token", "", "Token used for authentication")
	app.PersistentFlags().StringVar(&typ, "token-type", "Bearer", "Token type used for authentication")

	// Parse flags and setup signers
	app.ParseFlags(os.Args)
	source := &goaclient.StaticTokenSource{
		StaticToken: &goaclient.StaticToken{Type: typ, Value: token},
	}
	oauth2ClientBasicAuthSigner := newOauth2ClientBasicAuthSigner(user, pass)
	oAuth2Signer := newOAuth2Signer(source)

	// Initialize API client
	c.SetOauth2ClientBasicAuthSigner(oauth2ClientBasicAuthSigner)
	c.SetOAuth2Signer(oAuth2Signer)
	c.UserAgent = "-cli/0"

	// Register API commands
	cli.RegisterCommands(app, c)

	// Execute!
	if err := app.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(-1)
	}
}

// newHTTPClient returns the HTTP client used by the API client to make requests to the service.
func newHTTPClient() *http.Client {
	// TBD: Change as needed (e.g. to use a different transport to control redirection policy or
	// disable cert validation or...)
	return http.DefaultClient
}

// newOauth2ClientBasicAuthSigner returns the request signer used for authenticating
// against the oauth2_client_basic_auth security scheme.
func newOauth2ClientBasicAuthSigner(user, pass string) goaclient.Signer {
	return &goaclient.BasicSigner{
		Username: user,
		Password: pass,
	}

}

// newOAuth2Signer returns the request signer used for authenticating
// against the OAuth2 security scheme.
func newOAuth2Signer(source goaclient.TokenSource) goaclient.Signer {
	return &goaclient.OAuth2Signer{
		TokenSource: source,
	}

}
