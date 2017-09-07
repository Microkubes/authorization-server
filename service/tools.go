package service

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/JormungandrK/authorization-server/config"
	"github.com/JormungandrK/jwt-issuer/store"
	"github.com/JormungandrK/microservice-security/jwt"
	"github.com/afex/hystrix-go/hystrix"
	uuid "github.com/satori/go.uuid"
)

// Signature holds the data for signing the self-issued JWTs for accessing
// dependencies microservices.
type Signature struct {

	// SigningMethod is the method used for signing the JWT. Valid values are "RS256", "RS384" and "RS512".
	SigningMethod string

	// Key is the private key used for signing the JWT.
	Key interface{}

	// Claims is the map of standard and custom defined claims for the JWT.
	Claims map[string]interface{}
}

// NewSignedRequest creates an HTTP request that is signed with the given Signature.
// The request has its Authorization header populated with the generated JWT.
func NewSignedRequest(method string, urlStr string, body io.Reader, signature Signature) (*http.Request, error) {
	req, err := http.NewRequest(method, urlStr, body)
	if err != nil {
		return nil, err
	}
	signedString, err := jwt.SignToken(signature.Claims, signature.SigningMethod, signature.Key)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", signedString))
	return req, err
}

// ExecRequest executes an HTTP request to a given service.
// The execution is wrapped in a hystrix command with the name set to the "action" argument.
func ExecRequest(action string, req *http.Request, client *http.Client) (*http.Response, error) {
	var resp *http.Response
	err := hystrix.Do(action, func() error {
		r, e := client.Do(req)
		if e != nil {
			return e
		}
		resp = r
		return nil
	}, nil)
	return resp, err
}

// NewSystemSignature generates a common Signature from a given configuration. This Signature is
// issued with system authentication and used for communication with other microservices on the platform.
func NewSystemSignature(serverName string, securityConf config.Security, keyStore store.KeyStore) (*Signature, error) {
	claims := map[string]interface{}{
		"userId":   "system",
		"username": "system",
		"roles":    []string{"system"},
		"iss":      serverName,
		"sub":      "oauth2-auth-server",
		"jti":      uuid.NewV4().String(),
		"nbf":      0,
		"exp":      time.Now().Add(time.Duration(30 * time.Second)).Unix(),
		"iat":      time.Now().Unix(),
	}
	systemKey, err := keyStore.GetPrivateKeyByName("system")
	if err != nil {
		return nil, err
	}
	return &Signature{
		Claims:        claims,
		Key:           systemKey,
		SigningMethod: securityConf.SigningMethod,
	}, nil
}
