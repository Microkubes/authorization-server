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

type Signature struct {
	SigningMethod string
	Key           interface{}
	Claims        map[string]interface{}
}

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
