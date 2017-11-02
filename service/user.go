package service

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/JormungandrK/authorization-server/config"
	"github.com/JormungandrK/microservice-security/oauth2"
	"github.com/JormungandrK/microservice-security/tools"
)

// UserServiceAPI holds the data for implementation of oauth2.UserService.
type UserServiceAPI struct {
	// ServiceURL is the URL of the user microservice.
	ServiceURL string

	// Client is the http.Client used for all requests.
	*http.Client

	// Signature is the Signature of this server used for signing the self-issued JWTs.
	Signature
}

// VerifyUser makes a call to the user microservice to verify the user credentials.
func (u *UserServiceAPI) VerifyUser(email, password string) (*oauth2.User, error) {
	credentials := map[string]string{
		"email":    email,
		"password": password,
	}
	data, _ := json.Marshal(credentials)
	req, err := NewSignedRequest("POST", fmt.Sprintf("%s/find", u.ServiceURL), strings.NewReader(string(data)), u.Signature)
	req.Header.Add("Content-Type", "application/json")
	if err != nil {
		return nil, err
	}
	resp, err := ExecRequest("user-microservice", req, u.Client, 404)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == 404 {
		return nil, nil
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf(resp.Status)
	}
	user := oauth2.User{}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}
	return &user, nil
}

// NewUserService crates new UserServiceAPI from the ServerConfig.
func NewUserService(serverConfig *config.ServerConfig, client *http.Client, keyStore tools.KeyStore) (*UserServiceAPI, error) {
	signature, err := NewSystemSignature(serverConfig.ServerName, serverConfig.Security, keyStore)
	if err != nil {
		return nil, err
	}
	return &UserServiceAPI{
		Signature:  *signature,
		Client:     client,
		ServiceURL: serverConfig.ServicesEndpoints.UserServiceURL,
	}, nil
}
