package service

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/JormungandrK/authorization-server/config"
	"github.com/JormungandrK/jwt-issuer/store"
	"github.com/JormungandrK/microservice-security/oauth2"
)

type UserServiceAPI struct {
	ServiceURL string
	*http.Client
	Signature
}

func (u *UserServiceAPI) VerifyUser(username, password string) (*oauth2.User, error) {
	credentials := map[string]string{
		"username": username,
		"password": password,
	}
	data, _ := json.Marshal(credentials)
	req, err := NewSignedRequest("POST", fmt.Sprintf("%s/find", u.ServiceURL), strings.NewReader(string(data)), u.Signature)
	req.Header.Add("Content-Type", "application/json")
	if err != nil {
		return nil, err
	}
	resp, err := ExecRequest("user-microservice", req, u.Client)
	if err != nil {
		println("Error:", err)
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

func NewUserService(serverConfig *config.ServerConfig, client *http.Client, keyStore store.KeyStore) (*UserServiceAPI, error) {
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
