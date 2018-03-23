package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Microkubes/authorization-server/config"
	"github.com/Microkubes/authorization-server/db"
	"github.com/Microkubes/microservice-security/oauth2"
	"github.com/Microkubes/microservice-security/tools"
	uuid "github.com/satori/go.uuid"
)

// ClientServiceAPI holds the values for oauth2.ClientService implementation.
// This combines the access to a remote Clients (Apps) service and locally
// persisted ClientAuth repository.
type ClientServiceAPI struct {

	// ServiceURL Clients (Apps) microservice URL.
	ServiceURL string

	// Client pointer to the HTTP client.
	*http.Client

	// Signature is the signature data for the self-issued JWT for access the dependency microservices.
	Signature

	// ClientAuthRepository is the ClientAuthRepository for accessing the locally persisted data.
	db.ClientAuthRepository
}

func (c *ClientServiceAPI) getURL(path string) string {
	return fmt.Sprintf("%s/%s", c.ServiceURL, path)
}

// GetClient retrieves a client data from the clients (apps) microservice.
func (c *ClientServiceAPI) GetClient(clientID string) (*oauth2.Client, error) {
	req, err := NewSignedRequest("GET", c.getURL(fmt.Sprintf("%s", clientID)), nil, c.Signature)
	if err != nil {
		return nil, err
	}
	resp, err := ExecRequest("microservice-apps", req, c.Client, 404)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == 404 {
		return nil, nil
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf(resp.Status)
	}
	client := oauth2.Client{}
	err = json.NewDecoder(resp.Body).Decode(&client)
	return &client, err
}

//VerifyClientCredentials verifies a client (app) for the supplied credentials on the clients (apps) microservice.
func (c *ClientServiceAPI) VerifyClientCredentials(clientID, clientSecret string) (*oauth2.Client, error) {
	payload := map[string]string{
		"id":     clientID,
		"secret": clientSecret,
	}

	payloadData, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := NewSignedRequest("POST", c.getURL("verify"), bytes.NewReader(payloadData), c.Signature)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")

	resp, err := ExecRequest("microservice-apps", req, c.Client)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf(resp.Status)
	}
	client := oauth2.Client{}
	err = json.NewDecoder(resp.Body).Decode(&client)
	return &client, err
}

// SaveClientAuth stores the clientAuth in the client auth repository.
func (c *ClientServiceAPI) SaveClientAuth(clientAuth *oauth2.ClientAuth) error {
	_, err := c.ClientAuthRepository.Save(clientAuth)
	return err
}

// GetClientAuth looks up a clientAuth for the specified client and auth code.
func (c *ClientServiceAPI) GetClientAuth(clientID, code string) (*oauth2.ClientAuth, error) {
	return c.ClientAuthRepository.GetWithCode(clientID, code)
}

// GetClientAuthForUser looks up a clientAuth for the specified client and user.
func (c *ClientServiceAPI) GetClientAuthForUser(userID, clientID string) (*oauth2.ClientAuth, error) {
	return c.ClientAuthRepository.GetWithUserID(clientID, userID)
}

// ConfirmClientAuth confirms that the user has authorized the client. It updates the ClientAuth in the client auth repository.
func (c *ClientServiceAPI) ConfirmClientAuth(userID, clientID string) (*oauth2.ClientAuth, error) {
	ca, err := c.ClientAuthRepository.GetWithUserID(clientID, userID)
	if err != nil {
		return nil, err
	}
	if ca == nil {
		return nil, fmt.Errorf("No client auth")
	}
	ca.Confirmed = true
	return c.ClientAuthRepository.Save(ca)
}

// UpdateUserData updates the user data of the clientAuth identified by the client ID and auth code.
func (c *ClientServiceAPI) UpdateUserData(clientID, code, userID, userData string) error {
	ca, err := c.ClientAuthRepository.GetWithCode(clientID, code)
	if err != nil {
		return err
	}
	if ca == nil {
		return fmt.Errorf("No client auth")
	}
	ca.UserData = userData
	ca.UserID = userID
	_, err = c.ClientAuthRepository.Save(ca)
	if err != nil {
		fmt.Println("Failed to save user data: ", err.Error())
	}
	return err
}

// DeleteClientAuth removes the clientAuth identified by client id and auth code.
func (c *ClientServiceAPI) DeleteClientAuth(clientID, code string) error {
	return c.ClientAuthRepository.Delete(clientID, code)
}

// NewClientService creates new oauth2.ClientService.
func NewClientService(serverConfig *config.ServerConfig, client *http.Client, keyStore tools.KeyStore) (*ClientServiceAPI, func(), error) {
	signature, err := NewClientSignature(serverConfig.ServerName, serverConfig.Security, keyStore)
	if err != nil {
		return nil, nil, err
	}

	dbc := serverConfig.DBConfig

	clientRepository, cleanup, err := db.NewDBClientAuthRepository(dbc.Host,
		dbc.DatabaseName,
		dbc.Username,
		dbc.Password,
		time.Duration(serverConfig.ClientAuthorizationTTL)*time.Millisecond)

	if err != nil {
		return nil, nil, err
	}

	clientAPI := ClientServiceAPI{
		ServiceURL:           serverConfig.ServicesEndpoints.AppsServiceURL,
		Signature:            *signature,
		Client:               client,
		ClientAuthRepository: clientRepository,
	}
	return &clientAPI, cleanup, nil
}

// NewClientSignature builds new Signature containing the data and claims for signing the JWT tokens.
func NewClientSignature(serverName string, securityConf config.Security, keyStore tools.KeyStore) (*Signature, error) {
	randUUID, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}
	claims := map[string]interface{}{
		"userId":   "system",
		"username": "system",
		"roles":    "system",
		"scopes":   "api:read,api:write",
		"iss":      serverName,
		"sub":      "oauth2-auth-server",
		"jti":      randUUID.String(),
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
