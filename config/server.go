package config

import (
	"encoding/json"
	"io/ioutil"

	"github.com/Microkubes/microservice-tools/gateway"
)

// ServerConfig holds the main configuration for the Authorization Server
type ServerConfig struct {
	// ServerName is the name of the server. Used for signing when issuing access tokens (as JWT)
	ServerName string `json:"serverName,omitempty"`

	// Security holds the security configuration (keys, signing method etc)
	Security `json:"security,omitempty"`

	// MicroserviceConfig is the configuration for the server to run as microservice (gateway config, service namet etc)
	gateway.MicroserviceConfig `json:"microservice,omitempty"`

	// ServicesEndpoints holds the URLs of the other microservices that are dependencies to the authorization server.
	ServicesEndpoints `json:"services,omitempty"`

	// DBConfig holds the database configuration
	DBConfig `json:"database,omitempty"`

	// SessionConfig holds the value for the way the session is handled by the server
	SessionConfig `json:"session,omitempty"`

	// ClientAuthorizationTTL is a time duration in milliseconds for which the client authorization is valid.
	ClientAuthorizationTTL int `json:"clientAuthorizationTTL,omitempty"`

	// AccessTokenTTL controls the time duration for which an issued access token is valid. Specified in milliseconds.
	AccessTokenTTL int `json:"accessTokenTTL,omitempty"`

	// AccessTokenSigningMethod is the method used for signing the access tokens (as JWT). Usual values are: RS256, RS384 and RS512.
	AccessTokenSigningMethod string `json:"accessTokenSigningMethod,omitempty"`

	// AuthCodeLength is the length of generated the authorization code string.
	AuthCodeLength int `json:"authCodeLength,omitempty"`

	// RefreshTokenLength is the length of the random generated refresh token string.
	RefreshTokenLength int `json:"refreshTokenLength,omitempty"`

	//Version is version of the service
	Version string `json:"version"`
}

// Security holds the security configuration.
type Security struct {

	// Keys is a map key-name => file-path for the private keys used by this server. There should be at least a "default" and "system" key.
	Keys map[string]string `json:"keys"`

	// SigningMethod for the self-issued JWT tokens for accessing other services.
	SigningMethod string `json:"signingMethod,omitempty"`

	// The name used by this server in the self-issued JWTs.
	Issuer string `json:"issuer,omitempty"`
}

// ServicesEndpoints holds the URLs of the used microservices (user, client).
type ServicesEndpoints struct {

	// UserServiceURL is the exposed gateway URL of the user microservice
	UserServiceURL string `json:"userServiceURL,omitempty"`

	// UserServiceURL is the exposed gateway URL of the clients (apps) microservice
	AppsServiceURL string `json:"appsServiceURL,omitempty"`
}

// DBConfig holds the database configuration parameters.
type DBConfig struct {

	// Host is the database host+port URL
	Host string `json:"host,omitempty"`

	// Username is the username used to access the database
	Username string `json:"user,omitempty"`

	// Password is the databse user password
	Password string `json:"pass,omitempty"`

	// DatabaseName is the name of the database where the server will store the collections
	DatabaseName string `json:"database,omitempty"`
}

// SessionConfig holds the configuration for session handling by the server.
type SessionConfig struct {
	// AuthKey is the key used for auth of the encrypted session values.
	AuthKey string `json:"authKey,omitempty"`

	// EncryptKey is the key used to encrypt the session values. The value is Base64 encoded string and
	// MUST be multiple of 2 bytes when decoded. Reccommended is using a key that has 32 bytes when decoded.
	// For example, you can generate it like so: ```dd if=/dev/urandom bs=1 count=32 | base64```.
	// If not supplied, a random key with length of 32 bytes will be generated.
	EncryptKey string `json:"encryptKey,omitempty"`

	// SessionName is the name of the session used and recognized by this server.
	SessionName string `json:"name,omitempty"`
}

// LoadConfig loads the ServerConfig from a JSON file.
func LoadConfig(configFile string) (*ServerConfig, error) {
	buff, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	conf := ServerConfig{}
	if err = json.Unmarshal(buff, &conf); err != nil {
		return nil, err
	}
	return &conf, err
}
