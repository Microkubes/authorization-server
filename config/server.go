package config

import (
	"encoding/json"
	"io/ioutil"

	"github.com/JormungandrK/microservice-tools/gateway"
)

type ServerConfig struct {
	ServerName                 string `json:"serverName,omitempty"`
	Security                   `json:"security,omitempty"`
	gateway.MicroserviceConfig `json:"microservice,omitempty"`
	ServicesEndpoints          `json:"services,omitempty"`
	DBConfig                   `json:"database,omitempty"`
	SessionConfig              `json:"session,omitempty"`
	ClientAuthorizationTTL     int    `json:"clientAuthorizationTTL,omitempty"`
	AccessTokenTTL             int    `json:"accessTokenTTL,omitempty"`
	AccessTokenSigningMethod   string `json:"accessTokenSigningMethod,omitempty"`
	AuthCodeLength             int    `json:"authCodeLength,omitempty"`
	RefreshTokenLength         int    `json:"refreshTokenLength,omitempty"`
}

type Security struct {
	Keys          map[string]string `json:"keys"`
	SigningMethod string            `json:"signingMethod,omitempty"`
	Issuer        string            `json:"issuer,omitempty"`
}

type ServicesEndpoints struct {
	UserServiceURL string `json:"userServiceURL,omitempty"`
	AppsServiceURL string `json:"appsServiceURL,omitempty"`
}

type DBConfig struct {
	Host         string `json:"host,omitempty"`
	Username     string `json:"user,omitempty"`
	Password     string `json:"pass,omitempty"`
	DatabaseName string `json:"database,omitempty"`
}

type SessionConfig struct {
	AuthKey     string `json:"authKey,omitempty"`
	EncryptKey  string `json:"encryptKey,omitempty"`
	SessionName string `json:"name,omitempty"`
}

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
