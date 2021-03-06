package config

import (
	"io/ioutil"
	"os"
	"testing"
)

func TestLoadConfigFromFile(t *testing.T) {
	jsonConf := `{
    "serverName": "Jormungandr Authorization Server",
    "security": {
      "keys": {
        "default": "keys/default",
        "system": "keys/system"
      },
      "signingMethod": "RS256",
      "issuer": "oauth2-auth-server"
    },
    "microservice": {
      "name": "oauth2-auth-server",
      "port": 8080,
      "virtual_host": "jwt.auth.jormugandr.org",
      "hosts":["jwt.auth.jormugandr.org", "localhost"],
      "weight": 10,
      "slots": 5
    },
    "services": {
      "userServiceURL": "http://localhost:8081/users",
      "appsServiceURL": "http://localhost:8001/apps"
    },
    "database": {
      "host": "localhost:27017",
      "database": "oauth2",
      "user": "authserver",
      "pass": "authserver"
    },
    "session": {
      "name": "OAuth2Server",
      "authKey": "dGVzdC1hdXRoLWtleQo=",
      "encryptKey": "t/xzB8eZ5ypUiIGbuOq5PhZAKpU7LS239ucRXDq7Lw8="
    },
    "clientAuthorizationTTL": 300000,
    "accessTokenTTL": 2592000000,
    "accessTokenSigningMethod": "RS256",
    "authCodeLength": 10,
    "refreshTokenLength": 27
  }`
	cnfFile, err := ioutil.TempFile("", "config.json")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(cnfFile.Name())

	defer os.Remove(cnfFile.Name())

	_, err = cnfFile.WriteString(jsonConf)
	if err != nil {
		t.Fatal(err)
	}

	config, err := LoadConfig(cnfFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	if config == nil {
		t.Fatal("Expected server conf.")
	}

}
