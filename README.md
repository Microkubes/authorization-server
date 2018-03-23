OAuth2 Authorization Server
===========================

[![Build](https://travis-ci.com/Microkubes/authorization-server.svg?token=UB5yzsLHNSbtjSYrGbWf&branch=master)](https://travis-ci.com/Microkubes/authorization-server)
[![Test Coverage](https://api.codeclimate.com/v1/badges/1a6769b9294e060ecd33/test_coverage)](https://codeclimate.com/repos/59b900fc7b2913029c001215/test_coverage)
[![Maintainability](https://api.codeclimate.com/v1/badges/1a6769b9294e060ecd33/maintainability)](https://codeclimate.com/repos/59b900fc7b2913029c001215/maintainability)


OAuth2 Authorization Server as a separate micro-service.

# Installation

You can install the Auth Server via go:
```bash
go get -u github.com/Microkubes/authorization-server
```

## Building

To build the server, follow these steps:

1. Get the source code from github:
```bash
git clone https://github.com/Microkubes/authorization-server.git
cd authorization-server
```

2. Create ```keys``` directory:
```bash
mkdir keys
```

3. Copy you private key that is registered with github, so that the docker container can access the private repositories on github.

```bash
cp ~/.ssh/id_rsa ./keys
```

4. Run the docker build:

```bash
docker build -t authorization-server .
```

### Local build

To build the code locally for development, just run ```go build -o authorization-server```.

# Run the authorization server

To run the authorization-server docker image, you first need to have Mongo and Kong images running (see jormugandr-infrastructure project).
Then, you'll need to generate or specify the server keys.

1. Configure the access to mongo - to do this, you need to create/edit your configuration. Find your configuration file (config.json - usually in the
  same directory as the authorization-server). Then find the "database" property in it. Change the DB host, username and password to match your configuration.
  Example:

```json

"database": {
  "host": "192.168.0.187:27017",
  "database": "oauth2",
  "user": "authserver",
  "pass": "authserver"
},

```

Save the configuration file on an accessible location (for example in a config directory).

2. Generate the server RSA keys. You'll need at least 2 keys: ```system``` and ```default```.
Don't set passphrase for the keys.

```bash
mkdir server-keys
ssh-keygen -f server-keys/system
ssh-keygen -f server-keys/default
```

Make sure that the keys file names match the configuration.

3. Run the container, mounting the keys directory and the config directory as a volume:

```bash
docker run \
       -e SERVICE_CONFIG_FILE=/config/config.json \ # set custom config location
       -e API_GATEWAY_URL=http://192.168.0.187:8001 \ # set custom API gateway URL
       -v $(pwd)/server-keys:/keys \ # mount the server keys directory
       -v $(pwd)/config:/config \ # mount the config directory containig the modified configuration
       authorization-server
```

# Server Configuration

Default path for the config file is /run/secrets/microservice_authorization_server_config.json. To change this set the 
**SVC_CONFIG** env var.  

## General Server Properties

* ```serverName``` - the name of the server. This is a user-friendly name of the server.

## Access Token Management Properties

* ```clientAuthorizationTTL``` - Validity period for the client authorization (in **milliseconds**). A client authorization is a record that the keeps about a client (app) asking permission from a user. For each client asking permission, the server stores a record before prompting the user to authorize the client. After the user authorizes the client, the record keeps the Access Code that has been generated. Later on, when the client asks for a token, the code is retrieved from this record. However this record does not live forever. After this period expires, the record is removed automatically.
* ```accessTokenTTL``` - Validity period for the Access Tokens expressed in milliseconds.
* ```accessTokenSigningMethod``` - Method used for signing of the access tokens. Valid values are "RS256", "RS384" and "RS512". Because the Access Token itself is a JWT (self contained and signed), this is the method used for signing the JWT.

* ```authCodeLength``` - The length of the Authorization Code issued by the server. The Authorization Code is a randomly generated string with this length.

* ```refreshTokenLength``` - The length of the refresh token string. The refresh token is also a randomly generated string with this length.

## Security settings and self-signed JWTs

This is the section ```security``` of the configuration.

* ```keys``` - a map "name" => "path" of the server RSA keys. The auth server uses
two keys: ```default``` and ```system```. The default key is used for signing the Access Tokens. The system key is used for signing the self-issued JWTs which are used in the requests to the other inner microservices (the user microservice, the clients microservice etc).

* ```signingMethod``` - Signing method for the self-issued JWTs.
* ```issuer``` - the name of this server, set in the standard claim of the JWTs (```iss```).

## Server registration as microservice

The configuration for the server as microservice is located in the ```microservice``` section.

Available properties:

* ```name``` - The name of the microservice (in this case something like "oauth2-auth-server")
* ```port``` - The local port (in the docker container) on which the server is listening.
* ```virtual_host``` - the name of the virtual host (the domain) for the server. A valid value might be: "oauth2.auth.jormugandr.org". Note that this name must appear in the list of available hosts.
* ```hosts``` - a list of available and valid hosts for this microservice. This is used for registration with the API Gateway. The gateway proxy will redirect only those requests that have the HTTP header "Host" set to one of these values.
* ```weight``` - an integer weight used with the load balancing algorithm on the API Gateway. If you're not sure, put ```10``` as weight.
* ```slots``` - maximal number of instances allowed for this microservice. The instances are identified by the ```name```. At any given time there would be at maximum ```slots``` number of instances with name ```<name>```.

### Services URLs

The server must access a couple of other microservices, such as the user microservice and the clients (apps) microservice. The URLs of these services are specified in the ```services``` section:

* ```userServiceURL``` - the URL of the User Microservice. Note that this URL should also contain the top level path for the service (for example ```/users```).
* ```appsServiceURL``` - the URL of the Apps (Clients) microservice.

Note that in production these URLs are going to point to the URLs exposed by the API Gateway. This is done because in productio environment (or on docker swarm), we're going to have multiple containers (instances) running of each microservice. The actual selection for forwarding the request to the appropriate instance is done by the load balancer on the API Gateway.

## Database Configuration

Section: ```database```

* ```host``` - this is hostname plus port of the MongoDB (e.g. ```localhost:27017```).
* ```database``` - the name of the database.
* ```user``` - user name with access privileges on the database above.
* ```pass``` - password for the user.

## Session Management

Section: ```session```.

* ```name``` - The name of the session key as stored in the users agent cookies.
* ```authKey``` - Auth Key for the session store. Keep this secret.
* ```encryptKey``` - Encryption key. This is the base64 encoded value of the key. The key MUST be **24** or **32** bytes in length when decoded. If not provided, a random key is generated.

The session values kept in the User's agent are encrypted with the Encryption Key. In this way, the user (or an attacker) cannot modify the session content.

If you want to specify your own session encryption key, you can easily generate it like so:

```bash
dd if=/dev/urandom bs=1 count=32 | base64 -
```

Optionally with ```openssl```:
```bash
openssl rand -base64 32
```

## A full ```config.json``` example

```json
{
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
    "virtual_host": "oauth2.auth.jormugandr.org",
    "hosts":["oauth2.auth.jormugandr.org", "localhost"],
    "weight": 10,
    "slots": 5
  },
  "services": {
    "userServiceURL": "http://api.gateway:8081/users",
    "appsServiceURL": "http://api.gateway:8001/apps"
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
}
```

# Generating an access token

This explains the "authorization_code" flow for OAuth2.

Assuming that some user installs an application called EasyData that will publish metadata to its account. This is a web application with domain URL: https://easydata.com .

The user has an account on Jormungandr and wants to use EasyData to publish/store data on Jormungandr.

In order to access the protected API (POST https://api.jormungandr.org/metadata),
the client app (EasyData) must first obtain Access Token.
To do so, it must first create a call to https://api.jormungandr.org/oauth2/authorize .

The application on http://easydata.com redirects the user's browser to:

```
https://api.jormungandr.org/oauth2/authorize?client_id=easy-data-webapp&redirect_uri=https%3A%2F%2Feasydata.com%2Fauthorization%2Fcomplete&response_type=code&scope=api%3Awrite&state=0123456
```

Because the user is not signed in, Jormungandr redirects the user to:

```
https://api.jormungandr.org/login
```
Here the user is shown a login form.

The user enter his/hers email and password and signs in.

Then, Jormungandr redirects the user to:

```
https://api.jormungandr.org/auth/confirm-authorization
```

On this page, the user is asked to authorize the client app to access the resources on Jormungandr.

If the user clicks yes, the result is submitted back and the browser gets redirected again to the authorize URL, only this time the user is already signed in and has authorized the client (EasyData) to publish data to Jormungandr.

At this point the server generates an Authorization Code and redirects the browser back to EasyData:

```
https://easydata.com/authorization/complete?code=ChxkpKeq&state=0123456
```

The redirect_uri of the /authorize is called with two extra parameters:
 * code - the authorization code generated by the server which can be used to obtain an access token
 * state - with the same value of the first call.

 At this point, EasyData has the Authorization Code and can exchange it for an Access Token.

 To do so, it must make a call (POST) to the get_token endpoint on the authorization server:

 ```
 curl -u "easy-data-webapp:super-secret-password" -X POST -d '{"code":"ChxkpKeq","grant_type":"authorization_code","redirect_uri":"http://easydata.com/auth/complete","scope":"api:read"}' "http://localhost:8080/oauth2/token"
 ```

This will issue a new Access Token:
```
{"access_token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJPcmdhbml6YXRpb25zIjpudWxsLCJSb2xlcyI6WyJ1c2VyIl0sIlVzZXJJRCI6IjU5OTQxYzVkMDAwMDAwMDAwMDAwMDAwMCIsIlVzZXJuYW1lIjoicGF2bGUiLCJleHAiOjE1MDc5ODU4OTgsImlhdCI6MTUwNTM5Mzg5OCwiaXNzIjoiSm9ybXVuZ2FuZHIgQXV0aG9yaXphdGlvbiBTZXJ2ZXIiLCJqdGkiOiI5YTlhZDY4My05YTcwLTQyODQtYWZmNS02Nzc3MGJjNjRhMWUiLCJuYmYiOjAsInNjb3BlcyI6ImFwaTpyZWFkIiwic3ViIjoidGVzdC1jbGllbnQtMDAwMDAwMDAwMSJ9.j_oAonZlHawIWfQc-CRsIA7O25Xv-NJZwLkHjHKi8cxbnszZwat8Y9r6LRnDNs8vozmZ9UUUFKk-dvPBfguUxovypiwcGrjb7_hEyVLDN3pWZtgv76oCOK86cvB5CEA2lbEB914dk3ZXCbYVmvEuHes1MJiNAERCBVCgqsnSgIejSSaMK20pdE6MTYzwTP3jQ9BboV0EQEfqnJFynC-uhH6VtjUWw8i0C5k98-BRyAQNFVJXI8ZIcJY03PUknaVefd8GCaRv-Pc5eD1D1wg01CBxt090bo98ZLk7cqtpWrSmySWEEcc6m2zmONY5l3VU1PYYnhG3fI9ctuW73O9ZXQ","expires_in":2592000000,"refresh_token":"5pAIt9xtBHGmGvg4/jSDptrMoSU","token_type":"Bearer"}
```
