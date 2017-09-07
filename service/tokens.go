package service

import (
	"time"

	"github.com/JormungandrK/authorization-server/config"
	"github.com/JormungandrK/authorization-server/db"
	"github.com/JormungandrK/microservice-security/oauth2"
)

// OAuth2TokenService hold the data for implementation of oauth2.TokenService.
type OAuth2TokenService struct {

	// TokenRepository is the db.TokenRepository for persisting the oauth2 tokens.
	db.TokenRepository
}

// SaveToken saves the token in the underlying token repositry.
func (t *OAuth2TokenService) SaveToken(token oauth2.AuthToken) error {
	_, err := t.TokenRepository.Save(&token)
	return err
}

// GetToken retrieves a token from the underlying token repository.
// The token is checked if it is expired.
func (t *OAuth2TokenService) GetToken(refreshToken string) (*oauth2.AuthToken, error) {
	token, err := t.TokenRepository.GetForRefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}
	if token == nil || isExpired(token) {
		return nil, nil
	}
	return token, nil
}

// GetTokenForClient retrieves a token for the client and user from the token repository.
// The token is checked if it is expired.
func (t *OAuth2TokenService) GetTokenForClient(userID, clientID string) (*oauth2.AuthToken, error) {
	token, err := t.TokenRepository.GetForClientAndUser(clientID, userID)
	if err != nil {
		return nil, err
	}
	if token == nil || isExpired(token) {
		return nil, nil
	}
	return token, nil
}

func isExpired(token *oauth2.AuthToken) bool {
	now := time.Now()
	tokenValidUntil := time.Unix(0, token.IssuedAt).Add(time.Duration(token.ValidFor) * time.Millisecond)
	return now.After(tokenValidUntil)
}

// NewTokenService creates new oauth2.TokenService from a given ServerConfig.
func NewTokenService(serverConfig *config.ServerConfig) (*OAuth2TokenService, func(), error) {
	dbc := serverConfig.DBConfig
	tokenRepository, cleanup, err := db.NewTokenRepository(dbc.Host, dbc.DatabaseName, dbc.Username, dbc.Password, time.Duration(serverConfig.AccessTokenTTL)*time.Millisecond)
	if err != nil {
		return nil, nil, err
	}
	return &OAuth2TokenService{
		TokenRepository: tokenRepository,
	}, cleanup, nil
}
