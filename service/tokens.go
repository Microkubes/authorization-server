package service

import (
	"time"

	"github.com/JormungandrK/authorization-server/config"
	"github.com/JormungandrK/authorization-server/db"
	"github.com/JormungandrK/microservice-security/oauth2"
)

type OAuth2TokenService struct {
	db.TokenRepository
}

func (t *OAuth2TokenService) SaveToken(token oauth2.OAuth2Token) error {
	_, err := t.TokenRepository.Save(&token)
	return err
}

func (t *OAuth2TokenService) GetToken(refreshToken string) (*oauth2.OAuth2Token, error) {
	token, err := t.TokenRepository.GetForRefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}
	if token == nil || isExpired(token) {
		return nil, nil
	}
	return token, nil
}

func (t *OAuth2TokenService) GetTokenForClient(userID, clientID string) (*oauth2.OAuth2Token, error) {
	token, err := t.TokenRepository.GetForClientAndUser(clientID, userID)
	if err != nil {
		return nil, err
	}
	if token == nil || isExpired(token) {
		return nil, nil
	}
	return token, nil
}

func isExpired(token *oauth2.OAuth2Token) bool {
	now := time.Now()
	tokenValidUntil := time.Unix(0, token.IssuedAt).Add(time.Duration(token.ValidFor) * time.Millisecond)
	return now.After(tokenValidUntil)
}

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
