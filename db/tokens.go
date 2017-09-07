package db

import (
	"time"

	"github.com/JormungandrK/microservice-security/oauth2"
	mgo "gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

// TokenRepository defines interface for accessing OAuth2 tokens in a persistence.
type TokenRepository interface {

	// GetForClientAndUser retrieves an AuthToken for a particular user and client.
	GetForClientAndUser(clientID, userID string) (*oauth2.AuthToken, error)

	// GetForRefreshToken retrieves an AuthToken by its refreshToken value.
	GetForRefreshToken(refreshToken string) (*oauth2.AuthToken, error)

	// Save save new AuthToken.
	Save(token *oauth2.AuthToken) (*oauth2.AuthToken, error)
}

// MongoDBTokenRepository holds mongo related values for TokenRepository implementation.
type MongoDBTokenRepository struct {
	collection *mgo.Collection
	tokenTTL   time.Duration
}

// NewTokenRepository creates new TokenRepository that is backed by mongo.
// Note that you need to provide a token TTL. Each token entry in mongo is
// set to expire after this time duration.
func NewTokenRepository(host, dbName, username, password string, tokenTTL time.Duration) (*MongoDBTokenRepository, func(), error) {
	session, err := mgo.DialWithInfo(&mgo.DialInfo{
		Addrs:    []string{host},
		Username: username,
		Password: password,
		Database: dbName,
		Timeout:  30 * time.Second,
	})
	if err != nil {
		return nil, nil, err
	}

	// SetMode - consistency mode for the session.
	session.SetMode(mgo.Monotonic, true)

	collection := session.DB(dbName).C("oauth2-token")
	tokenRepo := &MongoDBTokenRepository{
		collection: collection,
		tokenTTL:   tokenTTL,
	}

	for _, name := range []string{"refreshToken", "clientId", "userId"} {
		err := collection.EnsureIndex(mgo.Index{
			Key:        []string{name},
			Background: true,
			Sparse:     true,
		})
		if err != nil {
			return nil, nil, err
		}
	}

	if err := collection.EnsureIndex(mgo.Index{
		Key:         []string{"issuedAt"},
		Background:  true,
		Sparse:      true,
		ExpireAfter: tokenTTL,
	}); err != nil {
		return nil, nil, err
	}

	return tokenRepo, func() { session.Close() }, nil
}

// GetForClientAndUser retrieves the AuthToken from the backing mongo collection.
func (m *MongoDBTokenRepository) GetForClientAndUser(clientID, userID string) (*oauth2.AuthToken, error) {
	token := oauth2.AuthToken{}
	err := m.collection.Find(bson.M{
		"clientId": clientID,
		"userId":   userID,
	}).One(&token)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// GetForRefreshToken retrieves the AuthToken identified by its refreshToken from the backing mongo collection.
func (m *MongoDBTokenRepository) GetForRefreshToken(refreshToken string) (*oauth2.AuthToken, error) {
	token := oauth2.AuthToken{}
	err := m.collection.Find(bson.M{
		"refreshToken": refreshToken,
	}).One(&token)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// Save saves new AuthToken in the backing mongo collection.
// The token record is automatically removed by Mongo after its token TTL is reached.
func (m *MongoDBTokenRepository) Save(token *oauth2.AuthToken) (*oauth2.AuthToken, error) {
	tokenMap := map[string]interface{}{}
	m.collection.Find(bson.M{
		"userId":   token.UserID,
		"clientId": token.ClientID,
	}).One(tokenMap)
	tokenMap["accessToken"] = token.AccessToken
	tokenMap["refreshToken"] = token.RefreshToken
	tokenMap["issuedAt"] = token.IssuedAt
	tokenMap["validFor"] = int(m.tokenTTL)
	tokenMap["scope"] = token.Scope
	tokenMap["clientId"] = token.ClientID
	tokenMap["userId"] = token.UserID
	if id, ok := tokenMap["_id"]; ok {
		err := m.collection.Update(bson.M{
			"_id": id,
		}, tokenMap)
		if err != nil {
			return nil, err
		}
	} else {
		if err := m.collection.Insert(tokenMap); err != nil {
			return nil, err
		}
	}
	return token, nil
}
