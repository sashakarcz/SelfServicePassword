package services

import (
	"ldap-self-service/internal/config"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type AuthService struct {
	config *config.Config
}

type Claims struct {
	Username string `json:"username"`
	DN       string `json:"dn"`
	jwt.RegisteredClaims
}

func NewAuthService(cfg *config.Config) *AuthService {
	return &AuthService{config: cfg}
}

func (s *AuthService) GenerateToken(username, dn string) (string, error) {
	expirationTime := time.Now().Add(time.Duration(s.config.JWT.Expiration) * time.Second)
	
	claims := &Claims{
		Username: username,
		DN:       dn,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.config.JWT.Secret))
}

func (s *AuthService) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.config.JWT.Secret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, jwt.ErrSignatureInvalid
}