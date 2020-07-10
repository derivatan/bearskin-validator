package bearskin

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
)

type Claims struct {
	jwt.StandardClaims
	UserId string `json:"user-id"`
}

func GetClaimsFromVerifiedJwt(publicKey, tokenString string) (*Claims, error) {
	verifyKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(publicKey))
	if err != nil {
		return nil, fmt.Errorf("cannot parse public key: %v", err)
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return verifyKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token: %v", err)
	}

	return token.Claims.(*Claims), nil
}
