package bearskin

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
)

/*
UnauthorizedError is used when the token is invalid, or there was some other error while parsing the claim.
*/
type UnauthorizedError struct {
	Message string
}

func (ue UnauthorizedError) Error() string {
	return ue.Message
}

/*
Claims are the information that is stored inside a token.
If the token was verified correctly, these claims represent the truth.
*/
type Claims struct {
	jwt.StandardClaims
	UserID string `json:"user-id"`
	Permissions []string `json:"permissions"`
}

/*
GetClaimsFromVerifiedJwt will return the claims if the token is valid.
If the token is invalid, nil is returned along with an error.
*/
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
		return nil, UnauthorizedError{Message: err.Error()}
	}

	return token.Claims.(*Claims), nil
}
