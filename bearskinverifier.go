package bearskin

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"strings"
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

Permissions is a nested map, with arbitrary depths, with strings for keys and a bool as value.
This could be explained by the Backus–Naur form: `Permissions = map[string]Permissions | bool`
The ending bool represent weather you
*/
type Claims struct {
	jwt.StandardClaims
	UserID      string       `json:"user-id"`
	Permissions *Permissions `json:"permissions"`
}

/*
Permissions should contain either a Permit or the Next permissions.
The Permit property should only considered if the map is nil.
*/
type Permissions struct {
	Next   map[string]*Permissions `json:"n,omitempty"`
	Permit bool                    `json:"p,omitempty"`
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

/*
CheckClaimForPermission is just a shortcut to be able to recurse over the other function.
*/
func CheckClaimForPermission(claims *Claims, permission string) bool {
	return checkClaimForPermissionRecursive(claims.Permissions, permission)
}

/*
checkClaimForPermissionRecursive does stuff.
 */
func checkClaimForPermissionRecursive(permissions *Permissions, permission string) bool {
	if permissions == nil {
		return false
	}
	if permissions.Next == nil && permission == "" {
		return permissions.Permit
	}
	var star bool
	parts := strings.SplitN(permission, ".", 2)
	if len(parts) > 0 {
		_, star = permissions.Next["*"]
		val, ok := permissions.Next[parts[0]]
		rest := ""
		if len(parts) > 1 {
			rest = parts[1]
		}
		if ok {
			return checkClaimForPermissionRecursive(val, rest)
		} else if parts[0] != "" {
			return star
		}
	}
	return false
}

/*
CheckPermission will checks a token if it contains a given permission.
*/
func CheckPermission(publicKey, tokenString, permission string) bool {
	claims, err := GetClaimsFromVerifiedJwt(publicKey, tokenString)
	if err != nil {
		return false
	}

	result := CheckClaimForPermission(claims, permission)

	return result
}
