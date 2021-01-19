package bearskin

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

// Note: some of these test will fail after 2029-12-31: 23:59:59 (1893455999), because of the expiredate on the token

func TestUnauthorizedError(t *testing.T) {
	message := "you have no power here!"
	err := UnauthorizedError{Message: message}

	assert.Equal(t, message, err.Error())
}

func TestGetClaimsFromVerifiedJwt(t *testing.T) {
	exp := int64(1893455999)
	userID := "73b461c4-dbe3-4430-b8fb-a7611394c9e1"
	token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE4OTM0NTU5OTksInVzZXItaWQiOiI3M2I0NjFjNC1kYmUzLTQ0MzAtYjhmYi1hNzYxMTM5NGM5ZTEiLCJwZXJtaXNzaW9ucyI6eyJuIjp7InVzZXJzIjp7Im4iOnsiKiI6eyJwIjp0cnVlfSwiZGVsZXRlIjp7fX19fX19.Uqz2x8guhGj3bzCKFlIasAQntIRFUyAbrREnrtWy-1Tu3kcxvNfA4Gx722Ke-w2sg45udZvlCt8NGDxAXhbt0pYGCLmPfP97woRfns4mlQjdOMS53AWihXHVzwPJDLc3Eh1uxRSBL-J9ffdkkHZx-k7F6ju0LQGSnT-6T7GMYTk"
	permissions := &Permissions{Next: map[string]*Permissions{
		"users": {Next: map[string]*Permissions{
			"*": {Permit: true},
			"delete": {Permit: false},
		}},
	}}

	claims, err := GetClaimsFromVerifiedJwt(getPublicKey(), token)

	assert.Nil(t, err)
	assert.Equal(t, exp, claims.ExpiresAt)
	assert.Equal(t, userID, claims.UserID)
	assert.Len(t, claims.Permissions.Next, len(permissions.Next))
	assert.Equal(t, claims.Permissions.Next["users"].Next["*"], permissions.Next["users"].Next["*"])
	assert.Equal(t, claims.Permissions.Next["users"].Next["delete"], permissions.Next["users"].Next["delete"])
}

func TestGetClaimsFromVerifiedJwtWithInvalidPublicKey(t *testing.T) {
	token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1ODIyMzAwMjAsInVzZXItaWQiOiJkYzdjMTJhNi01Nzk1LTQ1OGItYmIxZS0yYThjNjgwYTFkOWUifQ.AsPpFZriWS_7yyWHBy8fXGUPc4V3JUSDMMrRCkFHWLBIj-Lrn8sIoIlkjgQhpycoJmEUpC5scROGyjnDbtjTjJZSaPR4iasUH8XnJZiA2u8YwStMc0ppuyYmZ4d5Z_wqkgx0_dhM4GerKShU6wbTPE-nRUT8Mivi1uHwHtSvweE"
	claims, err := GetClaimsFromVerifiedJwt("", token)

	assert.Nil(t, claims)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "cannot parse public key")
}

func TestGetClaimsFromVerifiedJwtWithInvalidToken(t *testing.T) {
	claims, err := GetClaimsFromVerifiedJwt(getPublicKey(), "abc")

	assert.Nil(t, claims)
	assert.NotNil(t, err)
	assert.IsType(t, UnauthorizedError{}, err)
}

func TestGetClaimsFromVerifiedJwtWithExpiredToken(t *testing.T) {
	token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MTA2NTk3MzIsInVzZXItaWQiOiI3M2I0NjFjNC1kYmUzLTQ0MzAtYjhmYi1hNzYxMTM5NGM5ZTEiLCJwZXJtaXNzaW9ucyI6eyJuIjp7InVzZXJzIjp7Im4iOnsiKiI6eyJwIjp0cnVlfSwiZGVsZXRlIjp7fX19fX19.DTv4IH-ZlpgjZ0DRJcmUc4MkjCPOlcu53FHtpq7T10XICY4bo27RKINrMZqzDZd1ENTlGS_HZOpPPVh92UBcMq4T6TfTCpecK47SsXjBgMws9pLiGX84sWtUpgsdqxS7QrQ6fIoVicvlrRftxWLLRf0fC3SrVWy_4yNCPdqs6t4"
	claims, err := GetClaimsFromVerifiedJwt(getPublicKey(), token)

	assert.Nil(t, claims)
	assert.NotNil(t, err)
	assert.IsType(t, UnauthorizedError{}, err)
}
func TestGetClaimsFromVerifiedJwtWithWrongMethod(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE4OTM0NTU5OTksInVzZXItaWQiOiI3M2I0NjFjNC1kYmUzLTQ0MzAtYjhmYi1hNzYxMTM5NGM5ZTEiLCJwZXJtaXNzaW9ucyI6eyJuIjp7InVzZXJzIjp7Im4iOnsiKiI6eyJwIjp0cnVlfSwiZGVsZXRlIjp7fX19fX19.m0-vicb6JYYn_PK7Rire9ryjZt5AYoydbwDX8gtK2uE"
	claims, err := GetClaimsFromVerifiedJwt(getPublicKey(), token)

	assert.Nil(t, claims)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "unexpected signing method")
	assert.IsType(t, UnauthorizedError{}, err)
}

func TestCheckClaimForPermissionRecursive(t *testing.T) {
	type test struct {
		Name        string
		Permission  *Permissions
		NestedTests map[string]bool
	}

	tests := []test{
		{
			Name: "empty permissions",
			Permission: nil,
			NestedTests: map[string]bool{
				"": false,
				"users": false,
			},
		},
		{
			Name: "empty permissions",
			Permission: &Permissions{Permit: false},
			NestedTests: map[string]bool{
				"": false,
				"users": false,
			},
		},
		{
			Name: "create users, dont delete",
			Permission: &Permissions{Next: map[string]*Permissions{
				"users": {Next: map[string]*Permissions{
					"create": {Permit: true},
					"delete": {Permit: false},
				}},
			}},
			NestedTests: map[string]bool{
				"other.create": false,
				"users": false,
				"users.create": true,
				"users.create.1": false,
				"users.create.true": false,
				"users.delete": false,
				"users.read": false,
			},
		},
		{
			Name: "All user, except delete",
			Permission: &Permissions{Next: map[string]*Permissions{
				"users": {Next: map[string]*Permissions{
					"*": {Permit: true},
					"delete": {Permit: false},
				}},
			}},
			NestedTests: map[string]bool{
				"users.*": true,
				"users": false,
				"users.create": true,
				"users.create.123.apa": true,
				"users.delete": false,
				"users.delete.apa": false,
				"permissions.read": false,
			},
		},
	}

	for _, test := range tests {
		for permission, expected := range test.NestedTests {
			result := checkClaimForPermissionRecursive(test.Permission, permission)

			assert.Equal(t, expected, result, fmt.Sprintf("%s: %s", test.Name, permission))
		}
	}
}

func getPublicKey() string {
	return "-----BEGIN PUBLIC KEY-----\n" +
		"MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgGrOE4UxkwIRkIDkAfwTKqJMHh6d\n" +
		"spQO9vK9n2dk54/q7i+hwFfBah34rwYb/DJ7Gf8nscR/ay6bLCo88r9QogpP0YB4\n" +
		"wDKijRSgtoUWdKyuePX2oBihfIZfrdJgpTNn5NWocKY854bBOKGReLUbMaYJWCjg\n" +
		"qOXXSIVwsam3ysrnAgMBAAE=\n" +
		"-----END PUBLIC KEY-----\n"
}
