package bearskin

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestUnauthorizedError(t *testing.T) {
	message := "you have no power here!"
	err := UnauthorizedError{Message: message}

	assert.Equal(t, message, err.Error())
}
/*
func TestGetClaimsFromVerifiedJwt(t *testing.T) {
	exp := int64(1909872000)
	userId := "e6186040-6375-42e7-bee0-df9c0b9332c1"
	permissions := []string{
		"user.create",
		"user.read",
		"user.update",
		"user.delete",
	}

	claims, err := GetClaimsFromVerifiedJwt(getPublicKey(), "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE5MDk4NzIwMDAsInVzZXItaWQiOiJlNjE4NjA0MC02Mzc1LTQyZTctYmVlMC1kZjljMGI5MzMyYzEiLCJwZXJtaXNzaW9ucyI6WyJ1c2VyLmNyZWF0ZSIsInVzZXIucmVhZCIsInVzZXIudXBkYXRlIiwidXNlci5kZWxldGUiXX0.GDRkjoHXg2Y2wbBfgxgLB1Ae3RfoN5SKGaea221bVzNWCSojtZm2-WHEdTjuArnmwI2fp0NydkQ7NzFTfYC6FQP5Zxvcy3Ndd2hBH6PqmRbRY8vYT9Vq8N5p0ad_C0CFrw0kRi7iA6HJVffG_9pt_YrGoFXtTR5_g4FP_S5LI3w")

	assert.Nil(t, err)
	assert.Equal(t, exp, claims.ExpiresAt)
	assert.Equal(t, userId, claims.UserID)
	assert.Len(t, claims.Permissions, len(permissions))
	for p := 0; p < len(permissions); p++ {
		//assert.Equal(t, permissions[p], claims.Permissions[p])
	}
}

func TestGetClaimsFromVerifiedJwtWithInvalidPublicKey(t *testing.T) {
	claims, err := GetClaimsFromVerifiedJwt("", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1ODIyMzAwMjAsInVzZXItaWQiOiJkYzdjMTJhNi01Nzk1LTQ1OGItYmIxZS0yYThjNjgwYTFkOWUifQ.AsPpFZriWS_7yyWHBy8fXGUPc4V3JUSDMMrRCkFHWLBIj-Lrn8sIoIlkjgQhpycoJmEUpC5scROGyjnDbtjTjJZSaPR4iasUH8XnJZiA2u8YwStMc0ppuyYmZ4d5Z_wqkgx0_dhM4GerKShU6wbTPE-nRUT8Mivi1uHwHtSvweE")

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
	claims, err := GetClaimsFromVerifiedJwt(getPublicKey(), "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE5MDk4NzIsInVzZXItaWQiOiJlNjE4NjA0MC02Mzc1LTQyZTctYmVlMC1kZjljMGI5MzMyYzEifQ.DtwCv5sUUbBXmEFOnbfE61vpYYM8dqOAQfHgiPPlLH0bAmd8QGbZ0p6qviyanLWAPPxoUpdCv96Onrw0Usl5ZQKwbgP7E2RCXAzQdZkidEctJk_lGN6StLVFsDyZCEoeS6gKWv1xYapapOVDcHjE4MW0J3lEt6Ntvc9UHn2tW8k")

	assert.Nil(t, claims)
	assert.NotNil(t, err)
	assert.IsType(t, UnauthorizedError{}, err)
}

func TestGetClaimsFromVerifiedJwtWithWrongMethod(t *testing.T) {
	claims, err := GetClaimsFromVerifiedJwt(getPublicKey(), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE5MDk4NzIwMDAsInVzZXItaWQiOiJlNjE4NjA0MC02Mzc1LTQyZTctYmVlMC1kZjljMGI5MzMyYzEifQ.cui0YFf_RUuMnkU7QZOa8Ym_knh_50O9tvZr6s8yYLA")

	assert.Nil(t, claims)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "unexpected signing method")
	assert.IsType(t, UnauthorizedError{}, err)
}*/

func TestCheckClaimForPermissionRecursive(t *testing.T) {
	type test struct {
		Name        string
		Permission  *Permissions
		NestedTests map[string]bool
	}

	tests := []test{
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
				"users.create": true,
				"users.create.123.apa": true,
				"users.delete": false,
				"users.delete.apa": false,
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
		"MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgFLwYNEcOHhq4vhbbXT0BU6Z4KYt\n" +
		"73JoUZxKH5EPCkktdkh7bMBfgEr0fCy8ZRn5J+xNrU1IK2x5qajtzdmmd/Jw1kjx\n" +
		"T/I0sNu9sMctFMeX970LSMHks5GAr+kiioPUOLt0aMag4sCsfni5VFGH9mvdxe5U\n" +
		"EaEqjirH6BNikIHRAgMBAAE=\n" +
		"-----END PUBLIC KEY-----\n"
}

/*
https://jwt.io/#debugger-io?token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE5MDk4NzIwMDAsInVzZXItaWQiOiJlNjE4NjA0MC02Mzc1LTQyZTctYmVlMC1kZjljMGI5MzMyYzEiLCJwZXJtaXNzaW9ucyI6WyJ1c2VyLmNyZWF0ZSIsInVzZXIucmVhZCIsInVzZXIudXBkYXRlIiwidXNlci5kZWxldGUiXX0.GDRkjoHXg2Y2wbBfgxgLB1Ae3RfoN5SKGaea221bVzNWCSojtZm2-WHEdTjuArnmwI2fp0NydkQ7NzFTfYC6FQP5Zxvcy3Ndd2hBH6PqmRbRY8vYT9Vq8N5p0ad_C0CFrw0kRi7iA6HJVffG_9pt_YrGoFXtTR5_g4FP_S5LI3w&publicKey=-----BEGIN%20PUBLIC%20KEY-----%0AMIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgFLwYNEcOHhq4vhbbXT0BU6Z4KYt%0A73JoUZxKH5EPCkktdkh7bMBfgEr0fCy8ZRn5J%2BxNrU1IK2x5qajtzdmmd%2FJw1kjx%0AT%2FI0sNu9sMctFMeX970LSMHks5GAr%2BkiioPUOLt0aMag4sCsfni5VFGH9mvdxe5U%0AEaEqjirH6BNikIHRAgMBAAE%3D%0A-----END%20PUBLIC%20KEY-----

Keys that was used to generate tokens:

-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgFLwYNEcOHhq4vhbbXT0BU6Z4KYt
73JoUZxKH5EPCkktdkh7bMBfgEr0fCy8ZRn5J+xNrU1IK2x5qajtzdmmd/Jw1kjx
T/I0sNu9sMctFMeX970LSMHks5GAr+kiioPUOLt0aMag4sCsfni5VFGH9mvdxe5U
EaEqjirH6BNikIHRAgMBAAE=
-----END PUBLIC KEY-----

-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgFLwYNEcOHhq4vhbbXT0BU6Z4KYt73JoUZxKH5EPCkktdkh7bMBf
gEr0fCy8ZRn5J+xNrU1IK2x5qajtzdmmd/Jw1kjxT/I0sNu9sMctFMeX970LSMHk
s5GAr+kiioPUOLt0aMag4sCsfni5VFGH9mvdxe5UEaEqjirH6BNikIHRAgMBAAEC
gYA0Dw22M7B+ZRjyKvEZZ9Gs9Ik9xbd2aGRRZXVK59Xc+Nw1wsMQPOGaKruGmPoc
w3d7q4YL7DDVdcg4cIu1AfhnTMIDUZWHnB+m0V7eG4FH9DvOGmdhvHQCZyFpU15L
zNh1XVdiuhDRwSLv9xGTH6Rv7gKPfDyrmvs5nMl3XIrgAQJBAKK37jRALvlBtrkF
dYeFJfQAk1/YccsLDLwUlMdQ6+ANeZjeWrg2NzcjLMm5nepamUncx57L5qLGn0BC
MvuhA2ECQQCCfEAhYA9lApe4EBbVqIC/Uw2muYW+6YveLE3BPS7vdmukTGM8sNg1
M/Vx70ZHIgxp+bId2NjzrFVQEUoCwIRxAkBYZZmXcyLRsFxmqUuPAst6gfGOCRTQ
nEEf0AJ/QTvS7R8Y5/raxkE6x/Yl5JugW/WYhcNARj8WQNb03sG5p2AhAkAEWCqy
ccZRcKKoiDCacH/I3vUHZgnj71au0P7NvkG/y0uOLtTnAmRQcShs4LCQUbvkE2Iw
yDWA923nuouiR9KhAkEAhzwqufY69opqSLRB0ZNDM+xhedq57e6Sb+dREzHfhlHe
0MUAd+iQMjYntb39A/Vfp52p3B6vI/f7Yw1aDN9pXA==
-----END RSA PRIVATE KEY-----
*/
