package bearskin_test

import (
	"bearskin-validator"
	"github.com/stretchr/testify/assert"
	"testing"
)

// Note: these tests will stop working in 2030-07-10, because of the expiration time.

func TestGetClaimsFromVerifiedJwt(t *testing.T) {
	exp := int64(1909872000)
	userId := "e6186040-6375-42e7-bee0-df9c0b9332c1"

	claims, err := bearskin.GetClaimsFromVerifiedJwt(getPublicKey(), "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE5MDk4NzIwMDAsInVzZXItaWQiOiJlNjE4NjA0MC02Mzc1LTQyZTctYmVlMC1kZjljMGI5MzMyYzEifQ.QubK1QqqVZiZZIyzZgcopubSclAnDflJJfqkL6RRV-1E3hWZ7d6Gj3m8mx7eA1dOA2uMXFj4BG7e0V4VgsRZIIkf6pOqJiXrSVIQzMCBFTTxOjd6VZLV0_LAzmHiDmpTfaSQyNVf-P768O3Z0phZOnh9ykeBfMljZ4P-L1C21Is")

	assert.Nil(t, err)
	assert.Equal(t, exp, claims.ExpiresAt)
	assert.Equal(t, userId, claims.UserId)
}

func TestGetClaimsFromVerifiedJwtWithInvalidPublicKey(t *testing.T) {
	claims, err := bearskin.GetClaimsFromVerifiedJwt("", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1ODIyMzAwMjAsInVzZXItaWQiOiJkYzdjMTJhNi01Nzk1LTQ1OGItYmIxZS0yYThjNjgwYTFkOWUifQ.AsPpFZriWS_7yyWHBy8fXGUPc4V3JUSDMMrRCkFHWLBIj-Lrn8sIoIlkjgQhpycoJmEUpC5scROGyjnDbtjTjJZSaPR4iasUH8XnJZiA2u8YwStMc0ppuyYmZ4d5Z_wqkgx0_dhM4GerKShU6wbTPE-nRUT8Mivi1uHwHtSvweE")

	assert.Nil(t, claims)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "cannot parse public key")
}

func TestGetClaimsFromVerifiedJwtWithInvalidToken(t *testing.T) {
	claims, err := bearskin.GetClaimsFromVerifiedJwt(getPublicKey(), "abc")

	assert.Nil(t, claims)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid token")
}

func TestGetClaimsFromVerifiedJwtWithExpiredToken(t *testing.T) {
	claims, err := bearskin.GetClaimsFromVerifiedJwt(getPublicKey(), "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE5MDk4NzIsInVzZXItaWQiOiJlNjE4NjA0MC02Mzc1LTQyZTctYmVlMC1kZjljMGI5MzMyYzEifQ.DtwCv5sUUbBXmEFOnbfE61vpYYM8dqOAQfHgiPPlLH0bAmd8QGbZ0p6qviyanLWAPPxoUpdCv96Onrw0Usl5ZQKwbgP7E2RCXAzQdZkidEctJk_lGN6StLVFsDyZCEoeS6gKWv1xYapapOVDcHjE4MW0J3lEt6Ntvc9UHn2tW8k")

	assert.Nil(t, claims)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid token")
}

func TestGetClaimsFromVerifiedJwtWithWrongMethod(t *testing.T) {
	claims, err := bearskin.GetClaimsFromVerifiedJwt(getPublicKey(), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE5MDk4NzIwMDAsInVzZXItaWQiOiJlNjE4NjA0MC02Mzc1LTQyZTctYmVlMC1kZjljMGI5MzMyYzEifQ.cui0YFf_RUuMnkU7QZOa8Ym_knh_50O9tvZr6s8yYLA")

	assert.Nil(t, claims)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "unexpected signing method")
	assert.Contains(t, err.Error(), "invalid token")
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
