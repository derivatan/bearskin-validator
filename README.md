# bearskin-validator

Bearskin is the name of an authentication service.
It will generate a JWT token with some claims, that can be used by other services to authenticate and authorize users.

This library will provide other services to validate the JWT token without the need of calling the bearskin-service.
This is done by decrypting the JWT token with the public key.


Example:
```
claims, err := bearskin.GetClaimsFromVerifiedJwt(PUBLIC_KEY, JWT_TOKEN)
```

If the JWT token is invalid or there was a problem with the parsing, the `claims` will be `nil`, and an error will be returned.  
If the JWT token is valid, `claims` will be a `bearskin.Claims` struct with the information from the token, and err will be `nil`.
