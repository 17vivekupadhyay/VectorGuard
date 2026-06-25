# JWT and Session Review

JSON Web Tokens (JWT) are widely used for sessions and authorization. Many JWT
problems come from weak server-side validation rather than the token format
itself. Reference: https://portswigger.net/web-security/jwt

## Common signals

- JWT-shaped values appear in responses or cookies. A JWT's base64url header
  begins with "eyJ" (for example eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...). Seeing
  a token in a /my-account page or session cookie is worth an informational note.
- The server accepts "alg":"none" or unexpected signing algorithms.
- The signature is not verified, or expiration/issuer/audience are not checked.

## Safe vs unsafe testing

The defensive MVP check is informational only: it flags that a JWT-shaped token
is present so a human can review server-side validation. It does NOT tamper with
tokens, strip signatures, or attempt algorithm-confusion attacks.

## Remediation

- Verify the JWT signature server-side with a strong, secret key.
- Reject "alg":"none" and any algorithm you do not expect.
- Validate expiration (exp), issuer (iss), audience (aud), and required claims.
- Do not expose raw tokens in response bodies; scope and rotate signing secrets.
