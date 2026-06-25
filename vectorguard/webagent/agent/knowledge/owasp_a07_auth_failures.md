# OWASP A07:2021 - Identification and Authentication Failures

This category covers weaknesses in login, session, and credential handling that
let attackers compromise accounts. Reference:
https://owasp.org/Top10/2021/A07_2021-Identification_and_Authentication_Failures/

## Common signals

- Username enumeration: the login endpoint (/login) returns different responses
  for a valid versus invalid username (different message, status, or response
  length), letting an attacker discover valid accounts. Messages like "invalid
  username", "user does not exist", or "no such user" leak account validity.
- Weak lockout / rate limiting: unlimited login attempts enable credential
  stuffing or brute force.
- Weak session handling after login.

## Safe vs unsafe testing

A conservative, defensive check compares responses to a small number of
controlled login attempts to see if valid and invalid usernames are
distinguishable. It does NOT brute force, does NOT spray passwords, and does NOT
use credential lists. Login is a state-changing POST, so it is gated and not run
automatically in safe mode.

## Remediation

- Return a single generic error for any failed login (do not reveal which field
  was wrong).
- Apply rate limiting, progressive delays, and lockout that does not reveal
  account validity.
- Support multi-factor authentication and strong password policies.
