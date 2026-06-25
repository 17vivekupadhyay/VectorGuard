# Cross-Site Request Forgery (CSRF)

CSRF tricks an authenticated user's browser into sending a state-changing request
they did not intend, abusing the fact that the browser automatically attaches
session cookies. Reference:
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery

## Common signals

- A state-changing action (for example POST /my-account/change-email, change
  password, or update profile) succeeds without an unpredictable, per-session
  CSRF token.
- Session cookies are missing SameSite protection.
- The server accepts the request based only on the session cookie.

## Safe vs unsafe testing

CSRF testing targets a state-changing POST, so it is gated. In the VectorGuard
Web Agent it is planned and explained but not executed in safe mode (the runner
is GET-only). The check is whether the action requires and validates a CSRF token.

## Remediation

- Require a per-session, unpredictable CSRF token on all state-changing requests
  and validate it server-side.
- Set SameSite=Lax or Strict on session cookies.
- Consider re-authentication or origin/referer checks for sensitive actions.
