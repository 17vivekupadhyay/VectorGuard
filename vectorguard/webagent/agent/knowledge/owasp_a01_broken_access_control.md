# OWASP A01:2021 - Broken Access Control

Broken access control happens when an application does not properly enforce who is
allowed to access a resource or action. It is the most common web application
risk. Reference: https://owasp.org/Top10/2021/A01_2021-Broken_Access_Control/

## Common signals

- Forced browsing: an admin route such as /admin, /admin/users, or
  /user-management returns 200 and admin content (for example "Admin Panel",
  "delete user", "user management") to an unauthenticated or low-privilege user.
- Insecure direct object reference (IDOR): changing an id in a URL or parameter
  returns another user's data.
- Missing function-level authorization: privileged actions are reachable just by
  knowing the URL, relying on hidden frontend links instead of server checks.

## What a safe check looks like

A defensive, read-only check is a single GET to a suspected admin route and
inspecting the status code and body for admin-only keywords. It does not modify
state and does not attempt privilege escalation.

## Remediation

- Enforce authorization on the server for every privileged route and action.
- Deny by default; grant access explicitly per role.
- Do not rely on hidden links, client-side checks, or obscurity.
- Re-check ownership on every object access (prevent IDOR).
