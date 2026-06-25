# OWASP A03:2021 - Injection (SQL Injection focus)

Injection occurs when untrusted input is sent to an interpreter as part of a
command or query. SQL injection is the classic case: user input is concatenated
into a SQL statement and changes its meaning. Reference:
https://owasp.org/Top10/2021/A03_2021-Injection/

## Common signals

- Error-based: a single quote in a query parameter (for example
  /filter?category=') triggers a database error or HTTP 500. Error text such as
  "SQL syntax", "SQLSTATE", "unclosed quotation", "you have an error in your SQL",
  "ORA-", or "psqlexception" strongly suggests the input reaches a SQL query.
- Differential responses: changing the input meaningfully changes the response
  length or status in ways that track the query logic.

## Safe vs unsafe testing

A safe, defensive probe sends one benign metacharacter (a single quote) in one
parameter and looks for an error signature. It does NOT extract data, does NOT
use boolean/time-based blind techniques, and does NOT run destructive payloads.

## Remediation

- Use parameterized queries / prepared statements for all database access.
- Never build SQL by concatenating untrusted input.
- Apply least-privilege database accounts and input validation.
- Return generic error pages; do not leak database errors to clients.
