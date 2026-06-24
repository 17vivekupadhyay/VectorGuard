"""
VectorGuard Web Agent - local intentionally-vulnerable demo app.

⚠️  INTENTIONALLY VULNERABLE. LOCAL USE ONLY. DO NOT DEPLOY PUBLICLY.

This tiny Flask app exists only so you can exercise VectorGuard Web Agent
end-to-end against a known, owned, local target. The "vulnerabilities" here are
faked responses (no real database, no real auth) so the scanner's safe GET
checks have something to detect.

Run:
    python3 examples/web_demo_app/app.py

Then scan it with the commands in this folder's README.md.
"""

from __future__ import annotations

from flask import Flask, Response, request

app = Flask(__name__)

# A deliberately JWT-shaped (but fake, unsigned-looking) token for the
# informational JWT/session shape check. It is not a real credential.
FAKE_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJkZW1vIiwicm9sZSI6InVzZXIifQ."
    "ZmFrZS1kZW1vLXNpZ25hdHVyZQ"
)


@app.get("/")
def home() -> str:
    return (
        "<html><body>"
        "<h1>VectorGuard Demo Shop</h1>"
        "<p>Intentionally vulnerable, local-only demo app.</p>"
        "<ul>"
        '<li><a href="/admin">/admin</a></li>'
        '<li><a href="/filter?category=Gifts">/filter?category=Gifts</a></li>'
        '<li><a href="/my-account">/my-account</a></li>'
        "</ul>"
        "</body></html>"
    )


@app.get("/admin")
def admin() -> str:
    # Intentionally missing access control: serves admin content to anyone.
    return (
        "<html><body>"
        "<h1>Admin Panel</h1>"
        "<p>Welcome, administrator.</p>"
        "<ul>"
        "<li>delete user</li>"
        "<li>user management</li>"
        "</ul>"
        "</body></html>"
    )


@app.get("/filter")
def filter_products() -> Response:
    category = request.args.get("category", "")

    # Intentionally "vulnerable": a single quote breaks the fake query and
    # leaks a database-style error with a 500. No real database is involved.
    if "'" in category:
        body = (
            "<html><body>"
            "<h1>500 Internal Server Error</h1>"
            "<pre>You have an error in your SQL syntax; check the manual "
            "near \"'\" at line 1</pre>"
            "</body></html>"
        )
        return Response(body, status=500, mimetype="text/html")

    body = (
        "<html><body>"
        f"<h1>Products in {category or 'All'}</h1>"
        "<ul><li>Gift Card</li><li>Mug</li><li>Sticker Pack</li></ul>"
        "</body></html>"
    )
    return Response(body, status=200, mimetype="text/html")


@app.get("/my-account")
def my_account() -> Response:
    body = (
        "<html><body>"
        "<h1>My Account</h1>"
        "<p>Signed in as demo user.</p>"
        f"<p>session token: {FAKE_JWT}</p>"
        "</body></html>"
    )
    response = Response(body, status=200, mimetype="text/html")
    # Demo-only fake cookie; redacted by the scanner's evidence capture.
    response.headers["Set-Cookie"] = f"session={FAKE_JWT}; Path=/"
    return response


if __name__ == "__main__":
    # Bind to localhost only. This app must never be exposed publicly.
    app.run(host="127.0.0.1", port=5000)
