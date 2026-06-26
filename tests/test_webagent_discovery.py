"""Bounded same-origin link extraction."""

from __future__ import annotations

from vectorguard.webagent.agent.discovery import extract_links

BODY = """
<html><body>
  <a href="/admin/users">users</a>
  <a href="http://localhost:5000/account">account</a>
  <a href="https://evil.com/steal">offsite</a>
  <a href="mailto:x@y.com">email</a>
  <a href="#frag">frag</a>
  <a href="relative/page">relative</a>
  <img src="/static/logo.png" />
</body></html>
"""


def test_keeps_root_relative_links():
    links = extract_links(BODY, base_url="http://localhost:5000")
    assert "/admin/users" in links
    assert "/static/logo.png" in links


def test_keeps_same_origin_absolute_links_as_paths():
    links = extract_links(BODY, base_url="http://localhost:5000")
    assert "/account" in links


def test_drops_offsite_links():
    links = extract_links(BODY, base_url="http://localhost:5000")
    assert all("evil.com" not in link for link in links)


def test_drops_scheme_and_fragment_links():
    links = extract_links(BODY, base_url="http://localhost:5000")
    assert all(not link.startswith("mailto:") for link in links)
    assert "#frag" not in links
    # bare relative links (no leading slash) are skipped to avoid bad joins
    assert "relative/page" not in links


def test_empty_body_returns_empty():
    assert extract_links("", base_url="http://localhost:5000") == []
