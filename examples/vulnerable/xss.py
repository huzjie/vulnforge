"""Deliberately vulnerable example: reflected XSS (CWE-79).

Illustrates unsanitised user input rendered into HTML without escaping.
"""
from http.server import BaseHTTPRequestHandler


class CommentHandler(BaseHTTPRequestHandler):
    """Echoes user input straight back into an HTML page — vulnerable to XSS."""

    def do_GET(self) -> None:  # noqa: N802 - stdlib override
        name = self.path.split("name=")[-1]
        # vulnforge-static: xss
        body = "<h1>Hello, " + name + "</h1>"
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))


def render_profile(username: str) -> str:
    """Naive template helper that does not escape HTML entities."""
    # vulnforge-static: xss
    return "<div class='user'>" + username + "</div>"
