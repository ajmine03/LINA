"""
Pytest configuration and local fixtures.
Provides an isolated local HTTP server for testing without reaching public networks.
"""

import http.server
import socket
import threading
import pytest


class ToyHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self):
        self._handle_response(include_body=False)

    def do_GET(self):
        self._handle_response(include_body=True)

    def _handle_response(self, include_body=True):
        if self.path == "/redirect-internal":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:8080/dashboard")
            self.end_headers()
            return

        if self.path == "/redirect-external":
            self.send_response(302)
            self.send_header("Location", "https://unauthorized-external.com/leak")
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Server", "ToyServer/1.0")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        if include_body:
            self.wfile.write(b"Hello from toy server")

    def log_message(self, format, *args):
        # Silence logging during test runs
        pass


@pytest.fixture(scope="session")
def local_http_server():
    """Runs a local toy HTTP server on an available localhost port."""
    # Find free port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    server = http.server.HTTPServer(("127.0.0.1", port), ToyHTTPHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield f"127.0.0.1:{port}"

    server.shutdown()
