from __future__ import annotations

import ipaddress
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


MAX_HTML_BYTES = 64 * 1024 * 1024


def make_server(path, listen="127.0.0.1", port=8765):
    address = ipaddress.ip_address(listen)
    if address.version != 4:
        raise ValueError("Use an IPv4 listen address for this viewer server")
    if not 0 <= port <= 65535:
        raise ValueError("Port must be between 0 and 65535")
    source = Path(path)
    if source.is_symlink() or source.suffix.lower() != ".html":
        raise ValueError("Serve requires a regular .html viewer file, not a symlink")
    with source.open("rb") as handle:
        content = handle.read(MAX_HTML_BYTES + 1)
    if len(content) > MAX_HTML_BYTES:
        raise ValueError("Viewer exceeds the 64 MiB serving limit")
    token = secrets.token_urlsafe(32)
    route = "/" + token + "/"

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self._respond(False)

        def do_HEAD(self):
            self._respond(True)

        def _respond(self, head):
            try:
                host = urlsplit("http://" + self.headers.get("Host", "")).hostname
                if host != "localhost":
                    requested = ipaddress.ip_address(host)
                    if not address.is_unspecified and requested != address:
                        raise ValueError("wrong host")
                elif not (address.is_loopback or address.is_unspecified):
                    raise ValueError("wrong host")
            except (ValueError, TypeError):
                self.send_error(421)
                return
            if self.path not in (route, route + "index.html"):
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            if not head:
                self.wfile.write(content)

        def log_message(self, *args):
            pass  # Do not log viewer access tokens or request paths.

    server = ThreadingHTTPServer((listen, port), Handler)
    server.daemon_threads = True
    display_host = "127.0.0.1" if address.is_unspecified else listen
    server.viewer_url = f"http://{display_host}:{server.server_port}{route}"
    return server


def serve_viewer(path, listen="127.0.0.1", port=8765, open_browser=False):
    import webbrowser
    with make_server(path, listen, port) as server:
        print(f"UI: {server.viewer_url}", flush=True)
        print("Only this HTML is served. Keep its access-token URL private. Ctrl+C stops the server.", flush=True)
        if not ipaddress.ip_address(listen).is_loopback:
            print(f"Listening on {listen}; for another device, use this host's IP with the same port and token path.", flush=True)
            print("Remote access uses plain HTTP. Use a trusted network or an SSH tunnel; this is not a public web deployment.", flush=True)
        if open_browser:
            try:
                if not webbrowser.open(server.viewer_url):
                    print("Browser unavailable. Open the printed URL on this machine.")
            except (OSError, webbrowser.Error):
                print("Browser unavailable. Open the printed URL on this machine.")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("Viewer server stopped.")
