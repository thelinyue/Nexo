#!/usr/bin/env python3
"""Site-to-Site 验收用的普通 LAN 终端；不依赖 Nexo/Tailscale。"""

import argparse
import http.server
import ipaddress
import socket
import ssl
import subprocess
import threading


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "NexoIntegrationTerminal/1.0"

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
        remote = self.client_address[0]
        if self.path == "/source":
            body = f"source={remote}\n".encode()
        elif self.path == "/large":
            body = (b"nexo-site-to-site-" * 524288)[:8 * 1024 * 1024]
        else:
            body = f"terminal={self.server.bind_address}\nsource={remote}\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        print(f"request path={self.path} source={remote}", flush=True)

    def log_message(self, _format, *_args):
        return


def serve(address: str, port: int, tls: bool):
    server = http.server.ThreadingHTTPServer(("0.0.0.0", port), Handler)
    server.bind_address = address
    if tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(
            "/etc/ssl/certs/nexo-terminal.crt", "/etc/ssl/private/nexo-terminal.key"
        )
        server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"listening address={address} port={port} tls={tls}", flush=True)
    server.serve_forever()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--address", required=True)
    parser.add_argument("--remote-prefix", required=True)
    parser.add_argument("--next-hop", required=True)
    args = parser.parse_args()
    ipaddress.ip_network(args.remote_prefix)
    subprocess.run(
        ["ip", "route", "replace", args.remote_prefix, "via", args.next_hop],
        check=True,
    )
    print(
        f"static route installed destination={args.remote_prefix} next_hop={args.next_hop}",
        flush=True,
    )
    threading.Thread(target=serve, args=(args.address, 8080, False), daemon=True).start()
    serve(args.address, 8443, True)


if __name__ == "__main__":
    main()
