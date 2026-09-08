#!/usr/bin/env python3
"""普通子网验收用的 LAN 服务；不安装客户端、不配置静态回程路由。"""

import argparse
import base64
import hashlib
import http.server
import socket
import ssl
import threading


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "NexoIntegrationTerminal/1.0"

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
        remote = self.client_address[0]
        if self.path == "/ws" and self.headers.get("Upgrade", "").lower() == "websocket":
            self.handle_websocket()
            return
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

    def handle_websocket(self):
        """提供验收用的最小 WebSocket 回显端点。

        终端镜像刻意不安装第三方 WebSocket 库；这里仅实现 RFC 6455
        的握手、文本/二进制帧、Ping/Pong 和关闭帧，足以验证 Caddy
        reverse_proxy 和 Nexo Tunnel 会保留 HTTP Upgrade 长连接。
        """
        key = self.headers.get("Sec-WebSocket-Key")
        version = self.headers.get("Sec-WebSocket-Version")
        if not key or version != "13":
            self.send_error(400, "invalid websocket handshake")
            return
        accept = base64.b64encode(
            hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
            ).digest()
        ).decode()
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        self.wfile.flush()
        while True:
            frame = self.read_websocket_frame()
            if frame is None:
                return
            opcode, payload = frame
            if opcode == 0x8:  # close
                self.write_websocket_frame(0x8, payload[:125])
                return
            if opcode == 0x9:  # ping
                self.write_websocket_frame(0xA, payload[:125])
                continue
            if opcode in (0x1, 0x2):
                self.write_websocket_frame(opcode, payload)

    def read_websocket_frame(self):
        header = self.rfile.read(2)
        if len(header) != 2:
            return None
        first, second = header
        opcode = first & 0x0F
        masked = second & 0x80
        length = second & 0x7F
        if length == 126:
            raw_length = self.rfile.read(2)
            if len(raw_length) != 2:
                return None
            length = int.from_bytes(raw_length, "big")
        elif length == 127:
            raw_length = self.rfile.read(8)
            if len(raw_length) != 8:
                return None
            length = int.from_bytes(raw_length, "big")
        if length > 8 * 1024 * 1024:
            return None
        mask = self.rfile.read(4) if masked else b""
        if masked and len(mask) != 4:
            return None
        payload = self.rfile.read(length)
        if len(payload) != length:
            return None
        if masked:
            payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        return opcode, payload

    def write_websocket_frame(self, opcode, payload):
        length = len(payload)
        if length < 126:
            header = bytes([0x80 | opcode, length])
        elif length <= 0xFFFF:
            header = bytes([0x80 | opcode, 126]) + length.to_bytes(2, "big")
        else:
            header = bytes([0x80 | opcode, 127]) + length.to_bytes(8, "big")
        self.wfile.write(header + payload)
        self.wfile.flush()


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
    args = parser.parse_args()
    threading.Thread(target=serve, args=(args.address, 8800, False), daemon=True).start()
    serve(args.address, 8843, True)


if __name__ == "__main__":
    main()
