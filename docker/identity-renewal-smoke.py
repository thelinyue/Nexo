#!/usr/bin/env python3
"""复用 Tunnel 真进程验收，使用临时 CA 签发临近续签窗口的证书；额外需要 cryptography。"""
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import sqlite3
import ssl
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

spec = importlib.util.spec_from_file_location("tunnel_smoke", Path(__file__).with_name("tunnel-smoke.py"))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


def near_renewal(pem, authority):
    source = x509.load_pem_x509_certificate(pem.encode())
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(source.subject).issuer_name(source.issuer)
                   .public_key(source.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - datetime.timedelta(minutes=5))
                   .not_valid_after(now + datetime.timedelta(days=30, seconds=10)))
    for extension in source.extensions:
        certificate = certificate.add_extension(extension.value, extension.critical)
    key = serialization.load_pem_private_key(authority["ca_key"].encode(), password=None)
    return certificate.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()


class RenewalHarness(smoke.Harness):
    def before_restart(self, device, tcp, secure):
        before_services = self.api("tunnels")
        self.agent.terminate()
        self.agent.wait(timeout=10)
        self.stop_server()
        server_path = self.root / "server/transport/identity.json"
        agent_path = self.root / "agent/identity.json"
        authority = json.loads(server_path.read_text())
        agent = json.loads(agent_path.read_text())
        authority["server_pem"] = near_renewal(authority["server_pem"], authority)
        agent["certificate_pem"] = near_renewal(agent["certificate_pem"], authority)
        old_server = authority["server_pem"]
        old_agent = agent["certificate_pem"]
        server_path.write_text(json.dumps(authority))
        agent_path.write_text(json.dumps(agent))
        der = x509.load_pem_x509_certificate(old_agent.encode()).public_bytes(serialization.Encoding.DER)
        with sqlite3.connect(self.root / "server/nexo.db") as db:
            db.execute("UPDATE device_identities SET secret_digest=? WHERE device_id=?", (hashlib.sha256(der).hexdigest(), device))
            db.execute("UPDATE device_certificates SET certificate_pem=? WHERE device_id=?", (old_agent, device))
        # 以目录占用原子写入的临时文件，制造可恢复的真实磁盘写入失败。
        blocked = agent_path.with_suffix(".tmp")
        blocked.mkdir()
        self.start_server()
        self.start_agent()
        smoke.wait_for(lambda: self.ready(tcp["id"]), "续签前恢复数据连接")
        with socket.create_connection(("127.0.0.1", self.ports["public"]), timeout=5) as active:
            active.sendall(b"before-renewal")
            assert active.recv(100) == b"before-renewal"

            def failure():
                return next((row for row in self.api("devices") if row["id"] == device and row["certificate"]["status"] == "retry_wait"), None)
            failed = smoke.wait_for(failure, "设备续签写盘失败提醒")
            retry_at = failed["certificate"]["next_retry_at"]
            assert retry_at > time.time()
            assert "续签失败" in failed["certificate"]["error"]
            assert json.loads(agent_path.read_text())["certificate_pem"] == old_agent
            blocked.rmdir()
            self.check("真实写盘失败保留原身份，API 显示错误、到期时间和下次重试")

            def renewed():
                current = json.loads(agent_path.read_text())
                return current if current["certificate_pem"] != old_agent else None
            current = smoke.wait_for(renewed, "设备自动重试并续签", timeout=90)
            assert time.time() >= retry_at
            assert current["device_id"] == device
            assert current["key_pem"] != agent["key_pem"]
            assert current["ca_pem"] == agent["ca_pem"]
            assert current["pending_key"] is None
            smoke.wait_for(lambda: any(row["id"] == device and row["certificate"]["status"] == "valid" and not row["certificate"]["error"] for row in self.api("devices")), "安装确认更新证书状态")
            active.sendall(b"after-agent-renewal")
            assert active.recv(100) == b"after-agent-renewal"
            self.check("设备提前续签并更换私钥，ID 与原有 TCP 长连接保持不变")

            smoke.wait_for(lambda: json.loads(server_path.read_text())["server_pem"] != old_server, "服务端证书自动续签", timeout=90)
            updated = json.loads(server_path.read_text())
            assert updated["ca_pem"] == authority["ca_pem"]
            context = ssl.create_default_context(cadata=current["ca_pem"])
            certificate, key = self.root / "renewed.crt", self.root / "renewed.key"
            certificate.write_text(current["certificate_pem"])
            key.write_text(current["key_pem"])
            context.load_cert_chain(certificate, key)
            with socket.create_connection(("127.0.0.1", self.ports["control"]), timeout=5) as raw:
                with context.wrap_socket(raw, server_hostname="nexo-server") as stream:
                    actual = stream.getpeercert(binary_form=True)
                    expected = x509.load_pem_x509_certificate(updated["server_pem"].encode()).public_bytes(serialization.Encoding.DER)
                    assert actual == expected, "新握手仍在使用旧服务端证书"
            active.sendall(b"after-server-renewal")
            assert active.recv(100) == b"after-server-renewal"
            self.check("服务端证书热更新，新握手使用新证书，CA 和现有连接保持不变")
        after_services = self.api("tunnels")
        assert [(s["id"],s["device_id"],s["apply_revision"]) for s in before_services] == [(s["id"],s["device_id"],s["apply_revision"]) for s in after_services]
        assert len(self.api("devices")) == 1
        self.check("续签未新增设备，服务 ID、绑定和配置版本全部保留")


if __name__ == "__main__":
    smoke.Harness = RenewalHarness
    smoke.main()
