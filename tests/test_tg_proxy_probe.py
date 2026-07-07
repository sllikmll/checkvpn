from __future__ import annotations

import struct
from dataclasses import dataclass, field

from app.models import CheckStatus
from app.tg_proxy_probe import (
    TgProxyProbeBackend,
    build_mtproto_obfuscated_client_handshake,
    decrypt_mtproto_frame,
    encrypt_mtproto_frame,
    encrypt_mtproto_server_frame,
    probe_tg_proxy_uri,
)


TG_URI = "tg://proxy?server=telegram.example.com&port=443&secret=00112233445566778899aabbccddeeff"


@dataclass
class FakeSocket:
    secret: bytes
    handshake: bytes | None = None
    writes: list[bytes] = field(default_factory=list)
    recv_chunks: list[bytes] = field(default_factory=list)
    closed: bool = False
    timeout: float | None = None
    auto_respond: bool = True

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def sendall(self, data: bytes) -> None:
        self.writes.append(data)
        if self.handshake is None:
            self.handshake = data
            return
        if len(self.writes) == 2 and self.auto_respond:
            payload = b"\x00" * 8 + struct.pack("<q", 1729382256910270464) + struct.pack("<i", 4) + b"pong"
            encrypted = encrypt_mtproto_server_frame(self.handshake, self.secret, payload)
            self.recv_chunks.append(encrypted)

    def recv(self, n: int) -> bytes:
        if self.recv_chunks:
            chunk = self.recv_chunks[0][:n]
            self.recv_chunks[0] = self.recv_chunks[0][n:]
            if not self.recv_chunks[0]:
                self.recv_chunks.pop(0)
            return chunk
        raise TimeoutError("timed out")

    def close(self) -> None:
        self.closed = True


@dataclass
class FakeBackend(TgProxyProbeBackend):
    sock: FakeSocket = field(default_factory=lambda: FakeSocket(bytes.fromhex("00112233445566778899aabbccddeeff")))

    def create_connection(self, host: str, port: int, timeout: float):
        return self.sock

    def resolve_host(self, host: str) -> list[str]:
        return ["203.0.113.20"]

    def monotonic(self) -> float:
        self._t = getattr(self, "_t", 0.0) + 0.25
        return self._t

    def time(self) -> int:
        return 1_720_000_000

    def urandom(self, n: int) -> bytes:
        return bytes((i % 251) + 1 for i in range(n))


def test_probe_tg_proxy_reports_online_for_mtproto_data_path():
    backend = FakeBackend()

    outcome = probe_tg_proxy_uri(TG_URI, backend=backend, dc_id=2)

    assert outcome.status is CheckStatus.ONLINE
    assert outcome.stage == "usable_connectivity"
    assert outcome.details["host"] == "telegram.example.com"
    assert outcome.details["port"] == 443
    assert outcome.details["dc_id"] == 2
    assert outcome.details["resolved_ips"] == ["203.0.113.20"]
    assert outcome.details["response_len"] == 24
    assert outcome.latency_ms is not None
    assert len(backend.sock.writes) == 2
    assert len(backend.sock.writes[0]) == 64
    assert backend.sock.closed is True


def test_probe_tg_proxy_reports_offline_when_no_mtproto_response_arrives():
    backend = FakeBackend()
    backend.sock.auto_respond = False
    backend.sock.recv_chunks = []

    outcome = probe_tg_proxy_uri(TG_URI, backend=backend, dc_id=2)

    assert outcome.status is CheckStatus.OFFLINE
    assert outcome.stage == "mtproto_response"
    assert "no mtproto response" in outcome.summary.lower()


def test_mtproto_handshake_encrypts_and_decrypts_payload_roundtrip():
    secret = bytes.fromhex("00112233445566778899aabbccddeeff")
    handshake = build_mtproto_obfuscated_client_handshake(secret, dc_id=2, wall_time=1_720_000_000, random_bytes=bytes(range(1, 65)))
    payload = b"\x00" * 8 + struct.pack("<q", 1729382256910270464) + struct.pack("<i", 4) + b"pong"

    encrypted = encrypt_mtproto_server_frame(handshake, secret, payload)
    decrypted = decrypt_mtproto_frame(handshake, secret, encrypted)

    assert decrypted == payload
