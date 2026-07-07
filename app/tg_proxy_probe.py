from __future__ import annotations

import hashlib
import socket
import struct
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from app.checkers.base import CheckOutcome
from app.models import CheckStatus, Protocol
from app.netutils import resolve_host
from app.parsers import parse_target_config


HANDSHAKE_LEN = 64
SKIP_LEN = 8
PREKEY_LEN = 32
KEY_LEN = 32
IV_LEN = 16
PROTO_TAG_POS = 56
DC_IDX_POS = 60
PROTO_TAG_ABRIDGED = b"\xef\xef\xef\xef"
RESERVED_FIRST_BYTES = {0xEF}
RESERVED_STARTS = {
    b"HEAD",
    b"POST",
    b"GET ",
    b"\xee\xee\xee\xee",
    b"\xdd\xdd\xdd\xdd",
    b"\x16\x03\x01\x02",
}
RESERVED_CONTINUE = b"\x00\x00\x00\x00"
REQ_PQ = 0x60469778


class TgProxyProbeBackend:
    def create_connection(self, host: str, port: int, timeout: float):
        return socket.create_connection((host, port), timeout=timeout)

    def resolve_host(self, host: str) -> list[str]:
        return resolve_host(host)

    def monotonic(self) -> float:
        return time.perf_counter()

    def time(self) -> int:
        return int(time.time())

    def urandom(self, n: int) -> bytes:
        return bytes(__import__("os").urandom(n))


def _sanitize_handshake_seed(seed: bytes) -> bytes:
    data = bytearray(seed[:HANDSHAKE_LEN].ljust(HANDSHAKE_LEN, b"\x01"))
    if data[0] in RESERVED_FIRST_BYTES:
        data[0] = 0x01
    if bytes(data[:4]) in RESERVED_STARTS:
        data[0] ^= 0x11
    if bytes(data[4:8]) == RESERVED_CONTINUE:
        data[7] = 0x01
    return bytes(data)


def _build_encryptor(key: bytes, iv: bytes):
    iv_int = int.from_bytes(iv, "big")
    return Cipher(algorithms.AES(key), modes.CTR(iv_int.to_bytes(16, "big"))).encryptor()


def _derive_send_key_iv(handshake: bytes, secret: bytes) -> tuple[bytes, bytes]:
    prekey = handshake[SKIP_LEN:SKIP_LEN + PREKEY_LEN]
    iv = handshake[SKIP_LEN + PREKEY_LEN:SKIP_LEN + PREKEY_LEN + IV_LEN]
    return hashlib.sha256(prekey + secret).digest(), iv


def _derive_recv_key_iv(handshake: bytes, secret: bytes) -> tuple[bytes, bytes]:
    rev = handshake[SKIP_LEN:SKIP_LEN + PREKEY_LEN + IV_LEN][::-1]
    return hashlib.sha256(rev[:KEY_LEN] + secret).digest(), rev[KEY_LEN:]


def build_mtproto_obfuscated_client_handshake(secret: bytes, *, dc_id: int = 2, wall_time: int | None = None, random_bytes: bytes | None = None) -> bytes:
    seed = _sanitize_handshake_seed(random_bytes or b"") if random_bytes is not None else None
    if seed is None:
        while True:
            candidate = _sanitize_handshake_seed(bytes(__import__("os").urandom(HANDSHAKE_LEN)))
            if candidate[0] not in RESERVED_FIRST_BYTES and bytes(candidate[:4]) not in RESERVED_STARTS and bytes(candidate[4:8]) != RESERVED_CONTINUE:
                seed = candidate
                break
    assert seed is not None
    send_key, send_iv = _derive_send_key_iv(seed, secret)
    encryptor = _build_encryptor(send_key, send_iv)
    encrypted_full = encryptor.update(seed)
    keystream_tail = bytes(encrypted_full[i] ^ seed[i] for i in range(PROTO_TAG_POS, HANDSHAKE_LEN))
    dc_idx = dc_id
    tail_plain = PROTO_TAG_ABRIDGED + struct.pack("<h", dc_idx) + seed[62:64]
    encrypted_tail = bytes(tail_plain[i] ^ keystream_tail[i] for i in range(8))
    result = bytearray(seed)
    result[PROTO_TAG_POS:HANDSHAKE_LEN] = encrypted_tail
    return bytes(result)


def _outgoing_encryptor(handshake: bytes, secret: bytes):
    key, iv = _derive_send_key_iv(handshake, secret)
    enc = _build_encryptor(key, iv)
    enc.update(b"\x00" * HANDSHAKE_LEN)
    return enc


def _incoming_decryptor(handshake: bytes, secret: bytes):
    key, iv = _derive_recv_key_iv(handshake, secret)
    return _build_encryptor(key, iv)


def _abridged_wrap(payload: bytes) -> bytes:
    if len(payload) % 4 != 0:
        raise ValueError("MTProto abridged payload must be padded to 4 bytes")
    words = len(payload) // 4
    if words < 0x7F:
        return bytes([words]) + payload
    return b"\x7f" + struct.pack("<I", words)[:3] + payload


def _abridged_unwrap(payload: bytes) -> bytes:
    if not payload:
        raise ValueError("empty MTProto response")
    if payload[0] == 0x7F:
        if len(payload) < 4:
            raise ValueError("short MTProto abridged header")
        words = int.from_bytes(payload[1:4] + b"\x00", "little")
        offset = 4
    else:
        words = payload[0]
        offset = 1
    size = words * 4
    if len(payload) < offset + size:
        raise ValueError("short MTProto payload")
    return payload[offset:offset + size]


def encrypt_mtproto_frame(handshake: bytes, secret: bytes, payload: bytes) -> bytes:
    return _outgoing_encryptor(handshake, secret).update(_abridged_wrap(payload))


def encrypt_mtproto_server_frame(handshake: bytes, secret: bytes, payload: bytes) -> bytes:
    return _incoming_decryptor(handshake, secret).update(_abridged_wrap(payload))


def decrypt_mtproto_frame(handshake: bytes, secret: bytes, payload: bytes) -> bytes:
    decrypted = _incoming_decryptor(handshake, secret).update(payload)
    return _abridged_unwrap(decrypted)


def _build_req_pq_message(epoch: int, nonce: bytes) -> bytes:
    body = struct.pack("<I", REQ_PQ) + nonce
    message_id = ((epoch << 32) & ~0b11) | 0b00
    return b"\x00" * 8 + struct.pack("<q", message_id) + struct.pack("<i", len(body)) + body


def probe_tg_proxy_uri(config_text: str, *, backend: TgProxyProbeBackend | None = None, dc_id: int = 2) -> CheckOutcome:
    backend = backend or TgProxyProbeBackend()
    parsed = parse_target_config(Protocol.TG_PROXY, config_text)
    secret_text = (parsed.get("secret") or "").strip()
    resolved_ips = backend.resolve_host(parsed["host"])

    if not secret_text:
        return CheckOutcome(
            protocol=Protocol.TG_PROXY,
            status=CheckStatus.DEGRADED,
            stage="config_validation",
            summary="Telegram proxy deep-check requires a secret",
            details={"host": parsed["host"], "port": parsed["port"], "resolved_ips": resolved_ips},
        )
    try:
        secret = bytes.fromhex(secret_text)
    except ValueError:
        return CheckOutcome(
            protocol=Protocol.TG_PROXY,
            status=CheckStatus.DEGRADED,
            stage="config_validation",
            summary="Telegram proxy secret must be valid hex",
            details={"host": parsed["host"], "port": parsed["port"], "resolved_ips": resolved_ips},
        )

    started = backend.monotonic()
    sock = None
    try:
        sock = backend.create_connection(parsed["host"], parsed["port"], timeout=5.0)
        sock.settimeout(5.0)
        handshake = build_mtproto_obfuscated_client_handshake(secret, dc_id=dc_id, wall_time=backend.time(), random_bytes=backend.urandom(HANDSHAKE_LEN))
        sock.sendall(handshake)
        req_pq = _build_req_pq_message(backend.time(), backend.urandom(16))
        sock.sendall(encrypt_mtproto_frame(handshake, secret, req_pq))
        raw_response = sock.recv(4096)
        if not raw_response:
            return CheckOutcome(
                protocol=Protocol.TG_PROXY,
                status=CheckStatus.OFFLINE,
                stage="mtproto_response",
                summary="Telegram proxy deep-check failed: no MTProto response",
                details={"host": parsed["host"], "port": parsed["port"], "resolved_ips": resolved_ips, "dc_id": dc_id},
            )
        payload = decrypt_mtproto_frame(handshake, secret, raw_response)
        if len(payload) < 20 or payload[:8] != b"\x00" * 8:
            return CheckOutcome(
                protocol=Protocol.TG_PROXY,
                status=CheckStatus.OFFLINE,
                stage="mtproto_response",
                summary="Telegram proxy deep-check failed: invalid MTProto response",
                details={"host": parsed["host"], "port": parsed["port"], "resolved_ips": resolved_ips, "dc_id": dc_id},
            )
        constructor = None
        if len(payload) >= 24:
            constructor = f"0x{struct.unpack('<I', payload[20:24])[0]:08x}"
        latency_ms = int((backend.monotonic() - started) * 1000)
        return CheckOutcome(
            protocol=Protocol.TG_PROXY,
            status=CheckStatus.ONLINE,
            stage="usable_connectivity",
            summary="Telegram proxy accepted MTProto request and returned MTProto data",
            latency_ms=latency_ms,
            details={
                "host": parsed["host"],
                "port": parsed["port"],
                "kind": parsed.get("kind"),
                "secret_present": True,
                "resolved_ips": resolved_ips,
                "dc_id": dc_id,
                "response_len": len(payload),
                "body_constructor": constructor,
            },
        )
    except (socket.timeout, TimeoutError):
        return CheckOutcome(
            protocol=Protocol.TG_PROXY,
            status=CheckStatus.OFFLINE,
            stage="mtproto_response",
            summary="Telegram proxy deep-check failed: no MTProto response",
            details={"host": parsed["host"], "port": parsed["port"], "resolved_ips": resolved_ips, "dc_id": dc_id},
        )
    except Exception as exc:
        return CheckOutcome(
            protocol=Protocol.TG_PROXY,
            status=CheckStatus.OFFLINE,
            stage="command",
            summary=f"Telegram proxy deep-check failed: {exc}",
            details={"host": parsed["host"], "port": parsed["port"], "resolved_ips": resolved_ips, "dc_id": dc_id},
        )
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
