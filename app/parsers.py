from __future__ import annotations

from configparser import ConfigParser
from io import StringIO
from urllib.parse import parse_qs, unquote, urlparse

from app.models import Protocol


class ParseError(ValueError):
    pass


def _parse_ini(text: str) -> ConfigParser:
    parser = ConfigParser(interpolation=None)
    parser.optionxform = str
    parser.read_file(StringIO(text))
    return parser


def parse_wireguard_like(text: str, *, expect_awg: bool) -> dict:
    parser = _parse_ini(text)
    if not parser.has_section("Peer"):
        raise ParseError("Missing [Peer] section")
    endpoint = parser.get("Peer", "Endpoint", fallback="")
    if not endpoint or ":" not in endpoint:
        raise ParseError("Missing Endpoint host:port")
    host, port = endpoint.rsplit(":", 1)
    interface = dict(parser.items("Interface")) if parser.has_section("Interface") else {}
    peer = dict(parser.items("Peer"))
    result = {
        "host": host.strip(),
        "port": int(port),
        "endpoint": endpoint.strip(),
        "is_awg": False,
        "private_key": interface.get("PrivateKey", "").strip(),
        "peer_public_key": peer.get("PublicKey", "").strip(),
        "addresses": [item.strip() for item in interface.get("Address", "").split(",") if item.strip()],
        "dns_servers": [item.strip() for item in interface.get("DNS", "").split(",") if item.strip()],
        "allowed_ips": [item.strip() for item in peer.get("AllowedIPs", "").split(",") if item.strip()],
    }
    if expect_awg:
        result["is_awg"] = any(k in interface for k in ("Jc", "Jmin", "Jmax", "S1", "H1"))
    return result


def parse_vless_uri(text: str) -> dict:
    parsed = urlparse(text.strip())
    if parsed.scheme != "vless":
        raise ParseError("Expected vless:// URI")
    if not parsed.hostname or not parsed.port:
        raise ParseError("VLESS URI missing host or port")
    query = parse_qs(parsed.query)
    return {
        "host": parsed.hostname,
        "port": parsed.port,
        "uuid": parsed.username,
        "security": query.get("security", [""])[0],
        "type": query.get("type", [""])[0],
        "sni": query.get("sni", [""])[0],
        "pbk": query.get("pbk", [""])[0],
        "sid": query.get("sid", [""])[0],
        "spx": unquote(query.get("spx", [""])[0]),
    }


def parse_tg_proxy(text: str) -> dict:
    parsed = urlparse(text.strip())
    if parsed.scheme != "tg":
        raise ParseError("Expected tg:// URI")
    query = parse_qs(parsed.query)
    host = query.get("server", [""])[0]
    port = query.get("port", [""])[0]
    secret = query.get("secret", [""])[0]
    if not host or not port:
        raise ParseError("Telegram proxy URI missing server or port")
    return {
        "host": host,
        "port": int(port),
        "secret": secret,
        "kind": parsed.netloc,
    }


def parse_target_config(protocol: Protocol, text: str) -> dict:
    match protocol:
        case Protocol.WIREGUARD:
            return parse_wireguard_like(text, expect_awg=False)
        case Protocol.AMNEZIAWG:
            return parse_wireguard_like(text, expect_awg=True)
        case Protocol.VLESS:
            return parse_vless_uri(text)
        case Protocol.TG_PROXY:
            return parse_tg_proxy(text)
        case _:
            raise ParseError(f"Unsupported protocol: {protocol}")
