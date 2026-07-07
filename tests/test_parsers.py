from app.models import Protocol
from app.parsers import parse_target_config


def test_parse_wireguard_config_extracts_endpoint():
    text = """
[Interface]
PrivateKey = aaa=
Address = 10.0.0.2/32, fd00::2/128
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = bbb=
Endpoint = 1.2.3.4:51820
AllowedIPs = 0.0.0.0/0, ::/0
""".strip()
    parsed = parse_target_config(Protocol.WIREGUARD, text)
    assert parsed["host"] == "1.2.3.4"
    assert parsed["port"] == 51820
    assert parsed["private_key"] == "aaa="
    assert parsed["peer_public_key"] == "bbb="
    assert parsed["addresses"] == ["10.0.0.2/32", "fd00::2/128"]
    assert parsed["dns_servers"] == ["1.1.1.1", "8.8.8.8"]
    assert parsed["allowed_ips"] == ["0.0.0.0/0", "::/0"]


def test_parse_amneziawg_config_extracts_endpoint_and_marks_awg():
    text = """
[Interface]
PrivateKey = aaa=
Address = 10.0.0.2/32
Jc = 4
Jmin = 10
Jmax = 50

[Peer]
PublicKey = bbb=
Endpoint = vpn.example.com:9727
AllowedIPs = 0.0.0.0/0
""".strip()
    parsed = parse_target_config(Protocol.AMNEZIAWG, text)
    assert parsed["host"] == "vpn.example.com"
    assert parsed["port"] == 9727
    assert parsed["is_awg"] is True


def test_parse_vless_uri_extracts_core_fields():
    text = "vless://12345678-1234-1234-1234-123456789012@example.com:443?security=reality&type=tcp&sni=yandex.ru&pbk=KEY&sid=ac&fp=firefox#demo"
    parsed = parse_target_config(Protocol.VLESS, text)
    assert parsed["host"] == "example.com"
    assert parsed["port"] == 443
    assert parsed["security"] == "reality"
    assert parsed["sni"] == "yandex.ru"
    assert parsed["pbk"] == "KEY"
    assert parsed["sid"] == "ac"
    assert parsed["fp"] == "firefox"


def test_parse_tg_proxy_uri_extracts_secret():
    text = "tg://proxy?server=telegram.example.com&port=443&secret=abcdef"
    parsed = parse_target_config(Protocol.TG_PROXY, text)
    assert parsed["host"] == "telegram.example.com"
    assert parsed["port"] == 443
    assert parsed["secret"] == "abcdef"
