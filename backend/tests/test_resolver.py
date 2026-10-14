"""Résolution inverse des adresses internes (DNS de l'AD)."""

import socket
import struct
import threading

from minisoc import resolver


def test_display_name_and_scope():
    assert resolver.display_name("SRV-RADIUS.chatillon.lan.") == "SRV-RADIUS"
    assert resolver.display_name("fw.mairie-exemple.fr") == "fw.mairie-exemple.fr"
    assert resolver.is_private("192.168.2.38") and not resolver.is_private("8.8.8.8")
    assert not resolver.is_private("127.0.0.1")


def _fake_dns(answer: str):
    """Petit serveur DNS UDP local : répond à une requête PTR par `answer`."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))

    def serve():
        data, addr = sock.recvfrom(512)
        tid = data[:2]
        question = data[12:]
        name = b"".join(bytes([len(p)]) + p.encode() for p in answer.split(".")) + b"\x00"
        rr = b"\xc0\x0c" + struct.pack(">HHIH", 12, 1, 60, len(name)) + name
        sock.sendto(tid + struct.pack(">HHHHH", 0x8180, 1, 1, 0, 0) + question + rr, addr)

    threading.Thread(target=serve, daemon=True).start()
    return sock


def test_query_ptr_against_local_server():
    sock = _fake_dns("SRV-PRINT.chatillon.lan")
    port = sock.getsockname()[1]
    assert resolver.query_ptr("192.168.2.27", "127.0.0.1", port=port) == "SRV-PRINT.chatillon.lan"
    sock.close()


async def test_resolve_skips_public_and_unconfigured():
    assert await resolver.resolve("8.8.8.8", "192.168.2.9") == ""
    assert await resolver.resolve("192.168.2.27", "") == ""
    rows = [{"ip": "8.8.8.8"}]
    assert (await resolver.annotate(rows, ""))[0]["name"] == ""
