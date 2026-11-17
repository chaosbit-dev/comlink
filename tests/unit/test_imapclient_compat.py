"""imapclient against a real socket on the running Python, with no mocks.

Every other unit test fakes the IMAP client, so they kept passing when the image moved
to Python 3.14 while imapclient 3.1.0 broke there: its IMAP4WithTimeout assigned
``imaplib.IMAP4.file``, which 3.14 made a read-only property, so every IMAP call in
production failed. This test opens a real IMAPClient against a local stub server and
upgrades it with STARTTLS (fixed separately for 3.14 in imapclient 4.1.0), the same
path ``bridge/imap.py`` takes.
"""

from __future__ import annotations

import datetime
import ipaddress
import socket
import ssl
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest
from imapclient import IMAPClient

x509 = pytest.importorskip("cryptography.x509")
hashes = pytest.importorskip("cryptography.hazmat.primitives.hashes")
serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")
ec = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ec")


def _self_signed(tmp: Path) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp / "cert.pem", tmp / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def _serve(srv: socket.socket, server_ctx: ssl.SSLContext) -> None:
    conn, _ = srv.accept()
    stream = conn.makefile("rwb")
    # Advertise STARTTLS until TLS is up, in the greeting and in any CAPABILITY reply:
    # the client may ask again rather than trust the greeting.
    capabilities = b"IMAP4rev1 STARTTLS"
    stream.write(b"* OK [CAPABILITY " + capabilities + b"] stub ready\r\n")
    stream.flush()
    while line := stream.readline():
        tag, _, rest = line.rstrip(b"\r\n").partition(b" ")
        command = rest.split(b" ")[0].upper()
        if command == b"STARTTLS":
            stream.write(tag + b" OK begin TLS\r\n")
            stream.flush()
            conn = server_ctx.wrap_socket(conn, server_side=True)
            stream = conn.makefile("rwb")
            capabilities = b"IMAP4rev1"
            continue
        if command == b"CAPABILITY":
            stream.write(b"* CAPABILITY " + capabilities + b"\r\n")
        if command == b"LOGOUT":
            stream.write(b"* BYE\r\n" + tag + b" OK bye\r\n")
            stream.flush()
            break
        stream.write(tag + b" OK done\r\n")
        stream.flush()
    conn.close()


@pytest.fixture
def stub(tmp_path: Path) -> Iterator[tuple[int, ssl.SSLContext]]:
    cert_path, key_path = _self_signed(tmp_path)
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(cert_path, key_path)
    client_ctx = ssl.create_default_context(cafile=str(cert_path))
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    thread = threading.Thread(target=_serve, args=(srv, server_ctx), daemon=True)
    thread.start()
    yield srv.getsockname()[1], client_ctx
    srv.close()
    thread.join(timeout=5)


def test_imapclient_connects_and_starttls_on_this_python(stub: tuple[int, ssl.SSLContext]) -> None:
    port, client_ctx = stub
    # The same constructor arguments as bridge/imap.py: plain socket, timeout, then STARTTLS.
    client = IMAPClient("127.0.0.1", port=port, ssl=False, timeout=5)
    client.starttls(client_ctx)
    assert b"IMAP4REV1" in client.capabilities()
    client.logout()
