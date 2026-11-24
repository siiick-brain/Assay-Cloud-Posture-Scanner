"""A small threaded TLS server bound to 127.0.0.1 for endpoint checker tests."""

from __future__ import annotations

import contextlib
import socket
import ssl
import threading
import warnings
from pathlib import Path
from types import TracebackType


def strong_context(cert: Path, key: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    return ctx


def weak_context(cert: Path, key: Path) -> ssl.SSLContext:
    """As weak as the local OpenSSL allows: every protocol and cipher at security level 0."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.set_ciphers("ALL:COMPLEMENTOFALL:@SECLEVEL=0")
    with warnings.catch_warnings(), contextlib.suppress(ValueError):
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    ctx.load_cert_chain(cert, key)
    return ctx


class LocalTLSServer:
    def __init__(self, ctx: ssl.SSLContext) -> None:
        self._ctx = ctx
        self._sock = socket.create_server(("127.0.0.1", 0))
        self._sock.settimeout(0.2)
        self.port: int = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            conn.settimeout(5)
            # Failed handshakes are the point of half the probes, so errors are expected here.
            with contextlib.suppress(OSError), self._ctx.wrap_socket(conn, server_side=True) as tls:
                tls.recv(1)
            conn.close()

    def __enter__(self) -> LocalTLSServer:
        self._thread.start()
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        self._stop.set()
        self._sock.close()
        self._thread.join(timeout=5)
