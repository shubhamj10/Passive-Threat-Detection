"""Receive-only socket: the software data diode.

The enclave can only bind and receive. Every method that could transmit or
initiate a connection raises ReadOnlyViolation. The raw socket is private and
never handed out. In production this is backed by a hardware TAP / data diode.
"""
from __future__ import annotations

import socket


class ReadOnlyViolation(RuntimeError):
    """Raised on any attempt to send from, or connect, the receive-only socket."""


class ReceiveOnlySocket:
    __slots__ = ("_sock", "_bufsize", "host", "port")

    def __init__(self, host: str, port: int, bufsize: int = 65535, timeout: float = 0.5) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        except OSError:
            pass
        s.bind((host, port))
        s.settimeout(timeout)
        self._sock = s
        self._bufsize = bufsize
        self.host, self.port = host, port

    # ---- the only allowed direction -------------------------------------
    def recv(self) -> bytes | None:
        """Return one datagram, or None on timeout. The sender address is discarded."""
        try:
            data, _addr = self._sock.recvfrom(self._bufsize)
            return data
        except socket.timeout:
            return None

    def close(self) -> None:
        self._sock.close()

    # ---- everything else is forbidden ------------------------------------
    def _deny(self, *_a, **_k):
        raise ReadOnlyViolation("enclave socket is receive-only: no return path")

    send = sendto = sendall = sendmsg = sendfile = _deny
    connect = connect_ex = _deny

    def __getattr__(self, name: str):
        raise ReadOnlyViolation(f"attribute '{name}' is not available on a receive-only socket")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
