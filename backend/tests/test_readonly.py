"""Read-only proof (software level): the enclave can receive but never send or connect."""
import ast
import socket
from pathlib import Path

import pytest

from app.enclave.diode.receiver import ReadOnlyViolation, ReceiveOnlySocket

ENCLAVE = Path(__file__).resolve().parent.parent / "app" / "enclave"
FORBIDDEN_MODULES = {"requests", "httpx", "urllib", "urllib3", "http", "aiohttp", "websockets", "openai",
                     "smtplib", "ftplib", "telnetlib", "paramiko", "ssl", "asyncio"}
FORBIDDEN_CALLS = {"connect", "connect_ex", "send", "sendto", "sendall", "sendmsg", "sendfile",
                   "create_connection", "urlopen"}
SOCKET_ALLOWED = {"diode/receiver.py"}


@pytest.fixture
def rx():
    s = ReceiveOnlySocket("127.0.0.1", 0)
    yield s
    s.close()


@pytest.mark.parametrize("method", ["send", "sendto", "sendall", "sendmsg", "connect", "connect_ex"])
def test_send_or_connect_raises(rx, method):
    with pytest.raises(ReadOnlyViolation):
        getattr(rx, method)(b"x", ("127.0.0.1", 9))


def test_raw_socket_not_exposed(rx):
    for name in ("fileno", "dup", "makefile", "sock"):
        with pytest.raises(ReadOnlyViolation):
            getattr(rx, name)


def test_receives_datagrams():
    rx = ReceiveOnlySocket("127.0.0.1", 0, timeout=1.0)
    port = rx._sock.getsockname()[1]
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tx.sendto(b"hello", ("127.0.0.1", port))
    assert rx.recv() == b"hello"
    tx.close(); rx.close()


def _py_files():
    return [p for p in ENCLAVE.rglob("*.py")]


def test_static_scan_no_network_clients():
    problems = []
    for p in _py_files():
        rel = p.relative_to(ENCLAVE).as_posix()
        tree = ast.parse(p.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            mods = []
            if isinstance(node, ast.Import):
                mods = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                mods = [node.module.split(".")[0]]
            for m in mods:
                if m in FORBIDDEN_MODULES:
                    problems.append(f"{rel}: imports {m}")
                if m == "socket" and rel not in SOCKET_ALLOWED:
                    problems.append(f"{rel}: imports socket")
            if isinstance(node, ast.Call):
                fn = node.func
                name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", None)
                is_sqlite = isinstance(fn, ast.Attribute) and getattr(fn.value, "id", None) == "sqlite3"
                if name in FORBIDDEN_CALLS and not is_sqlite:   # sqlite3.connect opens a local file
                    problems.append(f"{rel}:{node.lineno}: calls {name}()")
    assert not problems, "\n".join(problems)


def test_only_assistant_may_use_outbound_clients():
    app_dir = ENCLAVE.parent
    for p in app_dir.rglob("*.py"):
        rel = p.relative_to(app_dir).as_posix()
        if rel.startswith("assistant/"):
            continue
        src = p.read_text(encoding="utf-8")
        assert "import openai" not in src and "from openai" not in src, rel
        assert "import requests" not in src, rel
