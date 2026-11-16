# Read-only proof

Software enforcement shows the DESIGN is read-only. Real assurance comes from a hardware TAP or data diode.

| Control | Where | Test |
|---|---|---|
| Receive-only socket: send/sendto/sendall/connect raise `ReadOnlyViolation`; the raw socket is never exposed | `enclave/diode/receiver.py` | `test_readonly.py::test_send_or_connect_raises`, `test_raw_socket_not_exposed` |
| Sender address of each datagram is discarded | `receiver.recv()` | code review |
| No module under `app/enclave/` imports a network client (requests, httpx, urllib, http, ssl, asyncio, openai, ...) or calls connect/send | AST scan | `test_static_scan_no_network_clients` |
| Only `diode/receiver.py` may import `socket` | AST scan | same |
| Only `app/assistant/` may use outbound clients, and only for finished, redacted alerts | AST/text scan | `test_only_assistant_may_use_outbound_clients` |
| No inline blocking: the system has no action API on traffic | design | API overview |

Replay controls (`/api/replay/*`) drive the simulated production side (the generator), never the enclave socket.

In production: put the enclave behind a hardware data diode or a passive TAP with no transmit
path, run the API on a separate analyst network, and keep the assistant disabled or behind an
egress proxy that only allows the Azure OpenAI endpoint.
