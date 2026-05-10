# fix(core): support IPv6 and dual-stack SMTP bind

The SMTP listener was hardcoded `socket.AF_INET`, so binding to `::`
or any IPv6 literal failed at startup with:

```
ERROR - Error running server: [Errno -2] Name or service not known
```

This makes IPv6-only deployments impossible and forces dual-stack
operators to wrap with an external listener.

## What changed

`SMTPHoneypot.start()` now uses `socket.create_server` and picks the
address family from the bind string:

- IPv4 literal (`0.0.0.0`, `127.0.0.1`, …) → `AF_INET`
- IPv6 literal (`::`, `::1`, `2001:db8::…`) → `AF_INET6`
- `::` specifically opts in to dual-stack via `dualstack_ipv6=True`
  when the platform supports it (Linux dual-stack on by default;
  `socket.has_dualstack_ipv6()` is the runtime check)

`SO_REUSEADDR` is still set automatically on POSIX (`create_server`
does this in stdlib).

The bind-address form is the bare literal, not the URL syntax — `::`
not `[::]`. The latter is a brackets-for-URL convention that the
sockets API does not accept.

## Why this is small and self-contained

- One method, ~20 lines changed
- No new dependencies
- Default behaviour (`MAILONEY_BIND_IP=0.0.0.0`) is unchanged
- Existing test (`tests/test_core.py::test_smtp_honeypot_start`) still
  passes because `create_server` calls `socket.socket()` under the
  hood, which the mock intercepts

## Tested with

- IPv4-only bind (`0.0.0.0`) — unchanged behaviour
- IPv6-only bind (`::1`)
- Dual-stack (`::`) — accepts both IPv4-mapped and IPv6 connections
