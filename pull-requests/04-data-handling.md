# feat: implement SMTP DATA phase with optional filesystem storage

**Supersedes #29.** This PR addresses the three review questions you
left there on 2025-12-30 (`src/` tree changes, chunked storage,
recv()-boundary handling) plus a few other issues, and adds optional
filesystem storage so captured bodies can be handled directly by mail
/ forensics tooling.

## The bug

Mailoney currently lumps DATA together with MAIL FROM / RCPT TO in a
single elif and replies `250 OK` to all three. It never enters
body-receive mode. Whatever the client sends after DATA gets pulled
by the regular `recv()` loop, lowercased, stripped, and treated as
SMTP commands — most fall through to "command not recognized" until
the error counter trips. The mail body — one of the more valuable
things an SMTP honeypot can capture — is effectively lost.

## What changed

- `DATA` now replies with `354 End data with <CR><LF>.<CR><LF>` and
  enters body-receive mode
- `_receive_mail_body()` reads via the client socket's `recv` until
  `<CRLF>.<CRLF>` (or the permissive `\n.\n`) appears, or until a
  1 MiB size cap is hit, or the peer closes
- The terminator search spans the chunk boundary by carrying over a
  4-byte tail per iteration; a `<CRLF>.<CRLF>` split across two
  `recv()` calls is still detected
- After the body:
  - terminator matched → `250 2.0.0 Ok`
  - size cap reached → `552 5.3.4 Message size limit exceeded`
  - peer closed mid-body → `421 4.4.2 Connection closed` + break
- The reply is `250 OK`, not `451 Try again later` as in #29. The
  intent is to make the attacker think the message went through, so
  they don't retry and double-store the same content.
- Empty bodies (`.\r\n` immediately after the 354) terminate
  correctly via a `\A`-anchored regex
- Body bytes are kept raw — no `.strip().lower()` — so headers,
  base64 attachments, and non-ASCII text survive intact

### Optional filesystem storage

`MAILONEY_MAIL_DIR` enables on-disk body capture:

```
<MAIL_DIR>/<YYYY-MM-DD>/<src-ip>/<session-uuid>.eml
```

When set:
- Body bytes are written verbatim (mode `0640`, dirs `0750`)
- The session log records the relative path, not the body contents
- Operationally simpler — `.eml` files open in any mail reader,
  scan cleanly with `clamscan`, `oletools`, etc.

When unset, the body stays inline in the session log as before (just
captured properly this time).

## Addressing #29 specifically

| Your review question | Answer in this PR |
|---|---|
| Why are changes in both `mailoney/core.py` and `src/mailoney/server.py`? | Only touches `mailoney/core.py`. The `src/` tree appears to be stale and isn't shipped from `main`. |
| Should the honeypot accumulate the full email body? | Yes. A single body record (not one per TCP chunk), kept as raw bytes. |
| Have you tested with large emails? | Yes. Multi-chunk bodies, terminator-across-boundary, peer-close mid-body, and size-cap-truncation are all covered by tests. The 1 MiB cap also protects against an attacker sending unbounded data to pin a worker thread. |

## Backward compatibility

- `MAILONEY_MAIL_DIR` unset → bodies stay inline in the session log
  (matches current "DATA does something with whatever bytes arrived")
  intent, just done correctly
- No new required env vars
- No DB schema changes

## Tests

`tests/test_data_handling.py` covers:
- Single-chunk body, multi-chunk body, terminator split across boundary
- Permissive `\n.\n` terminator
- Empty body
- Peer disconnect mid-body
- Size cap truncation
- Command-like bytes inside the body (must not be parsed as commands)
- Filesystem storage: layout, IPv6 paths (Linux), unsafe-character
  stripping, file mode `0640`
