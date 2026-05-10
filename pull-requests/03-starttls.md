# feat: STARTTLS support

The EHLO response already advertises `STARTTLS`, but the command isn't
actually handled — clients see the capability and then get
`502 command not recognized` when they try to use it. This PR
implements the upgrade properly.

## What changed

### Opt-in via cert/key paths

- `MAILONEY_TLS_CERT` + `MAILONEY_TLS_KEY` (or `--tls-cert` /
  `--tls-key`) both required to enable
- Either unset → no TLS support; `STARTTLS` from a client gets
  `454 4.7.0 TLS not available` and the EHLO response **does not**
  advertise `STARTTLS`
- Both set → TLS enabled; EHLO advertises `STARTTLS` pre-upgrade
  and drops the line post-upgrade per RFC 3207 §4.2

### Upgrade flow

When a client sends `STARTTLS`:
1. Server replies `220 2.0.0 Ready to start TLS`
2. Socket timeout is set to 10 seconds for the handshake (protects
   against half-open clients pinning worker threads)
3. `ssl.SSLContext.wrap_socket(server_side=True)` upgrades the
   connection
4. Conversation continues over the wrapped socket; the EHLO emitted
   after the upgrade omits the `STARTTLS` line

### TLS configuration

- Pinned to **TLS 1.2 minimum** (`ctx.minimum_version =
  ssl.TLSVersion.TLSv1_2`). 1.0/1.1 are deprecated and offer no
  honeypot upside.
- Cert and key are loaded **once at process start**. No hot-reload —
  certbot operators should restart the container after renewal
  (60-day cadence, monthly cron is plenty).
- Standard certbot paths work out of the box:
  - `MAILONEY_TLS_CERT=/etc/letsencrypt/live/<domain>/fullchain.pem`
  - `MAILONEY_TLS_KEY=/etc/letsencrypt/live/<domain>/privkey.pem`

### Subsequent `STARTTLS` is rejected

If the client somehow issues `STARTTLS` again on an already-encrypted
connection, the server replies `503 5.5.1 STARTTLS already active`.

### Pre-existing EHLO formatting bug fixed

The static EHLO response had `250 mail.example.com\n` as the first
line — `250 ` (space) is the SMTP "last line" marker per RFC 5321
§4.2.1, but more lines followed it. Reformatted so all but the last
capability line use `250-` continuation markers. Tolerant clients
accepted the old form; stricter ones (Postfix, some MTA libraries)
correctly rejected the response.

## Backward compatibility

- Both env vars unset → no behaviour change for existing deployments
  (EHLO no longer advertises a capability we couldn't deliver on
  anyway, which is *more* correct than before)
- No new required deps (`ssl` is stdlib)

## Tests

`tests/test_starttls.py` covers:
- No TLS context built when cert/key paths unset (or only one set)
- Context built from a real (openssl-generated) self-signed cert pair
- EHLO advertises STARTTLS only when configured
- Post-TLS EHLO omits the STARTTLS line
- Continuation markers (`250-` vs `250 `) format correctly
- STARTTLS reply branches: `454` unconfigured, `503` already-active,
  `220` + `wrap_socket` call when ready
- Handshake timeout is applied before `wrap_socket`
