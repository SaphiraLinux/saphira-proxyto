# saphira-proxyto

Generic TCP proxy that adds HAProxy PROXY protocol support to backends that
do not understand it. Intended for Geomyidae/Gopher but application-independent.

```
HAProxy :70  --send-proxy/v2-->  proxyto 172.16.0.2:70  -->  geomyidae 127.0.0.1:70
```

`saphira-proxyto` accepts a PROXY-protocol connection, consumes the complete
PROXY header, connects to the configured backend, and relays the remaining byte
stream unchanged in both directions.

No TLS, no HTTP/Gopher parsing, no TPROXY/source spoofing, no daemonisation.

## Invocation

```
proxyto geomyidae
```

Loads `/etc/saphira/proxyto/geomyidae.conf`.

```
proxyto -c /path/to/custom.conf
proxyto --help
proxyto --syslog geomyidae   # log to syslog instead of stderr
```

## Configuration

```ini
application=/usr/bin/geomyidae
listen=172.16.0.2:70
proxy=127.0.0.1:70
trusted_proxy=203.0.113.10, 203.0.113.11
```

- `application=` — informational/validation only. Not launched or supervised.
- `listen=` — exact local IP and port to bind. No `0.0.0.0` default.
- `proxy=` — backend IP and port.
- `trusted_proxy=` — optional comma-separated list of upstream IP addresses
  that are allowed to connect to the `listen` socket. When set, only
  those IPs may use the PROXY-protocol listener; all other peers are
  rejected before any header is processed. When not set, any peer may
  connect (the listener should still be protected by firewall policy).
  Example single address: `trusted_proxy=203.0.113.10`
  Multiple: `trusted_proxy=203.0.113.10, 203.0.113.11` or
  `trusted_proxy=203.0.113.10, [2001:db8::1]`. Up to 32 entries.

Same port with different addresses is valid:

```ini
listen=172.16.0.2:70
proxy=127.0.0.1:70
```

IPv6 must use brackets for `listen`/`proxy`:

```ini
listen=[2a02:xxx::10]:70
proxy=[::1]:70
```

## PROXY protocol

Vendored `proxy-protocol.txt` (HAProxy, 2026-04-27) is normative.

- v1 human-readable (`PROXY TCP4 ...\r\n`, `PROXY TCP6 ...`, `PROXY UNKNOWN`)
- v2 binary (`\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A` + ver/cmd/fam/len)
- TCP over IPv4 and IPv6; UDP/UNIX families are accepted and skipped via UNSPEC fallback
- `LOCAL` and `UNKNOWN` use the real socket peer for logging and accept the connection
- The entire header is consumed before any payload is forwarded; malformed/incomplete/plain connections are rejected and never forwarded

Partial reads are handled: the header is reassembled incrementally with a 5s timeout. Small tail payload that arrived with the header is retained and forwarded first.

## TLVs (v2)

- `0x01 ALPN` — retained and logged
- `0x02 AUTHORITY` — retained and logged as `authority=...`. Called AUTHORITY not SNI; SNI is one source of authority. Embedded NUL or control bytes (0x01-0x1F, 0x7F) cause rejection. No UTF-8 validation beyond that; stored as bounded string (255 bytes) for logging/future matching. Not injected into backend stream.
- `0x05 UNIQUE_ID` — retained/logged
- `0x03 CRC32C`, `0x04 NOOP`, `0x20 SSL` (and nested subtypes), `0x30 NETNS`, custom `0xE0-0xEF`, experimental `0xF0-0xF7`, future `0xF8-0xFF`, and unknown types — bounds-checked and skipped. CRC32C is recognised and skipped (no verification in v1). SSL outer TLV is skipped safely.

Authority-based virtual-host routing is not yet implemented; the value is parsed/logged now so a future `map` language can select backends without protocol changes.

## Forwarding

- Parent accepts and `fork()`s one worker per connection; parent reaps `SIGCHLD`.
- Each worker: parse header → non-blocking `connect()` to backend (`fcntl(O_NONBLOCK)` → `connect()` → `EINPROGRESS` → `poll(POLLOUT)` → `getsockopt(SO_ERROR)`) → `poll()` relay both directions with `O_NONBLOCK` on both sockets.
- `poll()` handles partial reads/writes, `EINTR`, half-close (`shutdown(SHUT_WR)`), and `POLLHUP`/`POLLERR`.
- Counters `rx` (client→backend) and `tx` (backend→client) for close log.
- No threads, no `splice`, no epoll state machine — small and auditable.

## Logging

Stderr by default (suitable for systemd/OpenRC capture). `--syslog` switches to `syslog(LOG_DAEMON)`.

```
proxyto[123]: geomyidae client=1.2.3.4:54321 backend=127.0.0.1:70 connected
proxyto[123]: geomyidae client=[2001:db8::1]:43122 backend=127.0.0.1:70 connected authority=gopher.example
proxyto[123]: geomyidae client=1.2.3.4:54321 closed rx=42 tx=1937
proxyto[123]: geomyidae client=unknown backend=127.0.0.1:70 rejected (Timed out)
```

Backend still sees `127.0.0.1` as peer; real client is in the log.

## Building

```sh
make               # -march=x86-64-v3 for Saphira x86-64
make ARCH=x86-64-v2
make ARCH=native
make ARCH=         # generic, no -march
make clean
make install DESTDIR=/tmp/pkg
```

Requires only a C11 compiler and Linux headers. Builds against glibc and musl.

```sh
cc -std=c11 -O2 -Wall -Wextra -Wpedantic -D_DEFAULT_SOURCE src/proxyto.c -o proxyto
```

## Testing

```sh
make
tests/run.sh
```

`tests/run.sh` exercises v1/v2, AUTHORITY, UNKNOWN/LOCAL, rejection, bracket parsing, and byte-identity of the forwarded stream.

## Repository layout

```
etc/saphira/proxyto/geomyidae.conf
src/proxyto.c
Makefile
README.md
proxy-protocol.txt
tests/run.sh
```

## Documentation

    man proxyto

The README and man page agree, but the man page is self-contained after
installation.

## Limitations (v1)

- No transparent proxy / TPROXY / source spoofing.
- No SIGHUP reload (restart only).
- No TLS, no application protocol injection.
- No authority-based routing yet.
