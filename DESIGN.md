Build a small standalone C program called saphira-proxyto.

Purpose
-------

saphira-proxyto is a generic TCP proxy for applications which do not
understand the HAProxy PROXY protocol.

It accepts a TCP connection carrying a valid PROXY protocol header,
parses and removes that header, connects to a configured local/backend
TCP service, then transparently forwards the remaining byte stream in
both directions.

It is deliberately application-independent. Geomyidae/Gopher is the
first use case, but the program must not contain Gopher-specific code.

Target
------

- Written in C.
- Must build cleanly against musl libc.
- No external library dependencies.
- Linux target.
- IPv4 and IPv6.
- No systemd-only assumptions.
- Do not daemonise; OpenRC/systemd will supervise it.
- Small, simple and auditable.
- No TLS, HTTP or application protocol parsing.
- No initramfs assumptions.

Invocation
----------

The intended invocation is:

    proxyto geomyidae

This loads:

    /etc/saphira/proxyto/geomyidae.conf

Configuration example:

    application=/usr/bin/geomyidae
    listen=172.16.0.2:70
    proxy=127.0.0.1:70

Meaning:

    application=
        Application associated with this proxy definition.
        Initially informational/validation only. proxyto does NOT launch
        or supervise the application.

    listen=
        Local IP address and TCP port on which proxyto accepts HAProxy
        PROXY-protocol connections.

    proxy=
        Backend IP address and TCP port to which the clean TCP stream
        is forwarded after the PROXY header has been removed.

Do not require listen and proxy ports to differ. This is valid:

    listen=172.16.0.2:70
    proxy=127.0.0.1:70

because they bind/connect different addresses.

Do not default to 0.0.0.0. The configured listen address must be used
exactly. IPv6 addresses must also be supported, with an unambiguous
configuration syntax.

PROXY protocol
--------------

Use the supplied HAProxy PROXY protocol specification as the normative
reference.

Support:

- PROXY protocol v1
- PROXY protocol v2
- TCP over IPv4
- TCP over IPv6
- LOCAL/UNKNOWN semantics where required by the specification

The complete PROXY header must be consumed before any application
payload is forwarded.

Malformed, incomplete or unsupported headers must cause the connection
to be rejected. Never pass a malformed PROXY header through to the
backend application.

Do not guess whether a connection is using PROXY protocol. The proxyto
listener is explicitly a PROXY-protocol listener.

Forwarding
----------

After parsing the header:

    client -> proxyto -> backend
    backend -> proxyto -> client

The application payload must be byte-for-byte unchanged.

Handle:

- partial reads
- partial writes
- EINTR
- connection close
- half-close where practical
- backend connection failure
- multiple simultaneous clients

Do not assume recv() returns the entire PROXY header in one call.

Logging
-------

proxyto knows the real client address from the PROXY header, so log it.

Useful connection log form:

    proxyto[pid]: geomyidae client=[2001:db8::1]:43122 backend=127.0.0.1:70 connected

and on close:

    proxyto[pid]: geomyidae client=[2001:db8::1]:43122 closed rx=42 tx=1937

Log startup/configuration errors clearly.

Important limitation
--------------------

The backend application will see proxyto's backend-side socket address,
for example 127.0.0.1, not the original client's address.

Do NOT implement transparent proxying, TPROXY, source-address spoofing,
routing tricks or application-specific client-IP injection in version 1.

The original client address is available in proxyto's logs.

Security
--------

The PROXY header is ASSERTED metadata: whoever writes it is claiming to
be somebody else. That claim is only worth anything if we can tell a
trusted proxy from a direct client, so the trust check is the security
boundary, not a convenience.

`trusted_proxy=` is REQUIRED: a comma-separated list of the peers
permitted to assert a source identity. An absent or empty list means
"nobody may assert an identity" and proxyto REFUSES TO START. It must
never mean "everybody may" - a listener with no trust list would let any
direct client claim any address, which is exactly the attack the
mechanism exists to prevent.

The check is ordered deliberately:

1. `getpeername()` the real socket peer
2. reject immediately if that peer is not in `trusted_proxy`
3. only then read and parse the header
4. an untrusted peer never has its header parsed at all

An untrusted peer is REJECTED, never downgraded to its real address.
`is_trusted_peer()` also fails closed independently of the startup check,
as defence in depth - a single branch away from trusting every peer is too
close to the failure this replaces.

Refusing at startup is preferable to rejecting per connection: an operator
learns the configuration is unsafe before the service is exposed, rather
than on the first connection that arrives.

Header parsing remains strict about length, address family, field sizes
and bounds checking. No unsafe unbounded string functions.

Firewall policy remains a useful second layer, not the primary control.

Conveying identity to the backend
--------------------------------

A backend on a Unix socket sees only proxyto's address, which identifies
proxyto and not the client. Where a backend needs the real client
identity, proxyto parses and validates the incoming header and then EMITS
a fresh, canonical PROXY v2 header to the backend - never relaying the
received bytes, so smuggled or untrusted metadata cannot survive the
crossing. The backend then implements only the small trusted-backend
consumption side and never the hostile-network parser.

Decisions taken for that work:

- TLS ordering is PROXY then TLS. This is the HAProxy-compatible wire
  contract: `send-proxy-v2` is emitted in clear before the handshake.
  TLS-then-PROXY would be a different protocol and break the native
  HAProxy path. The claimed identity stays PROVISIONAL until TLS/mTLS
  succeeds, and is never forwarded when TLS authentication fails.
- TLVs are re-emitted only from an explicit allowlist: ALPN, AUTHORITY and
  UNIQUE_ID. NOOP is not re-emitted. The nested SSL TLV is deferred rather
  than implemented as a complicated copier. CRC32C is never copied - it
  covers the header, so a copied checksum would be invalid for regenerated
  bytes; omit it or generate a fresh one.
- Identity policy is per listener, via `identity_required`. A backend that
  needs a verified source sets it, and LOCAL/UNKNOWN/UNSPEC are rejected
  because there is no verified IPv4/IPv6 to forward. A general-purpose
  listener may keep the real-peer fallback where explicitly configured.
- `max_children` is implemented: at the limit the listener refuses new
  connections and the backlog absorbs a short burst, resuming when SIGCHLD
  reports a free slot. The self-pipe required for SIGHUP reload is still to
  come and will be the parent wakeup mechanism.
- OpenSSL is an accepted dependency. The runtime dependency is the package
  that actually owns `libssl.so.3` / `libcrypto.so.3`; verify ownership
  rather than assuming the package split, and do not pull in the OpenSSL
  CLI where the runtime libraries ship separately.

TLS stays small: TLS 1.2/1.3, explicit certificate/key/CA configuration,
optional client-certificate verification, OpenSSL's own defaults, no
bespoke crypto knobs. TLS material must be readable by the runtime
account, because the privilege drop happens first and leaves no
supplementary groups.

Deliberately deferred: splice(), io_uring, worker pools, event-loop
rewrite. A small boring auditable C proxy is an advantage.

Repository layout
-----------------

    saphira-proxyto/
    ├── etc/
    │   └── saphira/
    │       └── proxyto/
    │           └── geomyidae.conf
    ├── src/
    │   ├── proxyto.c
    │   └── ...
    ├── usr/
    │   └── bin/
    ├── README.md
    └── Makefile

Build initially on Arch, but the source and Makefile must remain
musl-compatible. Do not rely on glibc-only APIs.

The first acceptance test is:

    HAProxy :70
        send-proxy / send-proxy-v2
            ->
    proxyto listening 172.16.0.2:70
            ->
    geomyidae listening 127.0.0.1:70

and a normal Gopher request must reach Geomyidae without any PROXY
header bytes leaking into its request stream.

## Privilege model

The daemon starts as root only to bind privileged ports such as
TCP/70. Startup order: parse and validate configuration, resolve and
bind the listening socket, listen(), resolve the dedicated
proxyto:proxyto account, permanently drop supplementary groups, gid
and uid (in that order), verify the drop stuck and privilege cannot
be regained (including a setuid(0) probe), then enter the
accept()/fork loop. All accepted connections and PROXY parsing run
as proxyto, never uid 0; forked workers inherit the dropped
identity. Any failure (missing account, failed setgroups/setgid/
setuid, regained privilege) is fatal. Started unprivileged, it logs
a notice and continues. No chroot yet (separate hardening step; it
complicates syslog and name resolution). The runtime account is
independent of any backend application account.

## Per-service tuning knobs

header_timeout=, connect_timeout= (milliseconds, 100..300000,
default 5000) and buffer_size= (bytes, 4096..1048576, default
16384, matching haproxy tune.bufsize). service_type= is a validated
backend label (default generic) used in logs, reserving the
namespace for future per-service relay tuning without complicating
the core loop. The small-segment v2 acceptance follows the PROXY
spec: reject only bytes that rule out both v1 and the v2 signature
prefix, otherwise wait for more.

  max_children= (1..4096, default 256) caps concurrent workers. Each
  accepted connection forks, so without a cap a peer that can reach the
  listener can fork until PIDs, fds, or memory run out. At the cap the
  daemon refuses new connections rather than queueing them: the kernel
  backlog absorbs the arrival and the peer sees a fast close, which is
  the backpressure haproxy's maxconn provides. Saturation is logged once
  on entry and once on recovery, never per connection, so a flood cannot
  become a log flood. The hard upper bound exists so a misconfigured
  max_children= cannot itself be the denial of service.

  accept() failures from resource exhaustion (EMFILE, ENFILE, ENOMEM,
  ENOBUFS) back off exponentially from 10ms to a 1s cap and reset on the
  first successful accept, so descriptor exhaustion cannot turn the
  accept loop into a busy spin that floods the log.

  trusted_proxy= may appear once. A second definition is a hard error
  rather than a silent overwrite: an operator who writes two lines and
  gets only the last would believe a peer is trusted when it is not. All
  peers belong on one comma-separated line.
