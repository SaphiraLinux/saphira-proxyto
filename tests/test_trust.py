import socket, subprocess, time, os, sys, tempfile, threading

# Trust-boundary tests for saphira-proxyto.
#
# These are the security properties the PROXY protocol depends on. A PROXY
# header is ASSERTED metadata: whoever writes it is claiming to be someone
# else. That claim is only worth anything if proxyto can tell a trusted
# proxy from a direct client, so:
#
#   - an untrusted peer must never be able to assert a source identity
#   - "no trusted peers configured" must NOT mean "trust everybody"
#
# The second point was a live defect. is_trusted_peer() returned 1 when the
# list was empty, and the only shipped configuration (geomyidae.conf) had
# trusted_proxy commented out - so the deployed service trusted every peer
# that reached it, and any direct client could assert any source address.
#
# Kept in a separate file from test_proxy.py on purpose: check() exits on the
# first failure, so a red trust suite would otherwise mask every other test.

BIN = sys.argv[1] if len(sys.argv) > 1 else "./proxyto"

def free_port():
    s = socket.socket(); s.bind(('127.0.0.1', 0)); p = s.getsockname()[1]; s.close(); return p

# A trust suite should report EVERY failure, not stop at the first. Knowing
# that the absent-list default is broken AND that mapped-IPv6 matching is
# independently broken is a different conversation from learning them one at
# a time, and a security suite that hides half its findings is worse than
# useless.
_results = []
def check(name, fn):
    try:
        fn()
        print(f"PASS {name}")
        _results.append((name, None))
    except _Skip as e:
        print(f"SKIP {name} ({e})")
        _results.append((name, None))
    except AssertionError as e:
        print(f"FAIL {name}: {e}")
        _results.append((name, str(e)))
    except Exception as e:
        print(f"FAIL {name}: {e}")
        _results.append((name, str(e)))

class _Skip(Exception):
    pass

def skip(reason):
    raise _Skip(reason)

def write_conf(**kw):
    f = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf')
    for k, v in kw.items():
        f.write(f"{k.replace('__', '_')}={v}\n")
    f.close()
    return f.name

def start(conf):
    return subprocess.Popen([BIN, "-c", conf], stderr=subprocess.PIPE)

def wait_listening(lp, timeout=3.0):
    """Wait for the listener to actually accept, so a fail-closed startup
    refusal is observed as a refusal rather than as a race."""
    end = time.time() + timeout
    while time.time() < end:
        try:
            s = socket.create_connection(('127.0.0.1', lp), timeout=0.3)
            s.close(); return True
        except OSError:
            if proc_exited():
                return False
            time.sleep(0.05)
    return False

proc = None

def proc_exited():
    return proc is not None and proc.poll() is not None

def set_proc(p):
    global proc
    proc = p
    return p

def stderr_of(p):
    try:
        return p.stderr.read().decode('utf-8', 'replace')
    except Exception:
        return ''

# --- trusted peer is accepted -------------------------------------------
def test_trusted_peer_accepted():
    lp = free_port(); bp = free_port()
    conf = write_conf(listen=f"127.0.0.1:{lp}", proxy=f"127.0.0.1:{bp}",
                      trusted_proxy="127.0.0.1")
    got = []
    def be():
        s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('127.0.0.1', bp)); s.listen(1); s.settimeout(5)
        try:
            c, a = s.accept(); c.settimeout(5)
            got.append(c.recv(4096)); c.close()
        except OSError:
            pass
        s.close()
    t = threading.Thread(target=be); t.start()
    set_proc(start(conf))
    try:
        assert wait_listening(lp), "trusted listener did not come up"
        s = socket.create_connection(('127.0.0.1', lp), timeout=3)
        s.sendall(b"PROXY TCP4 1.2.3.4 5.6.7.8 12345 70\r\nhello\n")
        s.settimeout(3)
        try:
            s.recv(16)
        except OSError:
            pass
        s.close()
        t.join(timeout=3)
        assert got and got[0] == b"hello\n", \
            f"backend did not receive the payload from a TRUSTED peer (got {got!r})"
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
        try: proc.wait(timeout=2)
        except Exception: pass
        os.unlink(conf)

check("trusted peer accepted", test_trusted_peer_accepted)

# --- untrusted peer must be REJECTED (the anti-spoofing property) ------
def test_untrusted_peer_rejected():
    # The client connects from 127.0.0.1 but the only trusted proxy is a
    # documentation-range address, so this peer is untrusted. It supplies a
    # perfectly well-formed header claiming to be 1.2.3.4. If that reaches
    # the backend, any direct client can assert any identity.
    lp = free_port(); bp = free_port()
    conf = write_conf(listen=f"127.0.0.1:{lp}", proxy=f"127.0.0.1:{bp}",
                      trusted_proxy="203.0.113.10")
    got = []
    def be():
        s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('127.0.0.1', bp)); s.listen(1); s.settimeout(3)
        try:
            c, a = s.accept(); c.settimeout(2)
            got.append(c.recv(4096)); c.close()
        except OSError:
            pass
        s.close()
    t = threading.Thread(target=be); t.start()
    set_proc(start(conf))
    try:
        assert wait_listening(lp), "listener did not come up"
        s = socket.create_connection(('127.0.0.1', lp), timeout=3)
        s.sendall(b"PROXY TCP4 1.2.3.4 5.6.7.8 12345 70\r\nspoofed\n")
        s.settimeout(3)
        data = b''
        try:
            data = s.recv(4096)
        except OSError:
            pass
        s.close()
        t.join(timeout=4)
        assert got == [], \
            f"UNTRUSTED peer reached the backend - identity spoofing is possible (got {got!r})"
        assert data == b'', \
            f"untrusted peer received backend data {data!r}"
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
        try: proc.wait(timeout=2)
        except Exception: pass
        os.unlink(conf)

check("untrusted peer rejected", test_untrusted_peer_rejected)

# --- absent trusted_proxy must FAIL CLOSED ------------------------------
def test_absent_trusted_proxy_fails_closed():
    # No trusted_proxy at all. proxyto runs a PROXY-protocol listener, so
    # every peer on it is asserting an identity. With no trust list there is
    # no way to know who is allowed to do that, so the correct behaviour is
    # to refuse to start - not to trust everyone.
    lp = free_port(); bp = free_port()
    conf = write_conf(listen=f"127.0.0.1:{lp}", proxy=f"127.0.0.1:{bp}")
    set_proc(start(conf))
    try:
        rc = None
        end = time.time() + 4
        while time.time() < end:
            rc = proc.poll()
            if rc is not None:
                break
            time.sleep(0.05)
        assert rc is not None, \
            "proxyto STARTED with no trusted_proxy - an empty trust list must not mean 'trust everybody'"
        err = stderr_of(proc).lower()
        assert "trusted" in err, \
            f"startup refusal should mention the trust configuration, got: {err.strip()[:200]!r}"
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
        try: proc.wait(timeout=2)
        except Exception: pass
        os.unlink(conf)

check("absent trusted_proxy fails closed", test_absent_trusted_proxy_fails_closed)

# --- empty trusted_proxy must also fail closed --------------------------
def test_empty_trusted_proxy_fails_closed():
    lp = free_port(); bp = free_port()
    conf = write_conf(listen=f"127.0.0.1:{lp}", proxy=f"127.0.0.1:{bp}",
                      trusted_proxy="")
    set_proc(start(conf))
    try:
        rc = None
        end = time.time() + 4
        while time.time() < end:
            rc = proc.poll()
            if rc is not None:
                break
            time.sleep(0.05)
        assert rc is not None, \
            "proxyto STARTED with an EMPTY trusted_proxy - same defect, different spelling"
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
        try: proc.wait(timeout=2)
        except Exception: pass
        os.unlink(conf)

check("empty trusted_proxy fails closed", test_empty_trusted_proxy_fails_closed)

# --- rejection is logged with the REAL peer, never the claimed one ------
def test_rejection_logs_real_peer():
    lp = free_port(); bp = free_port()
    conf = write_conf(listen=f"127.0.0.1:{lp}", proxy=f"127.0.0.1:{bp}",
                      trusted_proxy="203.0.113.10")
    set_proc(start(conf))
    try:
        assert wait_listening(lp), "listener did not come up"
        s = socket.create_connection(('127.0.0.1', lp), timeout=3)
        s.sendall(b"PROXY TCP4 1.2.3.4 5.6.7.8 12345 70\r\nx\n")
        s.settimeout(2)
        try: s.recv(64)
        except OSError: pass
        s.close()
        time.sleep(0.3)
        if proc.poll() is None:
            proc.terminate()
        try: proc.wait(timeout=2)
        except Exception: pass
        err = stderr_of(proc)
        # The claimed address is 1.2.3.4 and the real peer is 127.0.0.1.
        # An audit line that names 1.2.3.4 for a rejected connection is
        # actively misleading, so require the real peer to be present.
        assert "127.0.0.1" in err, \
            f"rejection log does not name the real peer 127.0.0.1: {err.strip()[:300]!r}"
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
        try: proc.wait(timeout=2)
        except Exception: pass
        os.unlink(conf)

check("rejection logs real peer", test_rejection_logs_real_peer)

# --- IPv4-mapped IPv6 trust comparison ----------------------------------
def test_ipv4_mapped_ipv6_trusted():
    # sockaddr_ip_equal() has an explicit IPv4-mapped-IPv6 case, and it had
    # no coverage at all. It cannot be reached through proxyto's own listener:
    # main() pins IPV6_V6ONLY=1 on every AF_INET6 listener (proxyto.c:1327),
    # so a [::] listener is not dual-stack and an IPv4 client can never
    # arrive as ::ffff:a.b.c.d. The branch is defensive, not dead - which
    # makes an untested defensive branch the worst kind to leave.
    #
    # To exercise it honestly it has to be driven directly rather than
    # through a socket, so it is asserted at the source level instead. This
    # test is kept as a reminder that the socket path does NOT reach it.
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.close()
    except OSError:
        skip("no IPv6 on this host")
    lp = free_port(); bp = free_port()
    conf = write_conf(listen=f"[::]:{lp}", proxy=f"127.0.0.1:{bp}",
                      trusted_proxy="127.0.0.1")
    got = []
    def be():
        s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('127.0.0.1', bp)); s.listen(1); s.settimeout(4)
        try:
            c, a = s.accept(); c.settimeout(3)
            got.append(c.recv(4096)); c.close()
        except OSError:
            pass
        s.close()
    t = threading.Thread(target=be); t.start()
    set_proc(start(conf))
    try:
        up = False
        end = time.time() + 3
        while time.time() < end:
            if proc_exited():
                break
            try:
                s = socket.create_connection(('127.0.0.1', lp), timeout=0.3)
                s.close(); up = True; break
            except OSError:
                time.sleep(0.05)
        if not up:
            skip("proxyto pins IPV6_V6ONLY=1, so no [::] listener is dual-stack; "
                 "the mapped branch is not reachable over a socket")
        s = socket.create_connection(('127.0.0.1', lp), timeout=3)
        s.sendall(b"PROXY TCP4 1.2.3.4 5.6.7.8 12345 70\r\nmapped\n")
        s.settimeout(3)
        try: s.recv(16)
        except OSError: pass
        s.close()
        t.join(timeout=4)
        assert got and got[0] == b"mapped\n", \
            f"IPv4-mapped peer not matched against IPv4 trust entry (got {got!r})"
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
        try: proc.wait(timeout=2)
        except Exception: pass
        os.unlink(conf)

check("IPv4-mapped IPv6 (socket path, expected unreachable)", test_ipv4_mapped_ipv6_trusted)

_failed = [n for n, e in _results if e is not None]
print()
if _failed:
    print(f"trust boundary: {len(_failed)} of {len(_results)} FAILED: " + ", ".join(_failed))
    sys.exit(1)
print(f"trust boundary: OK ({len(_results)} checks)")
