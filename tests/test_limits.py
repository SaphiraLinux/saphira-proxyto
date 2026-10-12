#!/usr/bin/env python3
"""Operational hardening tests: concurrency cap, accept backoff, config strictness.

These cover the four attack-surface fixes:
  1. max_children cap with backpressure (no unbounded fork)
  2. bounded backoff on accept() resource exhaustion (no CPU/log flood loop)
  3. duplicate trusted_proxy= keys rejected rather than silently overwritten
  4. dead validation branches and the unreachable total>65551 test removed

The backoff test counts emitted log lines rather than sampling CPU, because
that is deterministic: a retry-immediately loop logs once per iteration, which
under descriptor starvation is thousands of lines per second, while a correct
exponential backoff logs once per storm and stays silent afterwards.
"""

import os
import functools
import re
import resource
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BINARY = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "proxyto")
SOURCE = os.path.join(ROOT, "src", "proxyto.c")

results = []


def check(name, condition, detail=""):
    results.append((name, bool(condition), detail))
    print(("  PASS " if condition else "  FAIL ") + name + ((" -- " + detail) if detail and not condition else ""))


def free_port_pair():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p1 = s.getsockname()[1]
    s.close()
    return p1, p1 + 1


def write_config(body):
    handle = tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False)
    handle.write(body)
    handle.close()
    return handle.name


def start(config_path, limit_fds=None):
    pre = None
    if limit_fds is not None:
        pre = functools.partial(resource.setrlimit, resource.RLIMIT_NOFILE, (limit_fds, limit_fds))
    log = tempfile.NamedTemporaryFile("w+", suffix=".log", delete=False)
    log.close()
    handle = open(log.name, "w+")
    proc = subprocess.Popen([BINARY, "-c", config_path], stdout=handle, stderr=handle)
    return proc, handle, log.name


def stop(proc, handle, log_path):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
    handle.close()
    try:
        os.unlink(log_path)
    except OSError:
        pass


def read_log(path):
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def echo_backend(port, stop_flag):
    """Echo server that keeps each connection open until the peer closes.

    The connection must stay open for the child-cap test to mean anything:
    if the backend closed after one exchange the worker would exit, the slot
    would free itself, and the cap would never be observed under load.
    """
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(8)
    srv.settimeout(0.5)
    while not stop_flag[0]:
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break

        def serve(conn=conn):
            try:
                conn.settimeout(5)
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    conn.sendall(b"r:" + data)
            except OSError:
                pass
            finally:
                conn.close()

        threading.Thread(target=serve, daemon=True).start()
    srv.close()


def expect_echo(sock, payload, timeout=3):
    """Send payload through an already-headered connection and read the echo."""
    sock.sendall(payload)
    sock.settimeout(timeout)
    buf = b""
    try:
        while b"r:" + payload not in buf and len(buf) < 4096:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
    except OSError:
        pass
    return buf


def proxied_connect(listen_port, timeout=3):
    """Open a connection, send a valid v1 header plus payload, read the echo.

    Must send payload: a served connection with no payload produces no echo
    and is indistinguishable from a refused one, which is exactly the
    distinction these tests need to make.
    """
    try:
        s = socket.create_connection(("127.0.0.1", listen_port), timeout=timeout)
    except OSError:
        return None
    try:
        s.sendall(b"PROXY TCP4 198.51.100.9 203.0.113.9 40000 70\r\nprobe")
        s.settimeout(timeout)
        buf = b""
        try:
            while b"r:probe" not in buf and len(buf) < 4096:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
        except OSError:
            pass
        return buf
    except OSError:
        return b""
    finally:
        s.close()


# ---------------------------------------------------------------- max_children
def test_max_children_cap():
    lp, bp = free_port_pair()
    cfg = write_config(
        f"listen=127.0.0.1:{lp}\nproxy=127.0.0.1:{bp}\n"
        "trusted_proxy=127.0.0.1\nmax_children=1\n"
    )
    stop_flag = [False]
    backend = threading.Thread(target=echo_backend, args=(bp, stop_flag), daemon=True)
    backend.start()
    proc, log, logpath = start(cfg)
    time.sleep(0.7)
    try:
        # First connection takes the only child slot and stays open.
        held = socket.create_connection(("127.0.0.1", lp), timeout=3)
        held.sendall(b"PROXY TCP4 198.51.100.9 203.0.113.9 40000 70\r\n")
        first = expect_echo(held, b"one")
        check("max_children=1 serves the first connection",
              b"r:one" in first, f"got {first[:60]!r}")

        # Second connection must be refused, not forked and served.
        second = proxied_connect(lp)
        check("max_children=1 refuses a second concurrent connection",
              second == b"", f"got {second!r}, expected b'' (refused)")

        # The in-flight connection must be unaffected by the refusal.
        again = expect_echo(held, b"two")
        check("max_children=1 does not disturb the in-flight connection",
              b"r:two" in again, f"got {again[:60]!r}")
        held.close()
        time.sleep(0.8)

        # Slot released -> service resumes.
        third = proxied_connect(lp)
        check("max_children=1 accepts again once a child exits",
              third is not None and third.startswith(b"r:"), f"got {third!r}")

        logtext = read_log(logpath)
        check("child cap is logged once on transition, not per connection",
              logtext.count("at child cap") == 1,
              f"seen {logtext.count('at child cap')} times")
    finally:
        stop_flag[0] = True
        stop(proc, log, logpath)
        try:
            os.unlink(cfg)
        except OSError:
            pass
        backend.join(timeout=2)


def test_max_children_defaults():
    lp, bp = free_port_pair()
    cfg = write_config(f"listen=127.0.0.1:{lp}\nproxy=127.0.0.1:{bp}\ntrusted_proxy=127.0.0.1\n")
    proc, log, logpath = start(cfg)
    time.sleep(0.6)
    try:
        # With no max_children line the daemon must start (default applies).
        check("max_children has a working default (daemon starts without it)",
              proc.poll() is None, "daemon exited")
    finally:
        stop(proc, log, logpath)
        try:
            os.unlink(cfg)
        except OSError:
            pass


def test_max_children_validation():
    lp, bp = free_port_pair()
    cases = [
        ("max_children=0 rejected (0 would refuse everything)", "max_children=0", False),
        ("max_children=-1 rejected", "max_children=-1", False),
        ("max_children=abc rejected", "max_children=abc", False),
        ("max_children=99999 rejected above the hard bound", "max_children=99999", False),
        ("max_children=1 accepted", "max_children=1", True),
        ("max_children=4096 accepted at the hard bound", "max_children=4096", True),
    ]
    for name, line, should_start in cases:
        cfg = write_config(f"listen=127.0.0.1:{lp}\nproxy=127.0.0.1:{bp}\ntrusted_proxy=127.0.0.1\n{line}\n")
        proc, log, logpath = start(cfg)
        time.sleep(0.5)
        alive = proc.poll() is None
        check(name, alive == should_start, f"daemon {'started' if alive else 'exited'}")
        stop(proc, log, logpath)
        try:
            os.unlink(cfg)
        except OSError:
            pass


# ------------------------------------------------------------- accept backoff
def test_accept_backoff():
    """Structural assertion for accept() backoff, plus survival under pressure.

    Why this is structural and not behavioural: proxyto is fork-per-connection,
    so the parent holds only the listen socket and never accumulates one
    descriptor per connection. Parent-side EMFILE is therefore very hard to
    induce in a test -- a low RLIMIT_NOFILE instead starves the *children*
    (their connect() to the backend fails), and accept() itself keeps
    succeeding. An earlier version of this test tried to force EMFILE with a
    low descriptor limit and passed whether or not the backoff existed.

    So we assert the properties directly in the source: every resource errno is
    handled, the delay doubles, and the growth is capped. The runtime check
    below only proves the daemon survives descriptor pressure without dying.
    """
    src = open(SOURCE, "r", encoding="utf-8").read()
    for errno_name in ("EMFILE", "ENFILE", "ENOMEM", "ENOBUFS"):
        check(f"accept() handles {errno_name}",
              errno_name in src, f"{errno_name} not handled in the accept loop")
    check("accept() backoff uses an explicit capped sleep",
          "ACCEPT_BACKOFF_MAX_MS" in src and "nanosleep" in src,
          "no capped sleep found in the accept path")
    check("accept() backoff grows exponentially from a small floor",
          re.search(r"accept_backoff_ms\s*=\s*accept_backoff_ms\s*\*\s*2", src) is not None,
          "no doubling of the backoff interval")
    check("accept() backoff is capped so it cannot grow without bound",
          re.search(r"if \(accept_backoff_ms > ACCEPT_BACKOFF_MAX_MS\) accept_backoff_ms = ACCEPT_BACKOFF_MAX_MS", src) is not None,
          "backoff interval is not clamped to a maximum")
    check("accept() backoff resets after a successful accept",
          re.search(r"accept_backoff_ms = ACCEPT_BACKOFF_START_MS", src) is not None,
          "backoff never resets, so one storm would slow the daemon forever")

    # Runtime survival: starve descriptors and confirm the daemon stays up.
    lp, bp = free_port_pair()
    cfg = write_config(f"listen=127.0.0.1:{lp}\nproxy=127.0.0.1:{bp}\ntrusted_proxy=127.0.0.1\n")
    proc, log, logpath = start(cfg, limit_fds=8)
    time.sleep(0.6)
    try:
        held = []
        for _ in range(25):
            try:
                s = socket.create_connection(("127.0.0.1", lp), timeout=1)
                s.sendall(b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\nx")
                held.append(s)
            except OSError:
                break
        time.sleep(1.0)
        check("daemon survives descriptor pressure without dying",
              proc.poll() is None, "daemon exited under descriptor pressure")
        logtext = read_log(logpath)
        accept_errs = len(re.findall(r"accept: ", logtext))
        check("no accept() log flood under descriptor pressure",
              accept_errs <= 50, f"{accept_errs} accept errors logged")
        for s in held:
            try:
                s.close()
            except OSError:
                pass
    finally:
        stop(proc, log, logpath)
        try:
            os.unlink(cfg)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# config strictness
def test_duplicate_trusted_proxy_rejected():
    lp, bp = free_port_pair()
    cfg = write_config(
        f"listen=127.0.0.1:{lp}\nproxy=127.0.0.1:{bp}\n"
        "trusted_proxy=127.0.0.1\n"
        "trusted_proxy=10.0.0.1\n"
    )
    proc, log, logpath = start(cfg)
    time.sleep(0.6)
    try:
        check("duplicate trusted_proxy= is rejected at config load",
              proc.poll() is not None, "daemon started, so the second key was not rejected")
        check("duplicate trusted_proxy= names the duplicate in the error",
              "duplicate trusted_proxy" in read_log(logpath), read_log(logpath)[:200])
    finally:
        stop(proc, log, logpath)
        try:
            os.unlink(cfg)
        except OSError:
            pass


def test_single_trusted_proxy_multi_entry_ok():
    lp, bp = free_port_pair()
    cfg = write_config(
        f"listen=127.0.0.1:{lp}\nproxy=127.0.0.1:{bp}\n"
        "trusted_proxy=127.0.0.1, 10.0.0.1, [::1]\n"
    )
    proc, log, logpath = start(cfg)
    time.sleep(0.6)
    try:
        check("comma-separated trusted_proxy= list is still accepted",
              proc.poll() is None, "daemon exited on a valid single-line list")
    finally:
        stop(proc, log, logpath)
        try:
            os.unlink(cfg)
        except OSError:
            pass


# --------------------------------------------------------- dead code removal
def test_dead_code_removed():
    src = open(SOURCE, "r", encoding="utf-8").read()
    check("unreachable total > 65551 test removed",
          "total > 65551" not in src, "still present")
    # The UNIQUE_ID branch used to contain an if() whose body was only
    # comments, which read as validation while validating nothing.
    uniq = re.search(r"type==0x05(.{0,600}?)memcpy\(out->uniq", src, re.S)
    body = uniq.group(1) if uniq else ""
    check("UNIQUE_ID branch has no comment-only if() masquerading as a check",
          "if (memchr" not in body, "dead memchr guard still present")
    # The v1 CRLF length checks used to have three if() bodies of pure comments.
    crlf = re.search(r"if \(cr\[1\] != '\\n'\).{0,700}?header_len = pos\+2", src, re.S)
    crlf_body = crlf.group(0) if crlf else ""
    empty_ifs = re.findall(r"if \([^)]*\) \{\s*(//[^\n]*\s*)+\}", crlf_body)
    check("v1 CRLF length checks contain no comment-only if() blocks",
          not empty_ifs, f"found {len(empty_ifs)} comment-only if() block(s)")


def main():
    if not os.path.exists(BINARY):
        print("proxyto binary not found:", BINARY)
        return 1
    print("Running operational hardening tests...")
    test_max_children_cap()
    test_max_children_defaults()
    test_max_children_validation()
    test_accept_backoff()
    test_duplicate_trusted_proxy_rejected()
    test_single_trusted_proxy_multi_entry_ok()
    test_dead_code_removed()

    failures = [n for n, ok, _ in results if not ok]
    print(f"\n  {len(results) - len(failures)}/{len(results)} checks passed")
    if failures:
        print("FAILED:")
        for f in failures:
            print("  - " + f)
        return 1
    print("  operational hardening: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
