import socket, subprocess, time, os, sys, tempfile, threading, struct

BIN = sys.argv[1] if len(sys.argv)>1 else "./proxyto"

def free_port():
    s=socket.socket(); s.bind(('127.0.0.1',0)); p=s.getsockname()[1]; s.close(); return p

def check(name, fn):
    try:
        fn()
        print(f"PASS {name}")
    except _Skip as e:
        print(f"SKIP {name} ({e})")
    except AssertionError as e:
        print(f"FAIL {name}: {e}")
        import traceback; traceback.print_exc()
        sys.exit(1)
    except Exception as e:
        print(f"FAIL {name}: {e}")
        import traceback; traceback.print_exc()
        sys.exit(1)

class _Skip(Exception):
    pass

def skip(reason):
    raise _Skip(reason)

# --- v1 TCP4 ---
def test_v1_tcp4():
    lp=free_port(); bp=free_port()
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as f:
        f.write(f"listen=127.0.0.1:{lp}\nproxy=127.0.0.1:{bp}\ntrusted_proxy=127.0.0.1\n"); conf=f.name
    recv=[]
    def be():
        s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        s.bind(('127.0.0.1',bp)); s.listen(1); s.settimeout(5)
        c,a=s.accept(); c.settimeout(5); d=c.recv(4096); recv.append(d); c.sendall(b"r:"+d); c.close(); s.close()
    t=threading.Thread(target=be); t.start()
    p=subprocess.Popen([BIN,"-c",conf], stderr=subprocess.PIPE)
    time.sleep(0.4)
    s=socket.socket(); s.connect(('127.0.0.1',lp)); s.sendall(b"PROXY TCP4 1.2.3.4 5.6.7.8 12345 70\r\nhello\n"); s.settimeout(2); resp=s.recv(4096); s.close()
    p.terminate(); p.wait(timeout=2); t.join(timeout=2); os.unlink(conf)
    assert recv[0]==b"hello\n", f"recv {recv[0]!r}"
    assert resp==b"r:hello\n"

check("v1 TCP4", test_v1_tcp4)

# --- v1 TCP6 ---
def test_v1_tcp6():
    lp=free_port(); bp=free_port()
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as f:
        f.write(f"listen=127.0.0.1:{lp}\nproxy=127.0.0.1:{bp}\ntrusted_proxy=127.0.0.1\n"); conf=f.name
    recv=[]
    def be():
        s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        s.bind(('127.0.0.1',bp)); s.listen(1); s.settimeout(5)
        c,a=s.accept(); c.settimeout(5); d=c.recv(4096); recv.append(d); c.sendall(b"r:"+d); c.close(); s.close()
    t=threading.Thread(target=be); t.start()
    p=subprocess.Popen([BIN,"-c",conf], stderr=subprocess.PIPE)
    time.sleep(0.4)
    s=socket.socket(); s.connect(('127.0.0.1',lp)); s.sendall(b"PROXY TCP6 2001:db8::1 2001:db8::2 12345 70\r\nworld\n"); s.settimeout(2); resp=s.recv(4096); s.close()
    p.terminate(); p.wait(timeout=2); t.join(timeout=2); os.unlink(conf)
    assert recv[0]==b"world\n"
    assert resp==b"r:world\n"

check("v1 TCP6", test_v1_tcp6)

# --- v1 UNKNOWN ---
def test_v1_unknown():
    lp=free_port(); bp=free_port()
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as f:
        f.write(f"listen=127.0.0.1:{lp}\nproxy=127.0.0.1:{bp}\ntrusted_proxy=127.0.0.1\n"); conf=f.name
    recv=[]
    def be():
        s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        s.bind(('127.0.0.1',bp)); s.listen(1); s.settimeout(5)
        c,a=s.accept(); c.settimeout(5); d=c.recv(4096); recv.append(d); c.sendall(b"r:"+d); c.close(); s.close()
    t=threading.Thread(target=be); t.start()
    p=subprocess.Popen([BIN,"-c",conf], stderr=subprocess.PIPE)
    time.sleep(0.4)
    s=socket.socket(); s.connect(('127.0.0.1',lp)); s.sendall(b"PROXY UNKNOWN\r\npayload\n"); s.settimeout(2); resp=s.recv(4096); s.close()
    p.terminate(); p.wait(timeout=2); t.join(timeout=2); os.unlink(conf)
    assert recv[0]==b"payload\n"
    assert resp==b"r:payload\n"

check("v1 UNKNOWN", test_v1_unknown)

# --- v1 heading zero reject ---
def test_v1_heading_zero():
    lp=free_port(); bp=free_port()
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as f:
        f.write(f"listen=127.0.0.1:{lp}\nproxy=127.0.0.1:{bp}\ntrusted_proxy=127.0.0.1\n"); conf=f.name
    p=subprocess.Popen([BIN,"-c",conf], stderr=subprocess.PIPE)
    time.sleep(0.4)
    s=socket.socket(); s.connect(('127.0.0.1',lp)); s.sendall(b"PROXY TCP4 01.2.3.4 5.6.7.8 12345 70\r\nhello\n"); s.settimeout(1)
    try:
        d=s.recv(4096)
        assert d==b'' or len(d)==0, f"should be rejected, got {d!r}"
    except (ConnectionResetError, BrokenPipeError):
        pass
    except socket.timeout:
        pass
    finally: s.close(); p.terminate(); p.wait(timeout=2); os.unlink(conf)

check("v1 heading zero reject", test_v1_heading_zero)

# --- v2 basic ---
def test_v2():
    lp=free_port(); bp=free_port()
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as f:
        f.write(f"listen=127.0.0.1:{lp}\nproxy=127.0.0.1:{bp}\ntrusted_proxy=127.0.0.1\n"); conf=f.name
    recv=[]
    def be():
        s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        s.bind(('127.0.0.1',bp)); s.listen(1); s.settimeout(5)
        c,a=s.accept(); c.settimeout(5); d=c.recv(4096); recv.append(d); c.sendall(b"r:"+d); c.close(); s.close()
    t=threading.Thread(target=be); t.start()
    p=subprocess.Popen([BIN,"-c",conf], stderr=subprocess.PIPE)
    time.sleep(0.4)
    sig=b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a"
    addr=struct.pack("!4s4sHH", socket.inet_aton("1.2.3.4"), socket.inet_aton("5.6.7.8"), 12345, 70)
    hdr=sig+bytes([0x21,0x11])+struct.pack("!H", len(addr))+addr
    s=socket.socket(); s.connect(('127.0.0.1',lp)); s.sendall(hdr+b"v2payload\n"); s.settimeout(2); resp=s.recv(4096); s.close()
    p.terminate(); p.wait(timeout=2); t.join(timeout=2); os.unlink(conf)
    assert recv[0]==b"v2payload\n"
    assert resp==b"r:v2payload\n"

check("v2 basic", test_v2)

# --- v2 authority ---
def test_v2_auth():
    lp=free_port(); bp=free_port()
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as f:
        f.write(f"listen=127.0.0.1:{lp}\nproxy=127.0.0.1:{bp}\ntrusted_proxy=127.0.0.1\n"); conf=f.name
    recv=[]
    def be():
        s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        s.bind(('127.0.0.1',bp)); s.listen(1); s.settimeout(5)
        c,a=s.accept(); c.settimeout(5); d=c.recv(4096); recv.append(d); c.sendall(b"r:"+d); c.close(); s.close()
    t=threading.Thread(target=be); t.start()
    p=subprocess.Popen([BIN,"-c",conf], stderr=subprocess.PIPE)
    time.sleep(0.4)
    sig=b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a"
    addr=struct.pack("!4s4sHH", socket.inet_aton("1.1.1.1"), socket.inet_aton("2.2.2.2"), 1111, 70)
    auth=b"gopher.example"
    tlv=struct.pack("!BH", 0x02, len(auth))+auth
    length=len(addr)+len(tlv)
    hdr=sig+bytes([0x21,0x11])+struct.pack("!H", length)+addr+tlv
    s=socket.socket(); s.connect(('127.0.0.1',lp)); s.sendall(hdr+b"sel\n"); s.settimeout(2); resp=s.recv(4096); s.close()
    p.terminate(); p.wait(timeout=2); t.join(timeout=2); os.unlink(conf)
    assert recv[0]==b"sel\n"
    assert resp==b"r:sel\n"

check("v2 authority", test_v2_auth)

# --- v2 unknown TLV skip ---
def test_v2_unknown_tlv():
    lp=free_port(); bp=free_port()
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as f:
        f.write(f"listen=127.0.0.1:{lp}\nproxy=127.0.0.1:{bp}\ntrusted_proxy=127.0.0.1\n"); conf=f.name
    recv=[]
    def be():
        s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        s.bind(('127.0.0.1',bp)); s.listen(1); s.settimeout(5)
        c,a=s.accept(); c.settimeout(5); d=c.recv(4096); recv.append(d); c.sendall(b"r:"+d); c.close(); s.close()
    t=threading.Thread(target=be); t.start()
    p=subprocess.Popen([BIN,"-c",conf], stderr=subprocess.PIPE)
    time.sleep(0.4)
    sig=b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a"
    addr=struct.pack("!4s4sHH", socket.inet_aton("1.2.3.4"), socket.inet_aton("5.6.7.8"), 12345, 70)
    unknown=struct.pack("!BH", 0xE0, 4)+b"\xaa\xbb\xcc\xdd"
    length=len(addr)+len(unknown)
    hdr=sig+bytes([0x21,0x11])+struct.pack("!H", length)+addr+unknown
    s=socket.socket(); s.connect(('127.0.0.1',lp)); s.sendall(hdr+b"ok\n"); s.settimeout(2); resp=s.recv(4096); s.close()
    p.terminate(); p.wait(timeout=2); t.join(timeout=2); os.unlink(conf)
    assert recv[0]==b"ok\n"

check("v2 unknown TLV skip", test_v2_unknown_tlv)

# --- v2 LOCAL ---
def test_v2_local():
    lp=free_port(); bp=free_port()
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as f:
        f.write(f"listen=127.0.0.1:{lp}\nproxy=127.0.0.1:{bp}\ntrusted_proxy=127.0.0.1\n"); conf=f.name
    recv=[]
    def be():
        s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        s.bind(('127.0.0.1',bp)); s.listen(1); s.settimeout(5)
        c,a=s.accept(); c.settimeout(5); d=c.recv(4096); recv.append(d); c.sendall(b"r:"+d); c.close(); s.close()
    t=threading.Thread(target=be); t.start()
    p=subprocess.Popen([BIN,"-c",conf], stderr=subprocess.PIPE)
    time.sleep(0.4)
    sig=b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a"
    hdr=sig+bytes([0x20,0x00])+struct.pack("!H", 0)
    s=socket.socket(); s.connect(('127.0.0.1',lp)); s.sendall(hdr+b"local\n"); s.settimeout(2); resp=s.recv(4096); s.close()
    p.terminate(); p.wait(timeout=2); t.join(timeout=2); os.unlink(conf)
    assert recv[0]==b"local\n"

check("v2 LOCAL", test_v2_local)

# --- plain reject ---
def test_plain_reject():
    lp=free_port(); bp=free_port()
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as f:
        f.write(f"listen=127.0.0.1:{lp}\nproxy=127.0.0.1:{bp}\ntrusted_proxy=127.0.0.1\n"); conf=f.name
    p=subprocess.Popen([BIN,"-c",conf], stderr=subprocess.PIPE)
    time.sleep(0.4)
    s=socket.socket(); s.connect(('127.0.0.1',lp)); s.sendall(b"GET / HTTP/1.0\r\n\r\n"); s.settimeout(1)
    try:
        d=s.recv(4096)
        if d not in (b'', None): raise AssertionError(f"should reject plain, got {d!r}")
    except (ConnectionResetError, BrokenPipeError):
        pass
    except socket.timeout:
        raise AssertionError("timeout, expected close")
    finally: s.close(); p.terminate(); p.wait(timeout=2); os.unlink(conf)

check("plain reject", test_plain_reject)

# --- partial header (1 byte at a time) ---
def test_partial():
    lp=free_port(); bp=free_port()
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as f:
        f.write(f"listen=127.0.0.1:{lp}\nproxy=127.0.0.1:{bp}\ntrusted_proxy=127.0.0.1\n"); conf=f.name
    recv=[]
    def be():
        s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        s.bind(('127.0.0.1',bp)); s.listen(1); s.settimeout(5)
        c,a=s.accept(); c.settimeout(2)
        data=b""
        # collect with timeout loop
        c.settimeout(0.5)
        start=time.time()
        while time.time()-start<2:
            try:
                x=c.recv(4096)
                if not x: break
                data+=x
                if data.endswith(b"partial\n"): break
            except socket.timeout:
                break
        recv.append(data)
        c.sendall(b"r:"+data); c.close(); s.close()
    t=threading.Thread(target=be); t.start()
    p=subprocess.Popen([BIN,"-c",conf], stderr=subprocess.PIPE)
    time.sleep(0.4)
    s=socket.socket(); s.connect(('127.0.0.1',lp))
    hdr=b"PROXY TCP4 1.2.3.4 5.6.7.8 12345 70\r\npartial\n"
    for b in hdr:
        s.send(bytes([b])); time.sleep(0.005)
    s.settimeout(2); resp=s.recv(4096); s.close()
    p.terminate(); p.wait(timeout=2); t.join(timeout=2); os.unlink(conf)
    assert recv[0]==b"partial\n", f"recv {recv[0]!r}"
    assert resp==b"r:partial\n", f"resp {resp!r}"

check("partial header", test_partial)

# --- bidirectional + half-close ---
def test_bidir():
    lp=free_port(); bp=free_port()
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as f:
        f.write(f"listen=127.0.0.1:{lp}\nproxy=127.0.0.1:{bp}\ntrusted_proxy=127.0.0.1\n"); conf=f.name
    def be():
        s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        s.bind(('127.0.0.1',bp)); s.listen(1); s.settimeout(5)
        c,a=s.accept(); c.settimeout(5)
        d=c.recv(4096)
        c.sendall(b"echo:"+d)
        try: c.shutdown(socket.SHUT_WR)
        except: pass
        try:
            while True:
                x=c.recv(4096)
                if not x: break
        except: pass
        c.close(); s.close()
    t=threading.Thread(target=be); t.start()
    p=subprocess.Popen([BIN,"-c",conf], stderr=subprocess.PIPE)
    time.sleep(0.4)
    s=socket.socket(); s.connect(('127.0.0.1',lp))
    s.sendall(b"PROXY TCP4 1.2.3.4 5.6.7.8 12345 70\r\nping\n")
    s.settimeout(2); resp=s.recv(4096)
    s.shutdown(socket.SHUT_WR)
    try:
        while True:
            s.settimeout(1); x=s.recv(4096)
            if not x: break
    except: pass
    s.close()
    p.terminate(); p.wait(timeout=2); t.join(timeout=2); os.unlink(conf)
    assert resp==b"echo:ping\n", f"resp {resp!r}"

check("bidir half-close", test_bidir)

# --- bracket IPv6 config parse ---
def test_bracket_config():
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as f:
        f.write(f"listen=[::1]:{free_port()}\nproxy=127.0.0.1:{free_port()}\ntrusted_proxy=::1\n"); conf=f.name
    p=subprocess.Popen([BIN,"-c",conf], stderr=subprocess.PIPE)
    time.sleep(0.4)
    assert p.poll() is None, "should be running with [::1] listen"
    p.terminate(); p.wait(timeout=2); os.unlink(conf)

check("bracket IPv6 config", test_bracket_config)

# --- byte identity (no leak) ---
def test_no_leak():
    lp=free_port(); bp=free_port()
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as f:
        f.write(f"listen=127.0.0.1:{lp}\nproxy=127.0.0.1:{bp}\ntrusted_proxy=127.0.0.1\n"); conf=f.name
    payload=b"\x00\xff\xfe\xfd gopher \r\n binary \x00 data"
    recv=[]
    def be():
        s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        s.bind(('127.0.0.1',bp)); s.listen(1); s.settimeout(5)
        c,a=s.accept(); c.settimeout(5); d=c.recv(4096); recv.append(d); c.sendall(d); c.close(); s.close()
    t=threading.Thread(target=be); t.start()
    p=subprocess.Popen([BIN,"-c",conf], stderr=subprocess.PIPE)
    time.sleep(0.4)
    s=socket.socket(); s.connect(('127.0.0.1',lp)); s.sendall(b"PROXY TCP4 1.2.3.4 5.6.7.8 1234 70\r\n"+payload); s.settimeout(2); resp=s.recv(4096); s.close()
    p.terminate(); p.wait(timeout=2); t.join(timeout=2); os.unlink(conf)
    assert recv[0]==payload, f"leak {recv[0]!r} != {payload!r}"
    assert resp==payload

check("byte identity no leak", test_no_leak)

# --- concurrent clients ---
def test_concurrent():
    lp=free_port(); bp=free_port()
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as f:
        f.write(f"listen=127.0.0.1:{lp}\nproxy=127.0.0.1:{bp}\ntrusted_proxy=127.0.0.1\n"); conf=f.name
    # backend that handles 5 sequential connections
    results=[]
    def be():
        s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        s.bind(('127.0.0.1',bp)); s.listen(5); s.settimeout(5)
        for _ in range(5):
            try:
                c,a=s.accept(); c.settimeout(5); d=c.recv(4096); c.sendall(b"r:"+d); c.close()
            except: break
        s.close()
    t=threading.Thread(target=be); t.start()
    p=subprocess.Popen([BIN,"-c",conf], stderr=subprocess.PIPE)
    time.sleep(0.4)
    def client_task(msg):
        s=socket.socket(); s.connect(('127.0.0.1',lp)); s.sendall(b"PROXY TCP4 1.2.3.4 5.6.7.8 12345 70\r\n"+msg); s.settimeout(2); resp=s.recv(4096); s.close(); results.append((msg,resp))
    threads=[threading.Thread(target=client_task, args=(f"msg{i}\n".encode(),)) for i in range(5)]
    for th in threads: th.start()
    for th in threads: th.join()
    p.terminate(); p.wait(timeout=2); t.join(timeout=2); os.unlink(conf)
    assert len(results)==5
    for msg,resp in results:
        assert resp==b"r:"+msg, f"{msg!r} got {resp!r}"

check("concurrent 5 clients", test_concurrent)

# --- config knobs (header_timeout/connect_timeout/buffer_size/service_type) ---
def _drain(p):
    try:
        _, err = p.communicate(timeout=2)
    except Exception:
        try: p.kill()
        except Exception: pass
        _, err = p.communicate(timeout=2)
    return err.decode(errors="replace") if isinstance(err, bytes) else (err or "")

def test_config_knobs():
    lp=free_port(); bp=free_port()
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as f:
        f.write(f"listen=127.0.0.1:{lp}\nproxy=127.0.0.1:{bp}\ntrusted_proxy=127.0.0.1\nheader_timeout=1000\nconnect_timeout=2000\nbuffer_size=32768\nservice_type=postgres\n"); conf=f.name
    def be():
        s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        s.bind(('127.0.0.1',bp)); s.listen(1); s.settimeout(5)
        c,a=s.accept(); c.settimeout(5); d=c.recv(4096); c.sendall(b"r:"+d); c.close(); s.close()
    t=threading.Thread(target=be); t.start()
    p=subprocess.Popen([BIN,"-c",conf], stderr=subprocess.PIPE)
    time.sleep(0.4)
    s=socket.socket(); s.connect(('127.0.0.1',lp)); s.sendall(b"PROXY TCP4 1.2.3.4 5.6.7.8 12345 70\r\nknobs\n"); s.settimeout(2); resp=s.recv(4096); s.close()
    p.terminate(); err=_drain(p); p.wait(timeout=2); t.join(timeout=2); os.unlink(conf)
    assert resp==b"r:knobs\n", f"knobs exchange failed: {resp!r}"
    assert "service_type=postgres" in err, f"startup log missing service_type: {err!r}"
    assert "header_timeout=1000" in err and "connect_timeout=2000" in err and "buffer_size=32768" in err, f"startup log missing knobs: {err!r}"

def test_config_knobs_reject():
    for bad in ["header_timeout=5\n", "connect_timeout=9999999\n", "buffer_size=1024\n", "buffer_size=notanumber\n", "service_type=has space\n", "service_type=\n"]:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as f:
            f.write(f"listen=127.0.0.1:1\nproxy=127.0.0.1:1\n{bad}"); conf=f.name
        p=subprocess.Popen([BIN,"-c",conf], stderr=subprocess.PIPE)
        try:
            rc=p.wait(timeout=3)
        finally:
            try: p.kill()
            except Exception: pass
            err=_drain(p); os.unlink(conf)
        assert rc!=0, f"bad knob accepted: {bad!r}"
        assert "invalid" in err or "must be" in err, f"no validation message for {bad!r}: {err!r}"

# --- segmented v2 header must be accepted, not rejected ---
def test_v2_small_segments():
    lp=free_port(); bp=free_port()
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as f:
        f.write(f"listen=127.0.0.1:{lp}\nproxy=127.0.0.1:{bp}\ntrusted_proxy=127.0.0.1\n"); conf=f.name
    def be():
        s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        s.bind(('127.0.0.1',bp)); s.listen(1); s.settimeout(8)
        c,a=s.accept(); c.settimeout(8); d=c.recv(4096); c.sendall(b"r:"+d); c.close(); s.close()
    t=threading.Thread(target=be); t.start()
    p=subprocess.Popen([BIN,"-c",conf], stderr=subprocess.PIPE)
    time.sleep(0.4)
    hdr=struct.pack("!12sBBH",b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a",0x21,0x11,12)+socket.inet_aton("1.2.3.4")+socket.inet_aton("5.6.7.8")+struct.pack("!HH",12345,70)
    s=socket.socket(); s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1); s.connect(('127.0.0.1',lp))
    for b in hdr:
        s.sendall(bytes([b])); time.sleep(0.002)
    s.sendall(b"seg\n"); s.settimeout(5); resp=s.recv(4096); s.close()
    p.terminate(); p.wait(timeout=2); t.join(timeout=2); os.unlink(conf)
    assert resp==b"r:seg\n", f"segmented v2 rejected: {resp!r}"

# --- privilege drop (need root; account-gated with SKIP) ---
def _have_account():
    try:
        import pwd
        pwd.getpwnam("proxyto"); return True
    except Exception:
        return False

def test_privdrop_refuse_no_account():
    if os.geteuid()!=0:
        skip("needs root")
    if _have_account():
        skip("proxyto account exists here")
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as f:
        f.write("listen=127.0.0.1:1\nproxy=127.0.0.1:1\n"); conf=f.name
    p=subprocess.Popen([BIN,"-c",conf], stderr=subprocess.PIPE)
    try:
        rc=p.wait(timeout=3)
    finally:
        try: p.kill()
        except Exception: pass
        err=_drain(p); os.unlink(conf)
    assert rc!=0, "started as root without proxyto account instead of refusing"
    assert "does not exist" in err and "refusing" in err, f"no refusal message: {err!r}"

def _free_priv_port():
    import pwd
    for port in (79, 179, 101):
        s=socket.socket()
        try:
            s.bind(('127.0.0.1',port)); s.close(); return port
        except OSError:
            continue
    return None

def test_privdrop_ids():
    if os.geteuid()!=0:
        skip("needs root")
    if not _have_account():
        skip("needs proxyto account")
    import pwd
    want_uid=pwd.getpwnam("proxyto").pw_uid; want_gid=pwd.getpwnam("proxyto").pw_gid
    port=_free_priv_port()
    if port is None:
        skip("no free privileged probe port")
    lp=port; bp=free_port()
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as f:
        f.write(f"listen=127.0.0.1:{lp}\nproxy=127.0.0.1:{bp}\ntrusted_proxy=127.0.0.1\n"); conf=f.name
    def be():
        s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        s.bind(('127.0.0.1',bp)); s.listen(1); s.settimeout(8)
        c,a=s.accept(); c.settimeout(8); d=c.recv(4096); c.sendall(b"r:"+d); c.close(); s.close()
    t=threading.Thread(target=be); t.start()
    p=subprocess.Popen([BIN,"-c",conf], stderr=subprocess.PIPE)
    time.sleep(0.6)
    s=socket.socket(); s.connect(('127.0.0.1',lp)); s.sendall(b"PROXY TCP4 9.9.9.9 8.8.8.8 1111 70\r\ndrop\n"); s.settimeout(5); resp=s.recv(4096); s.close()
    p.terminate(); err=_drain(p); p.wait(timeout=2); t.join(timeout=2); os.unlink(conf)
    assert resp==b"r:drop\n", f"post-drop exchange failed (bind-before-drop broken?): {resp!r}"
    assert f"now running as proxyto:proxyto (uid={want_uid} gid={want_gid})" in err, f"drop verification missing: {err!r}"

# --- child reap: no lingering zombies while idle ---
def _zombie_children(pid):
    try:
        with open(f"/proc/{pid}/task/{pid}/children") as f:
            kids = f.read().split()
    except OSError:
        return []
    out = []
    for k in kids:
        try:
            with open(f"/proc/{k}/stat") as f:
                state = f.read().rsplit(')', 1)[1].split()[0]
                if state == 'Z':
                    out.append(k)
        except OSError:
            pass
    return out

def test_reap_no_zombie():
    lp=free_port(); bp=free_port()
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as f:
        f.write(f"listen=127.0.0.1:{lp}\nproxy=127.0.0.1:{bp}\ntrusted_proxy=127.0.0.1\n"); conf=f.name
    def be():
        s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        s.bind(('127.0.0.1',bp)); s.listen(5); s.settimeout(8)
        for _ in range(3):
            try:
                c,a=s.accept(); c.settimeout(8); d=c.recv(4096); c.sendall(d); c.close()
            except: break
        s.close()
    t=threading.Thread(target=be); t.start()
    p=subprocess.Popen([BIN,"-c",conf], stderr=subprocess.PIPE)
    time.sleep(0.4)
    for i in range(3):
        s=socket.socket(); s.connect(('127.0.0.1',lp)); s.sendall(b"PROXY TCP4 1.2.3.4 5.6.7.8 12345 70\r\n"+f"z{i}\n".encode()); s.settimeout(2); s.recv(4096); s.close()
    # children have exited; the daemon is now idle with no further
    # connections arriving - reaping must already have happened
    dead = _zombie_children(p.pid)
    for _ in range(20):
        if not dead:
            break
        time.sleep(0.1)
        dead = _zombie_children(p.pid)
    p.terminate(); p.wait(timeout=2); t.join(timeout=2); os.unlink(conf)
    assert not dead, f"zombie children linger while idle: {dead}"

check("config knobs accepted", test_config_knobs)
check("config knobs rejected", test_config_knobs_reject)
check("v2 small segments accepted", test_v2_small_segments)
check("privdrop refuse without account", test_privdrop_refuse_no_account)
check("privdrop ids after drop", test_privdrop_ids)
check("no zombie children while idle", test_reap_no_zombie)

print("\nAll tests passed")
