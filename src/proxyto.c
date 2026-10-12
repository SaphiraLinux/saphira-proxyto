#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <fcntl.h>
#include <poll.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <time.h>
#include <grp.h>
#include <pwd.h>

#define PROG "proxyto"
#define DEFAULT_CONF_DIR "/etc/saphira/proxyto"
#ifndef POLLRDHUP
#define POLLRDHUP 0x2000
#endif
#define HEADER_TIMEOUT_MS 5000
#define CONNECT_TIMEOUT_MS 5000
#define BUF_SIZE 16384
/* The three values above are the defaults for the per-service config
 * knobs header_timeout=, connect_timeout=, buffer_size= (milliseconds,
 * milliseconds, bytes). Defaults mirror haproxy practice: 5s connect
 * timeout, 16KiB tune.bufsize. */
#define MIN_TIMEOUT_MS 100
#define MAX_TIMEOUT_MS 300000
#define MIN_BUFFER_SIZE 4096
#define MAX_BUFFER_SIZE 1048576
/* Concurrency cap. Every accepted connection forks a worker, so without a
 * cap a peer that reaches this listener (or a trusted peer that leaks
 * connections) can fork until it exhausts PIDs, fds, or memory. At the cap
 * we stop accepting new work rather than queueing it, which is the
 * behaviour haproxy's maxconn provides. The hard bound exists so a
 * misconfigured max_children= cannot itself become the denial of service. */
#define DEFAULT_MAX_CHILDREN 256
#define MAX_CHILDREN_HARD 4096
/* Consecutive accept() resource failures (EMFILE/ENFILE/ENOMEM/ENOBUFS)
 * mean the process table or descriptor table is full. Retrying immediately
 * spins the accept loop at full speed and floods the log, so back off
 * exponentially and reset on the first success. */
#define ACCEPT_BACKOFF_START_MS 10
#define ACCEPT_BACKOFF_MAX_MS 1000
/* Dedicated runtime account. The daemon starts as root only to bind
 * privileged ports, then permanently drops to this account before
 * accepting anything. Never a backend application's account. */
#define PROXYTO_USER "proxyto"
#define PROXYTO_GROUP "proxyto"
#define MAX_V1_LINE 108
#define V2_SIG "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"
#define V2_SIG_LEN 12

static int opt_syslog = 0;
static const char *prog_name = PROG;
static const char *conf_name_global = NULL;
/* Live worker count. Written by the SIGCHLD handler and by the accept
 * loop, so it must be sig_atomic_t; the handler is the only reaper, so
 * the counter cannot drift from the actual process table. */
static volatile sig_atomic_t live_children = 0;

static void vlog_msg(const char *fmt, va_list ap) {
    if (opt_syslog) {
        vsyslog(LOG_INFO, fmt, ap);
    } else {
        vfprintf(stderr, fmt, ap);
        fputc('\n', stderr);
    }
}

static void log_msg(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vlog_msg(fmt, ap);
    va_end(ap);
}

static void log_err(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    if (opt_syslog) {
        vsyslog(LOG_ERR, fmt, ap);
    } else {
        fprintf(stderr, "%s: ", prog_name);
        vfprintf(stderr, fmt, ap);
        fputc('\n', stderr);
    }
    va_end(ap);
}

/* config */
#define MAX_TRUSTED 32
struct config {
    char application[512];
    char listen_raw[512];
    char proxy_raw[512];
    char listen_host[256];
    char listen_port[32];
    char proxy_host[256];
    char proxy_port[32];
    char trusted_raw[1024];
    struct sockaddr_storage trusted_addrs[MAX_TRUSTED];
    int trusted_count;
    char name[128];
    int header_timeout_ms;
    int connect_timeout_ms;
    size_t buffer_size;
    int max_children;
    /* Backend service label (gopher, postgres, ssh, ...). Validated
     * identifier used in logs; reserves the namespace for future
     * per-service relay tuning without complicating the core loop. */
    char service_type[64];
};

static char *trim(char *s) {
    char *e;
    while (*s && isspace((unsigned char)*s)) s++;
    if (*s == '\0') return s;
    e = s + strlen(s) - 1;
    while (e > s && isspace((unsigned char)*e)) { *e = '\0'; e--; }
    return s;
}

static int parse_host_port(const char *raw, char *host_out, size_t host_sz, char *port_out, size_t port_sz) {
    // raw is like 172.16.0.2:70 or [2001:db8::1]:70
    if (!raw || !*raw) return -1;
    if (raw[0] == '[') {
        const char *end = strchr(raw, ']');
        if (!end) return -1;
        size_t hlen = (size_t)(end - raw - 1);
        if (hlen == 0 || hlen >= host_sz) return -1;
        memcpy(host_out, raw+1, hlen);
        host_out[hlen] = '\0';
        if (end[1] != ':') return -1;
        const char *port = end + 2;
        if (*port == '\0') return -1;
        if (strlen(port) >= port_sz) return -1;
        // port must be digits, no leading zero check later
        for (const char *p = port; *p; p++) if (!isdigit((unsigned char)*p)) return -1;
        strncpy(port_out, port, port_sz-1);
        port_out[port_sz-1]='\0';
        return 0;
    } else {
        // must contain exactly one ':'
        int colons = 0;
        for (const char *p = raw; *p; p++) if (*p == ':') colons++;
        if (colons != 1) return -1; // IPv6 must use brackets
        const char *colon = strrchr(raw, ':');
        if (!colon) return -1;
        size_t hlen = (size_t)(colon - raw);
        if (hlen == 0 || hlen >= host_sz) return -1;
        memcpy(host_out, raw, hlen);
        host_out[hlen] = '\0';
        const char *port = colon + 1;
        if (*port == '\0') return -1;
        if (strlen(port) >= port_sz) return -1;
        for (const char *p = port; *p; p++) if (!isdigit((unsigned char)*p)) return -1;
        strncpy(port_out, port, port_sz-1);
        port_out[port_sz-1]='\0';
        return 0;
    }
}

static int validate_port_str(const char *p) {
    if (!p || !*p) return -1;
    if (p[0]=='0' && p[1]!='\0') return -1; // heading zero
    size_t len = strlen(p);
    if (len==0 || len>5) return -1;
    for (size_t i=0;i<len;i++) if (!isdigit((unsigned char)p[i])) return -1;
    long v = strtol(p, NULL, 10);
    if (v<0 || v>65535) return -1;
    return 0;
}

static int is_valid_ipv4_octets(const char *s) {
    // check heading zero per octet
    int parts=0;
    const char *p=s;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t len = dot ? (size_t)(dot-p) : strlen(p);
        if (len==0||len>3) return -1;
        if (len>1 && p[0]=='0') return -1;
        for (size_t i=0;i<len;i++) if (!isdigit((unsigned char)p[i])) return -1;
        char tmp[4]; memcpy(tmp,p,len); tmp[len]='\0';
        long v=strtol(tmp,NULL,10);
        if (v<0||v>255) return -1;
        parts++;
        if (!dot) break;
        p=dot+1;
    }
    return parts==4?0:-1;
}

static int parse_ip_literal(const char *s, struct sockaddr_storage *out) {
    // s is trimmed, may be bracketed [ipv6]; brackets stripped by caller if needed
    // try IPv4 then IPv6
    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, s, &a4)==1) {
        memset(out,0,sizeof(*out));
        struct sockaddr_in *sin=(struct sockaddr_in*)out;
        sin->sin_family=AF_INET;
        sin->sin_addr=a4;
        return 0;
    }
    if (inet_pton(AF_INET6, s, &a6)==1) {
        memset(out,0,sizeof(*out));
        struct sockaddr_in6 *sin6=(struct sockaddr_in6*)out;
        sin6->sin6_family=AF_INET6;
        memcpy(&sin6->sin6_addr, &a6, 16);
        return 0;
    }
    return -1;
}

static int parse_trusted_proxy_list(const char *raw, struct config *cfg, const char *path, int lineno) {
    cfg->trusted_count=0;
    if (!raw) {
        cfg->trusted_raw[0]='\0';
        return 0;
    }
    // store raw
    if (strlen(raw) >= sizeof(cfg->trusted_raw)) {
        log_err("%s:%d: trusted_proxy too long", path, lineno);
        return -1;
    }
    strncpy(cfg->trusted_raw, raw, sizeof(cfg->trusted_raw)-1);
    cfg->trusted_raw[sizeof(cfg->trusted_raw)-1]='\0';

    char work[1024];
    strncpy(work, raw, sizeof(work)-1);
    work[sizeof(work)-1]='\0';

    // check empty (no restriction)
    char *t = trim(work);
    if (*t=='\0') {
        cfg->trusted_count=0;
        return 0;
    }

    // split by comma
    char *saveptr=NULL;
    char *tok = strtok_r(work, ",", &saveptr);
    while (tok) {
        char *ip = trim(tok);
        if (*ip=='\0') {
            log_err("%s:%d: trusted_proxy: empty entry", path, lineno);
            return -1;
        }
        // allow bracketed IPv6 [::1]
        if (ip[0]=='[') {
            size_t l=strlen(ip);
            if (l<3 || ip[l-1]!=']') {
                log_err("%s:%d: trusted_proxy: invalid bracketed address '%s'", path, lineno, ip);
                return -1;
            }
            ip[l-1]='\0';
            ip++;
            ip = trim(ip);
            if (*ip=='\0') {
                log_err("%s:%d: trusted_proxy: empty bracketed address", path, lineno);
                return -1;
            }
        }
        if (cfg->trusted_count >= MAX_TRUSTED) {
            log_err("%s:%d: trusted_proxy: too many entries (max %d)", path, lineno, MAX_TRUSTED);
            return -1;
        }
        struct sockaddr_storage ss;
        if (parse_ip_literal(ip, &ss)!=0) {
            log_err("%s:%d: trusted_proxy: invalid IP '%s'", path, lineno, ip);
            return -1;
        }
        cfg->trusted_addrs[cfg->trusted_count++] = ss;
        tok = strtok_r(NULL, ",", &saveptr);
    }
    return 0;
}

static int sockaddr_ip_equal(const struct sockaddr_storage *a, const struct sockaddr_storage *b) {
    if (a->ss_family != b->ss_family) {
        // handle IPv4-mapped IPv6: ::ffff:a.b.c.d vs a.b.c.d
        // if one is AF_INET and other is AF_INET6 mapped, compare mapped part
        if (a->ss_family==AF_INET && b->ss_family==AF_INET6) {
            const struct sockaddr_in6 *b6=(const struct sockaddr_in6*)b;
            if (IN6_IS_ADDR_V4MAPPED(&b6->sin6_addr)) {
                struct in_addr b4;
                memcpy(&b4, &b6->sin6_addr.s6_addr[12], 4);
                const struct sockaddr_in *a4=(const struct sockaddr_in*)a;
                return memcmp(&a4->sin_addr, &b4, 4)==0;
            }
        } else if (a->ss_family==AF_INET6 && b->ss_family==AF_INET) {
            const struct sockaddr_in6 *a6=(const struct sockaddr_in6*)a;
            if (IN6_IS_ADDR_V4MAPPED(&a6->sin6_addr)) {
                struct in_addr a4;
                memcpy(&a4, &a6->sin6_addr.s6_addr[12], 4);
                const struct sockaddr_in *b4=(const struct sockaddr_in*)b;
                return memcmp(&a4, &b4->sin_addr, 4)==0;
            }
        }
        return 0;
    }
    if (a->ss_family==AF_INET) {
        const struct sockaddr_in *a4=(const struct sockaddr_in*)a;
        const struct sockaddr_in *b4=(const struct sockaddr_in*)b;
        return memcmp(&a4->sin_addr, &b4->sin_addr, 4)==0;
    } else if (a->ss_family==AF_INET6) {
        const struct sockaddr_in6 *a6=(const struct sockaddr_in6*)a;
        const struct sockaddr_in6 *b6=(const struct sockaddr_in6*)b;
        return memcmp(&a6->sin6_addr, &b6->sin6_addr, 16)==0;
    }
    return 0;
}

static int is_trusted_peer(const struct sockaddr_storage *peer, const struct config *cfg) {
    // Defence in depth. Startup already refuses to run with an empty list,
    // so this should be unreachable - but the consequence of getting it wrong
    // is that a direct client asserts an identity we then trust, and that is
    // not a failure worth leaving one branch away from. No list means nobody.
    if (cfg->trusted_count==0) return 0;
    for (int i=0;i<cfg->trusted_count;i++) {
        if (sockaddr_ip_equal(peer, &cfg->trusted_addrs[i])) return 1;
    }
    return 0;
}

static int parse_timeout_ms(const char *val, int *out) {
    if (!val || !*val) return -1;
    for (const char *p=val; *p; p++) if (!isdigit((unsigned char)*p)) return -1;
    if (strlen(val)>6) return -1;
    long v = strtol(val, NULL, 10);
    if (v<MIN_TIMEOUT_MS || v>MAX_TIMEOUT_MS) return -1;
    *out = (int)v;
    return 0;
}

static int parse_buffer_size(const char *val, size_t *out) {
    if (!val || !*val) return -1;
    for (const char *p=val; *p; p++) if (!isdigit((unsigned char)*p)) return -1;
    if (strlen(val)>7) return -1;
    long v = strtol(val, NULL, 10);
    if (v<MIN_BUFFER_SIZE || v>MAX_BUFFER_SIZE) return -1;
    *out = (size_t)v;
    return 0;
}

/* max_children is a count, not a duration: digits only, positive, and
 * capped by MAX_CHILDREN_HARD. A value of 0 would refuse everything, so
 * the minimum is 1. */
static int parse_max_children(const char *val, int *out) {
    if (!val || !*val) return -1;
    for (const char *p=val; *p; p++) if (!isdigit((unsigned char)*p)) return -1;
    if (strlen(val)>6) return -1;
    long v = strtol(val, NULL, 10);
    if (v<1 || v>MAX_CHILDREN_HARD) return -1;
    *out = (int)v;
    return 0;
}

static int valid_service_type(const char *val) {    size_t len = strlen(val);
    if (len==0 || len>=64) return -1;
    for (const char *p=val; *p; p++) {
        unsigned char c=(unsigned char)*p;
        if (!isalnum(c) && c!='_' && c!='-' && c!='.' && c!='+') return -1;
    }
    return 0;
}

static int load_config(const char *path, struct config *cfg) {
    FILE *f = fopen(path, "r");
    if (!f) {
        log_err("cannot open config %s: %s", path, strerror(errno));
        return -1;
    }
    char line[1024];
    int has_listen=0, has_proxy=0;
    int lineno=0;
    // init
    cfg->application[0]='\0';
    cfg->listen_raw[0]='\0';
    cfg->proxy_raw[0]='\0';
    cfg->trusted_raw[0]='\0';
    cfg->trusted_count=0;
    cfg->header_timeout_ms=HEADER_TIMEOUT_MS;
    cfg->connect_timeout_ms=CONNECT_TIMEOUT_MS;
    cfg->buffer_size=BUF_SIZE;
    cfg->max_children=DEFAULT_MAX_CHILDREN;
    snprintf(cfg->service_type, sizeof(cfg->service_type), "generic");
    char trusted_pending[1024] = "";
    int has_trusted_pending=0;
    while (fgets(line, sizeof(line), f)) {
        lineno++;
        // strip newline
        line[strcspn(line, "\r\n")]='\0';
        char *t = trim(line);
        if (*t=='\0' || *t=='#' || *t==';') continue;
        char *eq = strchr(t, '=');
        if (!eq) {
            log_err("%s:%d: invalid line (no '='): %s", path, lineno, t);
            fclose(f);
            return -1;
        }
        *eq='\0';
        char *key = trim(t);
        char *val = trim(eq+1);
        if (strcmp(key,"application")==0) {
            if (strlen(val)>=sizeof(cfg->application)) { log_err("%s:%d: application too long",path,lineno); fclose(f); return -1; }
            strncpy(cfg->application,val,sizeof(cfg->application)-1);
        } else if (strcmp(key,"listen")==0) {
            if (strlen(val)>=sizeof(cfg->listen_raw)) { log_err("%s:%d: listen too long",path,lineno); fclose(f); return -1; }
            strncpy(cfg->listen_raw,val,sizeof(cfg->listen_raw)-1);
            has_listen=1;
        } else if (strcmp(key,"proxy")==0) {
            if (strlen(val)>=sizeof(cfg->proxy_raw)) { log_err("%s:%d: proxy too long",path,lineno); fclose(f); return -1; }
            strncpy(cfg->proxy_raw,val,sizeof(cfg->proxy_raw)-1);
            has_proxy=1;
        } else if (strcmp(key,"trusted_proxy")==0) {
            /* A second trusted_proxy= line silently overwriting the first
             * would leave the operator believing both peers are trusted
             * when only the last one is. That is exactly the kind of
             * quiet narrowing this parser must not do by accident, so
             * treat a repeat as a hard error like an unknown key. */
            if (has_trusted_pending) {
                log_err("%s:%d: duplicate trusted_proxy= (define all peers on one comma-separated line)",path,lineno);
                fclose(f);
                return -1;
            }
            if (strlen(val)>=sizeof(trusted_pending)) { log_err("%s:%d: trusted_proxy too long",path,lineno); fclose(f); return -1; }
            strncpy(trusted_pending, val, sizeof(trusted_pending)-1);
            trusted_pending[sizeof(trusted_pending)-1]='\0';
            has_trusted_pending=1;
        } else if (strcmp(key,"header_timeout")==0) {
            if (parse_timeout_ms(val, &cfg->header_timeout_ms)!=0) { log_err("%s:%d: header_timeout must be %d..%d ms",path,lineno,MIN_TIMEOUT_MS,MAX_TIMEOUT_MS); fclose(f); return -1; }
        } else if (strcmp(key,"connect_timeout")==0) {
            if (parse_timeout_ms(val, &cfg->connect_timeout_ms)!=0) { log_err("%s:%d: connect_timeout must be %d..%d ms",path,lineno,MIN_TIMEOUT_MS,MAX_TIMEOUT_MS); fclose(f); return -1; }
          } else if (strcmp(key,"buffer_size")==0) {
              if (parse_buffer_size(val, &cfg->buffer_size)!=0) { log_err("%s:%d: buffer_size must be %d..%d bytes",path,lineno,MIN_BUFFER_SIZE,MAX_BUFFER_SIZE); fclose(f); return -1; }
          } else if (strcmp(key,"max_children")==0) {
              if (parse_max_children(val, &cfg->max_children)!=0) { log_err("%s:%d: max_children must be 1..%d",path,lineno,MAX_CHILDREN_HARD); fclose(f); return -1; }
        } else if (strcmp(key,"service_type")==0) {
            if (valid_service_type(val)!=0) { log_err("%s:%d: service_type must be 1..63 chars of [A-Za-z0-9_.+-]",path,lineno); fclose(f); return -1; }
            snprintf(cfg->service_type, sizeof(cfg->service_type), "%s", val);
        } else {
            log_err("%s:%d: unknown key '%s'", path, lineno, key);
            fclose(f);
            return -1;
        }
    }
    fclose(f);
    if (has_trusted_pending) {
        if (parse_trusted_proxy_list(trusted_pending, cfg, path, lineno)!=0) return -1;
    }
    if (!has_listen) { log_err("%s: missing listen=", path); return -1; }
    if (!has_proxy) { log_err("%s: missing proxy=", path); return -1; }
    // parse host/port
    if (parse_host_port(cfg->listen_raw, cfg->listen_host, sizeof(cfg->listen_host), cfg->listen_port, sizeof(cfg->listen_port))!=0) {
        log_err("%s: invalid listen '%s' (use 1.2.3.4:70 or [ipv6]:70)", path, cfg->listen_raw);
        return -1;
    }
    if (parse_host_port(cfg->proxy_raw, cfg->proxy_host, sizeof(cfg->proxy_host), cfg->proxy_port, sizeof(cfg->proxy_port))!=0) {
        log_err("%s: invalid proxy '%s' (use 1.2.3.4:70 or [ipv6]:70)", path, cfg->proxy_raw);
        return -1;
    }
    if (validate_port_str(cfg->listen_port)!=0 || validate_port_str(cfg->proxy_port)!=0) {
        log_err("%s: invalid port (heading zero or out of range)", path);
        return -1;
    }
    // verify listen/proxy host is numeric? allow via getaddrinfo check later.
    // application field optional; if present check not empty
    return 0;
}

static int set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl==-1) return -1;
    if (fcntl(fd, F_SETFL, fl | O_NONBLOCK)==-1) return -1;
    return 0;
}

static void format_sockaddr(const struct sockaddr_storage *ss, char *out, size_t outsz, char *port_out, size_t port_sz) {
    if (ss->ss_family==AF_INET) {
        const struct sockaddr_in *sin=(const struct sockaddr_in*)ss;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
        snprintf(out, outsz, "%s", ip);
        snprintf(port_out, port_sz, "%u", ntohs(sin->sin_port));
    } else if (ss->ss_family==AF_INET6) {
        const struct sockaddr_in6 *sin6=(const struct sockaddr_in6*)ss;
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
        snprintf(out, outsz, "%s", ip);
        snprintf(port_out, port_sz, "%u", ntohs(sin6->sin6_port));
    } else {
        snprintf(out, outsz, "unknown");
        snprintf(port_out, port_sz, "0");
    }
}

static void format_client_log(const struct sockaddr_storage *src, char *out, size_t outsz) {
    char ip[INET6_ADDRSTRLEN];
    char port[32];
    format_sockaddr(src, ip, sizeof(ip), port, sizeof(port));
    if (src->ss_family==AF_INET6) {
        snprintf(out, outsz, "[%s]:%s", ip, port);
    } else {
        snprintf(out, outsz, "%s:%s", ip, port);
    }
}

/* v1 helpers */
static int v1_validate_and_extract(const char *line, size_t linelen, struct sockaddr_storage *src, struct sockaddr_storage *dst) {
    // line is NUL terminated without CRLF, linelen is without CRLF
    // expected "PROXY ..."
    if (linelen < 5) return -1;
    // use manual tokenization
    // copy to mutable? line already mutable
    // count tokens by spaces
    // We need to handle UNKNOWN with variable tokens
    // Approach: split by single space, but ensure exactly one space between tokens
    // Quick check: no double spaces, no leading/trailing spaces already because spec
    // For simplicity, tokenise using strtok but validate exactly one space by checking for "  "
    if (strstr(line, "  ")!=NULL) return -1;
    // token array
    char *saveptr=NULL;
    // we need mutable copy; line is mutable
    char *p = (char*)line;
    // first token must be PROXY
    char *tok = strtok_r(p, " ", &saveptr);
    if (!tok || strcmp(tok,"PROXY")!=0) return -1;
    char *proto = strtok_r(NULL, " ", &saveptr);
    if (!proto) return -1;
    if (strcmp(proto,"UNKNOWN")==0) {
        // accept any remainder, treat as local
        return 1; // indicates UNKNOWN/LOCAL
    } else if (strcmp(proto,"TCP4")==0) {
        char *saddr = strtok_r(NULL, " ", &saveptr);
        char *daddr = strtok_r(NULL, " ", &saveptr);
        char *sport = strtok_r(NULL, " ", &saveptr);
        char *dport = strtok_r(NULL, " ", &saveptr);
        char *extra = strtok_r(NULL, " ", &saveptr);
        if (!saddr||!daddr||!sport||!dport||extra) return -1;
        if (validate_port_str(sport)!=0||validate_port_str(dport)!=0) return -1;
        if (is_valid_ipv4_octets(saddr)!=0||is_valid_ipv4_octets(daddr)!=0) return -1;
        struct in_addr sa, da;
        if (inet_pton(AF_INET,saddr,&sa)!=1) return -1;
        if (inet_pton(AF_INET,daddr,&da)!=1) return -1;
        long sp = strtol(sport,NULL,10);
        long dp = strtol(dport,NULL,10);
        memset(src,0,sizeof(*src));
        memset(dst,0,sizeof(*dst));
        struct sockaddr_in *sin=(struct sockaddr_in*)src;
        sin->sin_family=AF_INET;
        sin->sin_addr=sa;
        sin->sin_port=htons((uint16_t)sp);
        struct sockaddr_in *din=(struct sockaddr_in*)dst;
        din->sin_family=AF_INET;
        din->sin_addr=da;
        din->sin_port=htons((uint16_t)dp);
        return 0;
    } else if (strcmp(proto,"TCP6")==0) {
        char *saddr = strtok_r(NULL, " ", &saveptr);
        char *daddr = strtok_r(NULL, " ", &saveptr);
        char *sport = strtok_r(NULL, " ", &saveptr);
        char *dport = strtok_r(NULL, " ", &saveptr);
        char *extra = strtok_r(NULL, " ", &saveptr);
        if (!saddr||!daddr||!sport||!dport||extra) return -1;
        if (validate_port_str(sport)!=0||validate_port_str(dport)!=0) return -1;
        struct in6_addr sa6, da6;
        if (inet_pton(AF_INET6,saddr,&sa6)!=1) return -1;
        if (inet_pton(AF_INET6,daddr,&da6)!=1) return -1;
        long sp = strtol(sport,NULL,10);
        long dp = strtol(dport,NULL,10);
        memset(src,0,sizeof(*src));
        memset(dst,0,sizeof(*dst));
        struct sockaddr_in6 *sin6=(struct sockaddr_in6*)src;
        sin6->sin6_family=AF_INET6;
        memcpy(&sin6->sin6_addr,&sa6,16);
        sin6->sin6_port=htons((uint16_t)sp);
        struct sockaddr_in6 *din6=(struct sockaddr_in6*)dst;
        din6->sin6_family=AF_INET6;
        memcpy(&din6->sin6_addr,&da6,16);
        din6->sin6_port=htons((uint16_t)dp);
        return 0;
    } else {
        return -1;
    }
}

struct parsed_hdr {
    struct sockaddr_storage src;
    struct sockaddr_storage dst;
    int is_local; // 1 if LOCAL/UNKNOWN -> use real peer
    char authority[256];
    size_t authority_len;
    char alpn[256];
    size_t alpn_len;
    char uniq[129];
    size_t uniq_len;
    uint8_t *surplus;
    size_t surplus_len;
    size_t header_len; // total header bytes consumed
};

static int check_authority_value(const uint8_t *v, size_t len) {
    if (len==0) return -1;
    for (size_t i=0;i<len;i++) {
        uint8_t c=v[i];
        if (c==0) return -1;
        if (c<0x20 || c==0x7f) return -1;
    }
    return 0;
}

static int parse_proxy_header(int fd, struct parsed_hdr *out, const struct sockaddr_storage *real_src, const struct sockaddr_storage *real_dst, int timeout_ms) {
    memset(out,0,sizeof(*out));
    out->is_local=0;

    // heap buffer for header; start 16, grow to 16+len
    size_t cap = 16;
    uint8_t *buf = (uint8_t*)malloc(cap);
    if (!buf) return -1;
    size_t have=0;
    int header_complete=0;
    size_t header_len=0;
    // we need to allow up to 65535+16 = 65551 bytes per spec; allocate accordingly
    // but for v1 we only need up to 108
    // Use deadline polling with remaining timeout
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);

    while (!header_complete) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed = (now.tv_sec - start.tv_sec)*1000 + (now.tv_nsec - start.tv_nsec)/1000000;
        int rem = timeout_ms - (int)elapsed;
        if (rem < 0) rem = 0;
        if (rem<=0) { errno=ETIMEDOUT; free(buf); return -1; }
        // ensure cap > have
        if (have >= cap) {
            // Should not happen without resizing; but for v1 we may need up to 108
            if (cap < 108) {
                size_t ncap = 108;
                uint8_t *nb = realloc(buf, ncap);
                if (!nb) { free(buf); return -1; }
                buf=nb; cap=ncap;
            } else {
                // overflow
                free(buf); errno=EMSGSIZE; return -1;
            }
        }
        struct pollfd pfd; pfd.fd=fd; pfd.events=POLLIN; pfd.revents=0;
        int pr = poll(&pfd,1,rem);
        if (pr==0) { free(buf); errno=ETIMEDOUT; return -1; }
        if (pr<0) { if (errno==EINTR) continue; free(buf); return -1; }
        if (pfd.revents & (POLLERR|POLLHUP|POLLNVAL)) {
            // try recv anyway
        }
        ssize_t n;
        do { n=recv(fd, buf+have, cap-have, 0); } while (n==-1 && errno==EINTR);
        if (n==0) { free(buf); errno=ECONNRESET; return -1; }
        if (n<0) {
            if (errno==EAGAIN || errno==EWOULDBLOCK) continue;
            free(buf); return -1;
        }
        have += (size_t)n;

        // try to detect
        if (have >= 16 && memcmp(buf, V2_SIG, 12)==0 && (buf[12] & 0xF0)==0x20) {
            // v2
            uint16_t len_be;
            memcpy(&len_be, buf+14, 2);
            uint16_t len = ntohs(len_be);
            /* len is a uint16_t, so 16+len cannot exceed 65551. The
             * arithmetic is bounded by the wire type itself; an explicit
             * range test here would be unreachable rather than defensive. */
            size_t total = 16 + (size_t)len;
            if (total > cap) {
                uint8_t *nb = realloc(buf, total);
                if (!nb) { free(buf); return -1; }
                buf=nb; cap=total;
            }
            if (have < total) {
                // need more bytes
                continue;
            } else {
                // complete
                header_len = total;
                header_complete=1;
                // parse v2
                uint8_t ver_cmd = buf[12];
                uint8_t fam = buf[13];
                uint8_t cmd = ver_cmd & 0x0F;
                if (cmd!=0x00 && cmd!=0x01) { free(buf); errno=EPROTO; return -1; }
                if (cmd==0x00) {
                    out->is_local=1;
                    // still need to parse TLVs? For LOCAL, ignore but consume
                } else {
                    // PROXY command
                    // validate fam
                    //fam high 4 bits, low 4 bits
                    // For unsupported combos, treat as UNSPEC (is_local fallback?) but spec says fallback to UNSPEC = use real addresses
                    // We'll handle known TCP cases, else mark is_local=1 (use real)
                    size_t addr_len=0;
                    if (fam==0x11) addr_len=12;
                    else if (fam==0x21) addr_len=36;
                    else if (fam==0x00) { out->is_local=1; addr_len=0; }
                    else if (fam==0x12) addr_len=12; // UDP
                    else if (fam==0x22) addr_len=36;
                    else if (fam==0x31||fam==0x32) addr_len=216;
                    else {
                        // unspecified fam -> must reject? spec says must be rejected as invalid for version2 unspecified values
                        // but other values are unspecified and must not be emitted, must be rejected.
                        // So if fam nibble not 0-3 or proto not 0-2, reject
                        uint8_t fa = fam>>4;
                        uint8_t pr = fam & 0x0F;
                        if (fa>3 || pr>2) { free(buf); errno=EPROTO; return -1; }
                        // otherwise known but not implemented -> treat as UNSPEC fallback
                        out->is_local=1;
                        addr_len=0;
                        // But if len includes addr_len, we still skip it as part of TLV? Actually addr bytes are at offset 16
                        // For fallback, we ignore them.
                    }
                    if (!out->is_local) {
                        if (len < addr_len) { free(buf); errno=EPROTO; return -1; }
                        if (fam==0x11) {
                            // ipv4
                            uint32_t sa, da;
                            uint16_t sp, dp;
                            memcpy(&sa, buf+16, 4);
                            memcpy(&da, buf+20, 4);
                            memcpy(&sp, buf+24, 2);
                            memcpy(&dp, buf+26, 2);
                            memset(&out->src,0,sizeof(out->src));
                            memset(&out->dst,0,sizeof(out->dst));
                            struct sockaddr_in *sin=(struct sockaddr_in*)&out->src;
                            sin->sin_family=AF_INET;
                            sin->sin_addr.s_addr=sa;
                            sin->sin_port=sp;
                            struct sockaddr_in *din=(struct sockaddr_in*)&out->dst;
                            din->sin_family=AF_INET;
                            din->sin_addr.s_addr=da;
                            din->sin_port=dp;
                        } else if (fam==0x21) {
                            uint8_t sa[16], da[16];
                            uint16_t sp, dp;
                            memcpy(sa, buf+16, 16);
                            memcpy(da, buf+32, 16);
                            memcpy(&sp, buf+48, 2);
                            memcpy(&dp, buf+50, 2);
                            memset(&out->src,0,sizeof(out->src));
                            memset(&out->dst,0,sizeof(out->dst));
                            struct sockaddr_in6 *sin6=(struct sockaddr_in6*)&out->src;
                            sin6->sin6_family=AF_INET6;
                            memcpy(&sin6->sin6_addr, sa, 16);
                            sin6->sin6_port=sp;
                            struct sockaddr_in6 *din6=(struct sockaddr_in6*)&out->dst;
                            din6->sin6_family=AF_INET6;
                            memcpy(&din6->sin6_addr, da, 16);
                            din6->sin6_port=dp;
                        } else if (fam==0x12 || fam==0x22 || fam==0x31 || fam==0x32) {
                            // For now treat as UNSPEC fallback but still parse if UDP same layout as TCP
                            if (fam==0x12) {
                                uint32_t sa, da; uint16_t sp,dp;
                                memcpy(&sa,buf+16,4); memcpy(&da,buf+20,4); memcpy(&sp,buf+24,2); memcpy(&dp,buf+26,2);
                                memset(&out->src,0,sizeof(out->src)); memset(&out->dst,0,sizeof(out->dst));
                                struct sockaddr_in *sin=(struct sockaddr_in*)&out->src; sin->sin_family=AF_INET; sin->sin_addr.s_addr=sa; sin->sin_port=sp;
                                struct sockaddr_in *din=(struct sockaddr_in*)&out->dst; din->sin_family=AF_INET; din->sin_addr.s_addr=da; din->sin_port=dp;
                                out->is_local=0;
                            } else if (fam==0x22) {
                                uint8_t sa[16],da[16]; uint16_t sp,dp;
                                memcpy(sa,buf+16,16); memcpy(da,buf+32,16); memcpy(&sp,buf+48,2); memcpy(&dp,buf+50,2);
                                memset(&out->src,0,sizeof(out->src)); memset(&out->dst,0,sizeof(out->dst));
                                struct sockaddr_in6 *sin6=(struct sockaddr_in6*)&out->src; sin6->sin6_family=AF_INET6; memcpy(&sin6->sin6_addr,sa,16); sin6->sin6_port=sp;
                                struct sockaddr_in6 *din6=(struct sockaddr_in6*)&out->dst; din6->sin6_family=AF_INET6; memcpy(&din6->sin6_addr,da,16); din6->sin6_port=dp;
                                out->is_local=0;
                            } else {
                                out->is_local=1;
                            }
                        } else {
                            out->is_local=1;
                        }
                    }
                    // TLV parsing
                    size_t off = 16 + addr_len;
                    // For LOCAL, off =16
                    if (cmd==0x00) off=16; // for LOCAL, addr_len may be 0 but len may still have TLV? spec says LOCAL should have len 0 but receivers must skip
                    size_t remain = (total > off) ? total - off : 0;
                    size_t pos = off;
                    while (remain >= 3) {
                        uint8_t type = buf[pos];
                        uint16_t tlen = (uint16_t)((buf[pos+1]<<8)|buf[pos+2]);
                        if ((size_t)3 + tlen > remain) { free(buf); errno=EPROTO; return -1; }
                        const uint8_t *val = buf+pos+3;
                        if (type==0x02) { // AUTHORITY
                            if (check_authority_value(val,tlen)!=0) { free(buf); errno=EPROTO; return -1; }
                            size_t copy = tlen < sizeof(out->authority)-1 ? tlen : sizeof(out->authority)-1;
                            memcpy(out->authority, val, copy);
                            out->authority[copy]='\0';
                            out->authority_len=copy;
                        } else if (type==0x01) { // ALPN
                            size_t copy = tlen < sizeof(out->alpn)-1 ? tlen : sizeof(out->alpn)-1;
                            // reject NUL in ALPN as well
                            if (memchr(val,0,tlen)!=NULL) { free(buf); errno=EPROTO; return -1; }
                            memcpy(out->alpn,val,copy);
                            out->alpn[copy]='\0';
                            out->alpn_len=copy;
                        } else if (type==0x05) { // UNIQUE_ID up to 128
                            /* Opaque byte sequence. It is not validated as
                             * text: it is bounded, copied, and NUL
                             * terminated for logging. Embedded NULs simply
                             * truncate the logged form, which is harmless
                             * and cannot overrun the destination. */
                            size_t copy = tlen < sizeof(out->uniq)-1 ? tlen : sizeof(out->uniq)-1;
                            memcpy(out->uniq,val,copy);
                            out->uniq[copy]='\0';
                            out->uniq_len=copy;
                        } else {
                            // skip unknown including CRC32C, NOOP, SSL, etc.
                            // For SSL sub-TLVs, we just skip outer; no need to parse inner for safety
                        }
                        pos += 3 + tlen;
                        remain -= 3 + tlen;
                    }
                    if (remain!=0) { free(buf); errno=EPROTO; return -1; }
                    if (out->is_local) {
                        // use real addresses for logging
                        out->src = *real_src;
                        out->dst = *real_dst;
                    }
                }
                if (out->is_local) {
                    out->src = *real_src;
                    out->dst = *real_dst;
                }
                out->header_len = header_len;
                // surplus
                if (have > header_len) {
                    size_t slen = have - header_len;
                    out->surplus = (uint8_t*)malloc(slen);
                    if (!out->surplus) { free(buf); return -1; }
                    memcpy(out->surplus, buf+header_len, slen);
                    out->surplus_len = slen;
                } else {
                    out->surplus=NULL; out->surplus_len=0;
                }
                free(buf);
                return 0;
            }
        } else if (have >=5 && memcmp(buf, "PROXY",5)==0) {
            // v1 candidate
            // ensure we have searched for CRLF
            // need to find \r\n within first 107 bytes
            // if have >108, we already exceed max line without CRLF -> error
            if (have > 108) { free(buf); errno=EPROTO; return -1; }
            // search for \r
            uint8_t *cr = memchr(buf, '\r', have);
            if (cr) {
                size_t pos = (size_t)(cr - buf);
                if (pos+1 >= have) {
                    // need one more byte for \n, but we have not yet received it; wait
                    // if have ==108 and still not complete, error will be caught next loop
                    continue;
                }
                if (cr[1] != '\n') { free(buf); errno=EPROTO; return -1; }
                // CRLF found. Spec: a v1 line is at most 107 characters
                // including CRLF, so the header may not exceed MAX_V1_LINE.
                if (pos+2 > MAX_V1_LINE) { free(buf); errno=EMSGSIZE; return -1; }
                // For v1 we must have space for NUL
                header_len = pos+2;
                // NUL terminate for parsing
                // buf currently not NUL terminated; copy line to temp
                char line[MAX_V1_LINE+1];
                if (header_len >= sizeof(line)) { free(buf); errno=EMSGSIZE; return -1; }
                memcpy(line, buf, pos);
                line[pos]='\0';
                // Validate that line does not contain \n or \r before (already checked)
                // Now parse tokens
                // Need mutable for strtok_r, so use line
                struct sockaddr_storage vsrc, vdst;
                int pr = v1_validate_and_extract(line, pos, &vsrc, &vdst);
                if (pr==-1) { free(buf); errno=EPROTO; return -1; }
                if (pr==1) {
                    out->is_local=1;
                    out->src=*real_src;
                    out->dst=*real_dst;
                } else {
                    out->is_local=0;
                    out->src=vsrc;
                    out->dst=vdst;
                }
                out->header_len=header_len;
                if (have > header_len) {
                    size_t slen = have - header_len;
                    out->surplus = malloc(slen);
                    if (!out->surplus) { free(buf); return -1; }
                    memcpy(out->surplus, buf+header_len, slen);
                    out->surplus_len=slen;
                } else { out->surplus=NULL; out->surplus_len=0; }
                free(buf);
                return 0;
            } else {
                // no CR yet
                if (have >= 107) { free(buf); errno=EPROTO; return -1; }
                // need more data, but also need to grow cap to 108 if needed
                if (cap < 108 && have+1 > cap) {
                    uint8_t *nb = realloc(buf, 108);
                    if (!nb) { free(buf); return -1; }
                    buf=nb; cap=108;
                }
                continue;
            }
        } else if (have >=5) {
            // Reject only when the buffered bytes rule out BOTH a v1
            // header and a v2 signature prefix. Small TCP segments must
            // not kill a genuine v2 header still arriving: compare just
            // the bytes we have against the signature prefix and wait
            // for more on a prefix match.
            size_t cmp = have < V2_SIG_LEN ? have : V2_SIG_LEN;
            if (memcmp(buf, V2_SIG, cmp)!=0) {
                free(buf); errno=EPROTO; return -1;
            }
            // signature prefix so far (or full sig with have<16):
            // wait for the remaining bytes
            continue;
        } else {
            // have <5, continue reading
            continue;
        }
    }
    free(buf);
    return -1;
}

/* backend connect non-blocking */
static int connect_backend(const struct config *cfg, int timeout_ms) {
    struct addrinfo hints, *res, *rp;
    memset(&hints,0,sizeof(hints));
    hints.ai_family=AF_UNSPEC;
    hints.ai_socktype=SOCK_STREAM;
    // Use numeric host/port so no DNS delay? But keep generic
    char port_str[32];
    snprintf(port_str,sizeof(port_str),"%s",cfg->proxy_port);
    int s = getaddrinfo(cfg->proxy_host, cfg->proxy_port, &hints, &res);
    if (s!=0) {
        log_err("getaddrinfo proxy %s:%s: %s", cfg->proxy_host, cfg->proxy_port, gai_strerror(s));
        return -1;
    }
    int fd=-1;
    for (rp=res; rp!=NULL; rp=rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd==-1) continue;
        if (set_nonblock(fd)!=0) { close(fd); fd=-1; continue; }
        // optional TCP_NODELAY later after connect
        int r = connect(fd, rp->ai_addr, rp->ai_addrlen);
        if (r==0) {
            // immediate success (unlikely for localhost but ok)
            break;
        } else if (r==-1 && errno==EINPROGRESS) {
            struct pollfd pfd; pfd.fd=fd; pfd.events=POLLOUT; pfd.revents=0;
            int pr = poll(&pfd,1,timeout_ms);
            if (pr==0) { close(fd); fd=-1; errno=ETIMEDOUT; continue; }
            if (pr<0) { if (errno==EINTR) { close(fd); fd=-1; continue; } close(fd); fd=-1; continue; }
            int err=0; socklen_t elen=sizeof(err);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen)!=0) { close(fd); fd=-1; continue; }
            if (err!=0) { close(fd); fd=-1; errno=err; continue; }
            // connected
            break;
        } else {
            close(fd); fd=-1; continue;
        }
    }
    freeaddrinfo(res);
    if (fd==-1) return -1;
    // disable nonblock? Keep nonblock for relay, but we already set
    int one=1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    return fd;
}

/* relay */
static int relay_loop(int client_fd, int backend_fd, uint8_t *surplus, size_t surplus_len, uint64_t *rx_out, uint64_t *tx_out, size_t buf_size) {
    // surplus is initial client->backend data
    if (set_nonblock(client_fd)!=0) return -1;
    if (set_nonblock(backend_fd)!=0) return -1;

    uint8_t *c2b_buf = (uint8_t*)malloc(buf_size);
    uint8_t *b2c_buf = (uint8_t*)malloc(buf_size);
    if (!c2b_buf || !b2c_buf) { free(c2b_buf); free(b2c_buf); return -1; }
    size_t c2b_len=0, c2b_off=0;
    size_t b2c_len=0, b2c_off=0;
    // preload surplus into c2b
    if (surplus_len>0) {
        if (surplus_len > buf_size) {
            // surplus larger than buffer? Should not happen because surplus is tail after header (<buf_size), but handle by sending directly in loop
            // For now, handle by direct write before loop (blocking poll)
            size_t sent=0;
            while (sent < surplus_len) {
                struct pollfd pfd; pfd.fd=backend_fd; pfd.events=POLLOUT; pfd.revents=0;
                int pr=poll(&pfd,1,-1);
                if (pr<=0) { if (errno==EINTR) continue; free(c2b_buf); free(b2c_buf); return -1; }
                ssize_t n;
                do { n=send(backend_fd, surplus+sent, surplus_len-sent, 0); } while (n==-1 && errno==EINTR);
                if (n==-1) {
                    if (errno==EAGAIN||errno==EWOULDBLOCK) continue;
                    free(c2b_buf); free(b2c_buf); return -1;
                }
                sent+=(size_t)n;
            }
        } else {
            memcpy(c2b_buf, surplus, surplus_len);
            c2b_len=surplus_len;
            c2b_off=0;
        }
    }
    uint64_t rx=0, tx=0; // rx c->b, tx b->c
    rx += surplus_len;
    int client_eof=0, backend_eof=0;
    int client_writable_shutdown=0, backend_writable_shutdown=0;

    struct pollfd pfds[2];
    while (1) {
        // client
        pfds[0].fd=client_fd; pfds[0].events=0; pfds[0].revents=0;
        pfds[1].fd=backend_fd; pfds[1].events=0; pfds[1].revents=0;
        // client readable if not eof and c2b space
        if (!client_eof && c2b_len < buf_size) pfds[0].events |= POLLIN;
        if (b2c_len > b2c_off) pfds[0].events |= POLLOUT;
        if (!backend_eof && b2c_len < buf_size) pfds[1].events |= POLLIN;
        if (c2b_len > c2b_off) pfds[1].events |= POLLOUT;
        // if both eof and buffers empty, break
        if (client_eof && backend_eof && c2b_len==c2b_off && b2c_len==b2c_off) break;
        // if client eof and c2b empty, shutdown backend write
        if (client_eof && c2b_len==c2b_off && !backend_writable_shutdown) {
            shutdown(backend_fd, SHUT_WR);
            backend_writable_shutdown=1;
        }
        if (backend_eof && b2c_len==b2c_off && !client_writable_shutdown) {
            shutdown(client_fd, SHUT_WR);
            client_writable_shutdown=1;
        }
        // poll indefinitely; if both sides eof and no data to send, we already break above
        // If poll would block with no events (e.g., both eof but not yet shutdown), handle
        if (pfds[0].events==0 && pfds[1].events==0) {
            // nothing to do, but we have eof handling above; break if done
            if (client_eof && backend_eof) break;
            // wait for a bit to avoid busy loop
            struct timespec ts={0,10000000}; nanosleep(&ts,NULL);
            continue;
        }
        int pr = poll(pfds,2,-1);
        if (pr<0) { if (errno==EINTR) continue; break; }
        // check errors
        if (pfds[0].revents & (POLLERR|POLLNVAL)) break;
        if (pfds[1].revents & (POLLERR|POLLNVAL)) break;

        // client -> backend writes already? Do reads first?
        // handle client readable
        if ((pfds[0].revents & POLLIN) && !client_eof) {
            // compact c2b if needed
            if (c2b_off>0 && c2b_len>c2b_off) {
                memmove(c2b_buf, c2b_buf+c2b_off, c2b_len-c2b_off);
                c2b_len -= c2b_off;
                c2b_off=0;
            } else if (c2b_off==c2b_len) { c2b_len=0; c2b_off=0; }
            size_t space = buf_size - c2b_len;
            ssize_t n;
            do { n=recv(client_fd, c2b_buf+c2b_len, space, 0); } while (n==-1 && errno==EINTR);
            if (n==0) client_eof=1;
            else if (n>0) { c2b_len+=(size_t)n; rx+=(uint64_t)n; }
            else {
                if (errno!=EAGAIN && errno!=EWOULDBLOCK) { client_eof=1; }
            }
            if (client_eof && c2b_len==c2b_off && !backend_writable_shutdown) {
                shutdown(backend_fd, SHUT_WR);
                backend_writable_shutdown=1;
            }
        }
        // backend readable
        if ((pfds[1].revents & POLLIN) && !backend_eof) {
            if (b2c_off>0 && b2c_len>b2c_off) {
                memmove(b2c_buf, b2c_buf+b2c_off, b2c_len-b2c_off);
                b2c_len-=b2c_off; b2c_off=0;
            } else if (b2c_off==b2c_len) { b2c_len=0; b2c_off=0; }
            size_t space = buf_size - b2c_len;
            ssize_t n;
            do { n=recv(backend_fd, b2c_buf+b2c_len, space, 0); } while (n==-1 && errno==EINTR);
            if (n==0) backend_eof=1;
            else if (n>0) { b2c_len+=(size_t)n; tx+=(uint64_t)n; }
            else {
                if (errno!=EAGAIN && errno!=EWOULDBLOCK) { backend_eof=1; }
            }
            if (backend_eof && b2c_len==b2c_off && !client_writable_shutdown) {
                shutdown(client_fd, SHUT_WR);
                client_writable_shutdown=1;
            }
        }
        // client writable (b2c -> client)
        if ((pfds[0].revents & POLLOUT) && b2c_len > b2c_off) {
            ssize_t n;
            do { n=send(client_fd, b2c_buf+b2c_off, b2c_len-b2c_off, 0); } while (n==-1 && errno==EINTR);
            if (n>0) {
                b2c_off+=(size_t)n;
                if (b2c_off==b2c_len) { b2c_len=0; b2c_off=0; }
            } else if (n==-1) {
                if (errno!=EAGAIN && errno!=EWOULDBLOCK) break;
            }
        }
        // backend writable (c2b -> backend)
        if ((pfds[1].revents & POLLOUT) && c2b_len > c2b_off) {
            ssize_t n;
            do { n=send(backend_fd, c2b_buf+c2b_off, c2b_len-c2b_off, 0); } while (n==-1 && errno==EINTR);
            if (n>0) {
                c2b_off+=(size_t)n;
                if (c2b_off==c2b_len) { c2b_len=0; c2b_off=0; }
                // if client eof and now empty, shutdown backend
                if (client_eof && c2b_len==c2b_off && !backend_writable_shutdown) {
                    shutdown(backend_fd, SHUT_WR);
                    backend_writable_shutdown=1;
                }
            } else if (n==-1) {
                if (errno!=EAGAIN && errno!=EWOULDBLOCK) break;
            }
        }
        // handle HUP
        if (pfds[0].revents & (POLLHUP|POLLRDHUP)) client_eof=1;
        if (pfds[1].revents & (POLLHUP|POLLRDHUP)) backend_eof=1;
    }
    free(c2b_buf);
    free(b2c_buf);
    *rx_out=rx;
    *tx_out=tx;
    return 0;
}

static void handle_client(int client_fd, struct config *cfg) {
    struct sockaddr_storage real_src, real_dst;
    socklen_t slen=sizeof(real_src), dlen=sizeof(real_dst);
    // get real peer and local
    if (getpeername(client_fd, (struct sockaddr*)&real_src, &slen)!=0) {
        memset(&real_src,0,sizeof(real_src));
    }
    if (getsockname(client_fd, (struct sockaddr*)&real_dst, &dlen)!=0) {
        memset(&real_dst,0,sizeof(real_dst));
    }

    if (!is_trusted_peer(&real_src, cfg)) {
        char peer_str[128];
        format_client_log(&real_src, peer_str, sizeof(peer_str));
        log_msg("%s[%d]: %s peer=%s rejected (untrusted proxy)", PROG, getpid(), cfg->name, peer_str);
        close(client_fd);
        _exit(1);
    }

    struct parsed_hdr hdr;
    memset(&hdr,0,sizeof(hdr));
    int pr = parse_proxy_header(client_fd, &hdr, &real_src, &real_dst, cfg->header_timeout_ms);
    if (pr!=0) {
        // reject
        log_msg("%s[%d]: %s client=unknown backend=%s:%s rejected (%s)",
                PROG, getpid(), cfg->name, cfg->proxy_host, cfg->proxy_port, strerror(errno));
        close(client_fd);
        _exit(1);
    }

    char client_str[128];
    format_client_log(&hdr.src, client_str, sizeof(client_str));
    char backend_str[512];
    snprintf(backend_str,sizeof(backend_str),"%s:%s", cfg->proxy_host, cfg->proxy_port);

    // log connected
    if (hdr.authority_len>0) {
        log_msg("%s[%d]: %s client=%s backend=%s connected authority=%s",
                PROG, getpid(), cfg->name, client_str, backend_str, hdr.authority);
    } else if (hdr.alpn_len>0) {
        log_msg("%s[%d]: %s client=%s backend=%s connected alpn=%s",
                PROG, getpid(), cfg->name, client_str, backend_str, hdr.alpn);
    } else {
        log_msg("%s[%d]: %s client=%s backend=%s connected",
                PROG, getpid(), cfg->name, client_str, backend_str);
    }

    int backend_fd = connect_backend(cfg, cfg->connect_timeout_ms);
    if (backend_fd<0) {
        log_msg("%s[%d]: %s client=%s backend=%s connect failed (%s)",
                PROG, getpid(), cfg->name, client_str, backend_str, strerror(errno));
        if (hdr.surplus) free(hdr.surplus);
        close(client_fd);
        _exit(1);
    }

    uint64_t rx=0, tx=0;
    relay_loop(client_fd, backend_fd, hdr.surplus, hdr.surplus_len, &rx, &tx, cfg->buffer_size);

    log_msg("%s[%d]: %s client=%s closed rx=%llu tx=%llu",
            PROG, getpid(), cfg->name, client_str, (unsigned long long)rx, (unsigned long long)tx);

    if (hdr.surplus) free(hdr.surplus);
    close(client_fd);
    close(backend_fd);
    _exit(0);
}

/* Reap exited children immediately inside the SIGCHLD handler.
 * waitpid() is async-signal-safe, so this is safe, and errno is
 * preserved for the interrupted code. Reaping here (rather than via
 * a flag checked at the top of the accept loop) matters because
 * SIGCHLD is installed with SA_RESTART: accept() is not interrupted,
 * so a deferred reap would leave each most recently exited child as
 * a zombie until the next connection arrives - an idle daemon must
 * not retain zombies. */
static void sigchld(int sig) {
    int saved_errno = errno;
    (void)sig;
    pid_t reaped;
    while ((reaped = waitpid(-1, NULL, WNOHANG)) > 0) {
        if (live_children > 0) live_children--;
    }
    errno = saved_errno;
}

/* Privilege drop: the daemon starts as root only to bind privileged
 * ports. After the listening socket exists, permanently become the
 * dedicated proxyto account. Any failure (missing account, failed
 * setgroups/setgid/setuid, regainable privilege) is fatal - never
 * continue, and never continue as root. Callers that already run
 * unprivileged (tests, manual runs) skip the drop with a notice:
 * there is nothing to drop and no privilege to regain. */
static int drop_privileges(void) {
    if (getuid()!=0 && geteuid()!=0) {
        log_msg("%s: not started as root, continuing unprivileged (no privilege to drop)", PROG);
        return 0;
    }
    errno = 0;
    struct passwd *pw = getpwnam(PROXYTO_USER);
    if (!pw) {
        log_err("runtime account '%s' does not exist - refusing to continue (create it, never run as root or a backend account)", PROXYTO_USER);
        return -1;
    }
    struct group *gr = getgrnam(PROXYTO_GROUP);
    if (!gr) {
        log_err("runtime group '%s' does not exist - refusing to continue", PROXYTO_GROUP);
        return -1;
    }
    if (pw->pw_uid==0 || gr->gr_gid==0) {
        log_err("runtime account '%s' resolves to uid/gid 0 - refusing to continue", PROXYTO_USER);
        return -1;
    }
    log_msg("%s: dropping privileges to %s:%s (%u:%u)", PROG, PROXYTO_USER, PROXYTO_GROUP,
            (unsigned)pw->pw_uid, (unsigned)gr->gr_gid);
    if (setgroups(0, NULL)!=0) {
        log_err("setgroups: %s - refusing to continue", strerror(errno));
        return -1;
    }
    if (setgid(gr->gr_gid)!=0) {
        log_err("setgid(%u): %s - refusing to continue", (unsigned)gr->gr_gid, strerror(errno));
        return -1;
    }
    if (setuid(pw->pw_uid)!=0) {
        log_err("setuid(%u): %s - refusing to continue", (unsigned)pw->pw_uid, strerror(errno));
        return -1;
    }
    // verify the drop stuck and privilege cannot be regained
    if (getuid()!=pw->pw_uid || geteuid()!=pw->pw_uid || getgid()!=gr->gr_gid || getegid()!=gr->gr_gid) {
        log_err("privilege drop verification failed (uid=%u euid=%u gid=%u egid=%u) - refusing to continue",
                (unsigned)getuid(), (unsigned)geteuid(), (unsigned)getgid(), (unsigned)getegid());
        return -1;
    }
    errno = 0;
    if (setuid(0)!=-1) {
        log_err("privilege regained after drop - refusing to continue");
        return -1;
    }
    if (getuid()==0 || geteuid()==0) {
        log_err("still root after drop - refusing to continue");
        return -1;
    }
    log_msg("%s: now running as %s:%s (uid=%u gid=%u), privilege drop verified",
            PROG, PROXYTO_USER, PROXYTO_GROUP, (unsigned)getuid(), (unsigned)getgid());
    return 0;
}

static void usage(void) {
    fprintf(stderr, "Usage: %s [--syslog] <name> | -c <config>\n", prog_name);
    fprintf(stderr, "  <name> loads %s/<name>.conf\n", DEFAULT_CONF_DIR);
}

int main(int argc, char *argv[]) {
    prog_name = argv[0];
    const char *config_path=NULL;
    char config_buf[512];
    const char *name=NULL;

    // simple arg parse
    int i=1;
    for (; i<argc; i++) {
        if (strcmp(argv[i],"--help")==0 || strcmp(argv[i],"-h")==0) { usage(); return 0; }
        else if (strcmp(argv[i],"--syslog")==0) { opt_syslog=1; }
        else if (strcmp(argv[i],"-c")==0) {
            if (i+1>=argc) { usage(); return 1; }
            config_path=argv[++i];
        } else if (argv[i][0]=='-') { fprintf(stderr,"unknown option %s\n",argv[i]); usage(); return 1; }
        else { name=argv[i]; break; }
    }
    if (!config_path) {
        if (!name) { usage(); return 1; }
        // sanitize name
        if (strchr(name,'/')||strstr(name,"..")) { log_err("invalid name '%s'", name); return 1; }
        for (const char *p=name; *p; p++) if (!isalnum((unsigned char)*p) && *p!='_' && *p!='-' && *p!='.') { log_err("invalid name '%s'",name); return 1; }
        snprintf(config_buf,sizeof(config_buf),"%s/%s.conf", DEFAULT_CONF_DIR, name);
        config_path=config_buf;
    } else {
        // when -c used, name derived from basename without .conf
        const char *base = strrchr(config_path,'/');
        base = base ? base+1 : config_path;
        // strip .conf
        size_t blen=strlen(base);
        if (blen>5 && strcmp(base+blen-5,".conf")==0) blen-=5;
        static char nbuf[128];
        if (blen>=sizeof(nbuf)) blen=sizeof(nbuf)-1;
        memcpy(nbuf,base,blen); nbuf[blen]='\0';
        name=nbuf;
        if (name[0]=='\0') name="proxyto";
    }

    struct config cfg;
    memset(&cfg,0,sizeof(cfg));
    snprintf(cfg.name, sizeof(cfg.name), "%s", name);
    conf_name_global = name;

    if (load_config(config_path,&cfg)!=0) {
        return 1;
    }

    // FAIL CLOSED on the trust boundary.
    //
    // A PROXY header is asserted metadata: whoever writes it is claiming to
    // be somebody else. That claim is only worth anything if we can tell a
    // trusted proxy from a direct client. With no trusted_proxy list there is
    // no way to know who is permitted to assert an identity, so the only
    // safe reading of "no list" is "nobody is permitted" - which means
    // refusing to start.
    //
    // This used to be the opposite. is_trusted_peer() returned 1 when the
    // list was empty, and the shipped geomyidae.conf had trusted_proxy
    // commented out, so the deployed listener trusted every peer that reached
    // it and any direct client could assert any source address. Refusing at
    // startup is better than rejecting at runtime: an operator finds out
    // before the service is exposed, not on the first connection.
    if (cfg.trusted_count==0) {
        log_err("%s: no trusted_proxy configured - refusing to start. This is a "
                "PROXY-protocol listener, so every peer on it is asserting a "
                "source identity; with no trusted_proxy list there is no way to "
                "know who may do that. Set trusted_proxy to the address(es) of "
                "the proxies permitted to assert identity, for example: "
                "trusted_proxy=127.0.0.1", conf_name_global ? conf_name_global : config_path);
        return 1;
    }

    if (cfg.application[0]) {
        if (access(cfg.application, X_OK)!=0 && access(cfg.application, F_OK)!=0) {
            log_err("application %s not found/executable (%s) - continuing", cfg.application, strerror(errno));
        }
    }

    if (opt_syslog) openlog(PROG, LOG_PID, LOG_DAEMON);

    // create listener
    struct addrinfo hints, *res, *rp;
    memset(&hints,0,sizeof(hints));
    hints.ai_family=AF_UNSPEC;
    hints.ai_socktype=SOCK_STREAM;
    hints.ai_flags=AI_NUMERICHOST|AI_NUMERICSERV;

    int rc = getaddrinfo(cfg.listen_host, cfg.listen_port, &hints, &res);
    if (rc!=0) {
        log_err("getaddrinfo listen %s:%s: %s", cfg.listen_host, cfg.listen_port, gai_strerror(rc));
        return 1;
    }
    int listen_fd=-1;
    for (rp=res; rp!=NULL; rp=rp->ai_next) {
        listen_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (listen_fd==-1) continue;
        int one=1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#ifdef IPV6_V6ONLY
        if (rp->ai_family==AF_INET6) setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
#endif
        if (bind(listen_fd, rp->ai_addr, rp->ai_addrlen)!=0) { close(listen_fd); listen_fd=-1; continue; }
        if (listen(listen_fd, SOMAXCONN)!=0) { close(listen_fd); listen_fd=-1; continue; }
        break;
    }
    freeaddrinfo(res);
    if (listen_fd==-1) {
        log_err("cannot bind listen %s:%s: %s", cfg.listen_host, cfg.listen_port, strerror(errno));
        return 1;
    }

    // Privilege drop happens here by design: configuration parsed and
    // validated, addresses resolved, socket bound and listening. All
    // accepted connections and PROXY parsing run unprivileged; forked
    // workers inherit the dropped identity. Any failure is fatal.
    if (drop_privileges()!=0) {
        close(listen_fd);
        return 1;
    }

    // log startup
    if (cfg.trusted_count>0) {
        char tbuf[512] = "";
        for (int i=0;i<cfg.trusted_count;i++) {
            char ip[INET6_ADDRSTRLEN]; char port[8];
            format_sockaddr(&cfg.trusted_addrs[i], ip, sizeof(ip), port, sizeof(port));
            if (i>0) strncat(tbuf, ",", sizeof(tbuf)-strlen(tbuf)-1);
            strncat(tbuf, ip, sizeof(tbuf)-strlen(tbuf)-1);
        }
        log_msg("%s[%d]: %s service_type=%s listen=%s:%s proxy=%s:%s application=%s trusted_proxy=%s header_timeout=%d connect_timeout=%d buffer_size=%zu started",
                PROG, getpid(), cfg.name, cfg.service_type, cfg.listen_host, cfg.listen_port, cfg.proxy_host, cfg.proxy_port,
                cfg.application[0]?cfg.application:"-", tbuf,
                cfg.header_timeout_ms, cfg.connect_timeout_ms, cfg.buffer_size);
    } else {
        log_msg("%s[%d]: %s service_type=%s listen=%s:%s proxy=%s:%s application=%s header_timeout=%d connect_timeout=%d buffer_size=%zu started",
                PROG, getpid(), cfg.name, cfg.service_type, cfg.listen_host, cfg.listen_port, cfg.proxy_host, cfg.proxy_port,
                cfg.application[0]?cfg.application:"-",
                cfg.header_timeout_ms, cfg.connect_timeout_ms, cfg.buffer_size);
    }

    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa; memset(&sa,0,sizeof(sa)); sa.sa_handler=sigchld; sigemptyset(&sa.sa_mask); sa.sa_flags=SA_RESTART; sigaction(SIGCHLD,&sa,NULL);
    signal(SIGINT, SIG_DFL);
    signal(SIGTERM, SIG_DFL);

    // accept loop (exited children are reaped in the SIGCHLD
    // handler itself, so no reap bookkeeping is needed here)
    int accept_backoff_ms = ACCEPT_BACKOFF_START_MS;
    int accept_storm_active = 0;
    int children_saturated_logged = 0;
    for (;;) {
        struct sockaddr_storage cli;
        socklen_t clilen=sizeof(cli);
        int cfd = accept(listen_fd, (struct sockaddr*)&cli, &clilen);
        if (cfd==-1) {
            if (errno==EINTR) continue;
            if (errno==EAGAIN||errno==EWOULDBLOCK) continue;
            /* Resource exhaustion (EMFILE/ENFILE/ENOMEM/ENOBUFS) is not
             * transient at this rate: retrying immediately turns the
             * accept loop into a busy spin that also floods the log.
             * Back off exponentially, capped, and reset on success. */
            if (errno==EMFILE||errno==ENFILE||errno==ENOMEM||errno==ENOBUFS) {
                int delay = accept_backoff_ms;
                if (accept_backoff_ms < ACCEPT_BACKOFF_MAX_MS) {
                    accept_backoff_ms = accept_backoff_ms * 2;
                    if (accept_backoff_ms > ACCEPT_BACKOFF_MAX_MS) accept_backoff_ms = ACCEPT_BACKOFF_MAX_MS;
                }
                if (!accept_storm_active) {
                    log_err("accept: %s (resource exhaustion, backing off up to %dms)",
                            strerror(errno), ACCEPT_BACKOFF_MAX_MS);
                    accept_storm_active = 1;
                }
                struct timespec ts;
                ts.tv_sec = delay / 1000;
                ts.tv_nsec = (long)(delay % 1000) * 1000000L;
                nanosleep(&ts, NULL);
                continue;
            }
            log_err("accept: %s", strerror(errno));
            continue;
        }
        /* A successful accept means the resource pressure has cleared. */
        if (accept_storm_active) {
            log_msg("%s[%d]: %s accept recovered", PROG, getpid(), cfg.name);
            accept_storm_active = 0;
        }
        accept_backoff_ms = ACCEPT_BACKOFF_START_MS;
        int one=1; setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

        /* Concurrency cap. Refuse the new connection rather than queueing
         * or forking past the cap: the kernel backlog absorbs the arrival
         * and the peer sees a fast close, which is the backpressure signal.
         * Log once on transition into the saturated state, not per
         * connection, so a flood cannot itself become a log flood. */
        if (live_children >= cfg.max_children) {
            if (!children_saturated_logged) {
                log_msg("%s[%d]: %s at child cap %d - refusing new connections (backpressure)",
                        PROG, getpid(), cfg.name, cfg.max_children);
                children_saturated_logged = 1;
            }
            close(cfd);
            continue;
        }
        if (children_saturated_logged) {
            log_msg("%s[%d]: %s below child cap - accepting normally", PROG, getpid(), cfg.name);
            children_saturated_logged = 0;
        }

        if (!is_trusted_peer(&cli, &cfg)) {
            char peer_str[128];
            format_client_log(&cli, peer_str, sizeof(peer_str));
            log_msg("%s[%d]: %s peer=%s rejected (untrusted proxy)", PROG, getpid(), cfg.name, peer_str);
            close(cfd);
            continue;
        }

        pid_t pid = fork();
        if (pid==-1) {
            log_err("fork: %s", strerror(errno));
            close(cfd);
            continue;
        }
        if (pid==0) {
            // child
            close(listen_fd);
            // reset signal handlers
            signal(SIGCHLD, SIG_DFL);
            handle_client(cfd, &cfg);
            // not reached
        } else {
            close(cfd);
            live_children++;
        }
    }
    return 0;
}
