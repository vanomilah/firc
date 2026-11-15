#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include "quic.h"
#include "certgen.h"
#include "scrypto.h"
#include "unit.h"

#ifndef SOL_UDP
#define SOL_UDP 17
#endif
#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif

#define MIB 1048576
#define MAXST 1024
#define MAXOUT 1024

static uint8_t *g_pat;
static unsigned char g_ca1[2048], g_ca2[2048], g_leaf[2048], g_leaf_ip[2048], g_key[512];
static size_t g_ca1_n, g_ca2_n, g_leaf_n, g_leaf_ip_n, g_key_n;
static char g_ca1_pem[4096], g_ca2_pem[4096], g_leaf_pem[4096];
static const unsigned char *g_srv_der;
static size_t g_srv_n;
static int g_nb;
static int g_fail_seg_probe;
static unsigned g_seg_cmsgs;
static size_t g_emsg_over, g_largest;
static unsigned g_emsg_n;
static unsigned long g_clk_n, g_clk_calls;
static struct end *g_quiet, *g_clk_end;
static unsigned g_tx = 1;

int __real_getsockopt(int fd, int level, int name, void *val, socklen_t *len);
ssize_t __real_sendmsg(int fd, const struct msghdr *mh, int flags);
int __real_sendmmsg(int fd, struct mmsghdr *mm, unsigned n, int flags);

static int seg_probe_refused(int level, int name) {
    if (!(g_fail_seg_probe && level == SOL_UDP && name == UDP_SEGMENT)) return 0;
    errno = ENOPROTOOPT;
    return 1;
}

int __wrap_getsockopt(int fd, int level, int name, void *val, socklen_t *len) {
    return seg_probe_refused(level, name) ? -1 : __real_getsockopt(fd, level, name, val, len);
}

static void seg_scan(const struct msghdr *mh) {
    if (!mh->msg_control || mh->msg_controllen < sizeof(struct cmsghdr)) return;
    for (struct cmsghdr *c = CMSG_FIRSTHDR((struct msghdr *)mh); c; c = CMSG_NXTHDR((struct msghdr *)mh, c))
        if (c->cmsg_level == SOL_UDP && c->cmsg_type == UDP_SEGMENT) g_seg_cmsgs++;
}

static size_t mh_len(const struct msghdr *mh) {
    size_t n = 0;
    for (size_t i = 0; i < mh->msg_iovlen; i++) n += mh->msg_iov[i].iov_len;
    return n;
}

static size_t mh_seg(const struct msghdr *mh) {
    if (!mh->msg_control || mh->msg_controllen < sizeof(struct cmsghdr)) return 0;
    for (struct cmsghdr *c = CMSG_FIRSTHDR((struct msghdr *)mh); c; c = CMSG_NXTHDR((struct msghdr *)mh, c))
        if (c->cmsg_level == SOL_UDP && c->cmsg_type == UDP_SEGMENT) {
            uint16_t v;
            memcpy(&v, CMSG_DATA(c), sizeof v);
            return v;
        }
    return 0;
}

static size_t mh_dgram(const struct msghdr *mh) {
    size_t seg = mh_seg(mh), n = mh_len(mh);
    return seg && seg < n ? seg : n;
}

static int sendmsg_refused(const struct msghdr *mh) {
    seg_scan(mh);
    size_t d = mh_dgram(mh);
    if (g_emsg_over && d > g_emsg_over) {
        g_emsg_n++;
        errno = EMSGSIZE;
        return 1;
    }
    if (d > g_largest) g_largest = d;
    return 0;
}

static unsigned sendmmsg_taken(struct mmsghdr *mm, unsigned n) {
    for (unsigned i = 0; i < n; i++) seg_scan(&mm[i].msg_hdr);
    unsigned k = 0;
    while (k < n && !(g_emsg_over && mh_dgram(&mm[k].msg_hdr) > g_emsg_over)) k++;
    if (k == 0 && n > 0) {
        g_emsg_n++;
        errno = EMSGSIZE;
        return 0;
    }
    for (unsigned i = 0; i < k; i++)
        if (mh_dgram(&mm[i].msg_hdr) > g_largest) g_largest = mh_dgram(&mm[i].msg_hdr);
    return k;
}

ssize_t __wrap_sendmsg(int fd, const struct msghdr *mh, int flags) {
    return sendmsg_refused(mh) ? -1 : __real_sendmsg(fd, mh, flags);
}

int __wrap_sendmmsg(int fd, struct mmsghdr *mm, unsigned n, int flags) {
    unsigned k = sendmmsg_taken(mm, n);
    return k == 0 && n > 0 ? -1 : __real_sendmmsg(fd, mm, k, flags);
}

#if (defined(__GLIBC__) && defined(__USE_TIME_BITS64) && __TIMESIZE == 32) || (defined(_REDIR_TIME64) && _REDIR_TIME64)
int __real___getsockopt64(int fd, int level, int name, void *val, socklen_t *len);
ssize_t __real___sendmsg64(int fd, const struct msghdr *mh, int flags);
int __real___sendmmsg64(int fd, struct mmsghdr *mm, unsigned n, int flags);
int __wrap___getsockopt64(int fd, int level, int name, void *val, socklen_t *len);
ssize_t __wrap___sendmsg64(int fd, const struct msghdr *mh, int flags);
int __wrap___sendmmsg64(int fd, struct mmsghdr *mm, unsigned n, int flags);

int __wrap___getsockopt64(int fd, int level, int name, void *val, socklen_t *len) {
    return seg_probe_refused(level, name) ? -1 : __real___getsockopt64(fd, level, name, val, len);
}

ssize_t __wrap___sendmsg64(int fd, const struct msghdr *mh, int flags) {
    return sendmsg_refused(mh) ? -1 : __real___sendmsg64(fd, mh, flags);
}

int __wrap___sendmmsg64(int fd, struct mmsghdr *mm, unsigned n, int flags) {
    unsigned k = sendmmsg_taken(mm, n);
    return k == 0 && n > 0 ? -1 : __real___sendmmsg64(fd, mm, k, flags);
}
#endif

static int kernel_takes_segment(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    int v = 0;
    socklen_t l = sizeof v;
    int ok = fd >= 0 && __real_getsockopt(fd, SOL_UDP, UDP_SEGMENT, &v, &l) == 0;
    if (fd >= 0) close(fd);
    return ok;
}

static uint64_t ms_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static uint8_t pat(size_t i) { return (uint8_t)((i * 31 + 7) % 251); }

struct strm {
    int64_t sid;
    size_t got, consumed, bad;
    int fin, closed, rx_reset, tx_stopped, responded;
    long send_in_close;
    uint64_t rx_err, tx_err;
    unsigned writable;
};

struct out {
    int used, own, fin, fin_done, dead;
    int64_t sid;
    uint8_t *buf;
    size_t n, cap, off;
};

struct end {
    struct qc *q;
    int hs, closed, reason, app;
    uint64_t code, closed_ms;
    char why[160];
    struct strm st[MAXST];
    int nst;
    struct out ob[MAXOUT];
    int echo, echo_nofin, consume_in_cb;
    size_t respond;
    unsigned dg_n;
    size_t dg_len;
    uint8_t dg[2048];
    int in_ep;
    struct end *fwd;
    int64_t fwd_sid;
    unsigned sopen;
    unsigned aborts;
    int64_t ab_sid;
    int ab_reset, ab_stopped;
    uint64_t ab_rx, ab_tx;
};

struct pair {
    struct end c, s;
    int ep;
};

struct fstate {
    unsigned tx_n, bad;
    size_t largest;
};

static struct strm *strm_find(struct end *e, int64_t sid) {
    for (int i = 0; i < e->nst; i++)
        if (e->st[i].sid == sid) return &e->st[i];
    return NULL;
}

static struct strm *strm_get(struct end *e, int64_t sid) {
    for (int i = 0; i < e->nst; i++)
        if (e->st[i].sid == sid) return &e->st[i];
    if (e->nst == MAXST) return NULL;
    struct strm *s = &e->st[e->nst++];
    memset(s, 0, sizeof *s);
    s->sid = sid;
    return s;
}

static struct out *out_for(struct end *e, int64_t sid) {
    for (int i = 0; i < MAXOUT; i++)
        if (e->ob[i].used && e->ob[i].sid == sid) return &e->ob[i];
    for (int i = 0; i < MAXOUT; i++)
        if (!e->ob[i].used) {
            memset(&e->ob[i], 0, sizeof e->ob[i]);
            e->ob[i].used = 1;
            e->ob[i].sid = sid;
            return &e->ob[i];
        }
    return NULL;
}

static void out_static(struct end *e, int64_t sid, const uint8_t *d, size_t n, int fin) {
    struct out *o = out_for(e, sid);
    if (!o) return;
    o->buf = (uint8_t *)d;
    o->n = n;
    o->fin = fin;
}

static void out_append(struct end *e, int64_t sid, const uint8_t *d, size_t n, int fin) {
    struct out *o = out_for(e, sid);
    if (!o) return;
    o->own = 1;
    if (o->n + n > o->cap) {
        size_t cap = (o->n + n) * 2 + 64;
        uint8_t *b = realloc(o->buf, cap);
        if (!b) return;
        o->buf = b;
        o->cap = cap;
    }
    memcpy(o->buf + o->n, d, n);
    o->n += n;
    if (fin) o->fin = 1;
}

static void drain(struct end *e) {
    if (!e->q) return;
    for (int i = 0; i < MAXOUT; i++) {
        struct out *o = &e->ob[i];
        if (!o->used || o->dead) continue;
        if (o->off == o->n && (!o->fin || o->fin_done)) continue;
        ssize_t w = qc_stream_send(e->q, o->sid, o->buf + o->off, o->n - o->off, o->fin);
        if (w == QC_EAGAIN) continue;
        if (w < 0) { o->dead = 1; continue; }
        o->off += (size_t)w;
        if (o->fin && o->off == o->n) o->fin_done = 1;
    }
}

static void ends_free_out(struct end *e) {
    for (int i = 0; i < MAXOUT; i++)
        if (e->ob[i].used && e->ob[i].own) free(e->ob[i].buf);
    memset(e->ob, 0, sizeof e->ob);
}

static void cb_hs(void *u) { ((struct end *)u)->hs++; }

static void cb_data(void *u, int64_t sid, const uint8_t *d, size_t n, int fin) {
    struct end *e = u;
    struct strm *s = strm_get(e, sid);
    if (!s) return;
    for (size_t i = 0; i < n; i++)
        if (d[i] != pat(s->got + i)) s->bad++;
    s->got += n;
    if (fin) s->fin = 1;
    if (e->echo) out_append(e, sid, d, n, fin && !e->echo_nofin);
    if (e->respond && !s->responded) {
        s->responded = 1;
        out_static(e, sid, g_pat, e->respond, 0);
    }
    if (e->consume_in_cb) {
        qc_stream_consumed(e->q, sid, n);
        s->consumed += n;
    }
    if (e->fwd) {
        out_append(e->fwd, e->fwd_sid, d, n, fin);
        drain(e->fwd);
        (void)qc_on_readable(e->fwd->q);
    }
}

static void cb_writable(void *u, int64_t sid) {
    struct strm *s = strm_get(u, sid);
    if (s) s->writable++;
}

static void cb_sclose(void *u, int64_t sid, int rx_reset, uint64_t rx_err, int tx_stopped, uint64_t tx_err) {
    struct strm *s = strm_find(u, sid);
    if (!s) return;
    s->closed++;
    s->send_in_close = qc_stream_send(((struct end *)u)->q, sid, (const uint8_t *)"z", 1, 0);
    s->rx_reset = rx_reset;
    s->rx_err = rx_err;
    s->tx_stopped = tx_stopped;
    s->tx_err = tx_err;
}

static void cb_dg(void *u, const uint8_t *d, size_t n) {
    struct end *e = u;
    e->dg_n++;
    e->dg_len = n;
    memcpy(e->dg, d, n < sizeof e->dg ? n : sizeof e->dg);
    if (e->echo) (void)qc_datagram_send(e->q, d, n);
}

static void cb_closed(void *u, int reason, int app, uint64_t code, const char *why) {
    struct end *e = u;
    e->closed++;
    e->reason = reason;
    e->app = app;
    e->code = code;
    e->closed_ms = ms_now();
    snprintf(e->why, sizeof e->why, "%s", why ? why : "");
}

static void cb_sopen(void *u) { ((struct end *)u)->sopen++; }

static void cb_abort(void *u, int64_t sid, int reset, uint64_t rx_err, int stopped, uint64_t tx_err) {
    struct end *e = u;
    e->aborts++;
    e->ab_sid = sid;
    e->ab_reset = reset;
    e->ab_rx = rx_err;
    e->ab_stopped = stopped;
    e->ab_tx = tx_err;
}

static const struct qc_ops g_ops = {
    .on_handshake = cb_hs, .on_stream_data = cb_data, .on_stream_writable = cb_writable,
    .on_streams_open = cb_sopen, .on_stream_peer_abort = cb_abort, .on_stream_close = cb_sclose,
    .on_datagram = cb_dg, .on_closed = cb_closed,
};

static void srv_cfg(struct qc_srv_cfg *sc, const char *alpn) {
    memset(sc, 0, sizeof *sc);
    sc->bind_host = "127.0.0.1";
    sc->alpn = alpn;
    sc->cert_der = g_srv_der;
    sc->cert_n = g_srv_n;
    sc->key_der = g_key;
    sc->key_n = g_key_n;
    sc->no_batch = g_nb;
}

static void cli_cfg(struct qc_cfg *c, const char *alpn) {
    memset(c, 0, sizeof *c);
    c->host = "127.0.0.1";
    c->sni = "node.test";
    c->alpn = alpn;
    c->ca_pem = (const uint8_t *)g_ca1_pem;
    c->ca_pem_n = strlen(g_ca1_pem);
    c->no_batch = g_nb;
}

static void ep_add(struct pair *p, struct end *e) {
    struct epoll_event ev = { .events = EPOLLIN, .data.ptr = e };
    if (epoll_ctl(p->ep, EPOLL_CTL_ADD, qc_fd(e->q), &ev) == 0) e->in_ep = 1;
}

static int pair_open(struct pair *p, struct qc_cfg *cc, const struct qc_srv_cfg *sc) {
    memset(p, 0, sizeof *p);
    p->ep = epoll_create1(0);
    if (qc_listen(sc, &g_ops, &p->s, &p->s.q) != 0) return -1;
    ep_add(p, &p->s);
    cc->port = qc_local_port(p->s.q);
    if (qc_open(cc, &g_ops, &p->c, &p->c.q) != 0) return -2;
    ep_add(p, &p->c);
    return 0;
}

static void pair_free(struct pair *p) {
    qc_free(p->c.q);
    qc_free(p->s.q);
    ends_free_out(&p->c);
    ends_free_out(&p->s);
    close(p->ep);
    p->c.q = p->s.q = NULL;
}

static void pass_ends(int ep, struct end **ends, int cnt) {
    int t = 50;
    for (int i = 0; i < cnt; i++) {
        if (!ends[i]->q || ends[i]->closed) continue;
        int k = qc_timeout_ms(ends[i]->q);
        if (k >= 0 && k < t) t = k;
    }
    struct epoll_event ev[4];
    int n = epoll_wait(ep, ev, 4, t);
    for (int i = 0; i < n; i++) {
        struct end *e = ev[i].data.ptr;
        if (e->closed) continue;
        unsigned long c0 = qc_clock_reads();
        (void)qc_on_readable(e->q);
        if (e == g_clk_end) {
            g_clk_n += qc_clock_reads() - c0;
            g_clk_calls++;
        }
    }
    for (int i = 0; i < cnt; i++) {
        struct end *e = ends[i];
        if (!e->q) continue;
        if (!e->closed && qc_timeout_ms(e->q) == 0) {
            unsigned long c0 = qc_clock_reads();
            (void)qc_on_timer(e->q);
            if (e == g_clk_end) {
                g_clk_n += qc_clock_reads() - c0;
                g_clk_calls++;
            }
        }
        if (e->closed && e->in_ep) {
            epoll_ctl(ep, EPOLL_CTL_DEL, qc_fd(e->q), NULL);
            e->in_ep = 0;
        }
        if (!e->closed) drain(e);
        if (e != g_quiet) qc_flush(e->q);
    }
}

static void pass(struct pair *p) {
    struct end *ends[2] = { &p->c, &p->s };
    pass_ends(p->ep, ends, 2);
}

typedef int (*cond_fn)(struct pair *p, void *arg);

static int pump_until(struct pair *p, cond_fn cond, void *arg, unsigned limit_ms) {
    uint64_t end = ms_now() + (uint64_t)limit_ms * g_tx;
    while (ms_now() < end) {
        if (cond(p, arg)) return 1;
        pass(p);
    }
    return cond(p, arg);
}

static void pump_for(struct pair *p, unsigned ms) {
    uint64_t end = ms_now() + (uint64_t)ms * g_tx;
    while (ms_now() < end) pass(p);
}

static int c_both_hs(struct pair *p, void *a) { (void)a; return p->c.hs && p->s.hs; }
static int c_cli_closed(struct pair *p, void *a) { (void)a; return p->c.closed != 0; }
static int c_srv_closed(struct pair *p, void *a) { (void)a; return p->s.closed != 0; }
static int c_cli_dg(struct pair *p, void *a) { (void)a; return p->c.dg_n > 0; }

static int c_cli_closed_or_hs(struct pair *p, void *a) { (void)a; return p->c.closed || p->c.hs; }

struct want { struct end *e; int64_t sid; size_t n; };

static int c_got(struct pair *p, void *a) {
    (void)p;
    struct want *w = a;
    struct strm *s = strm_get(w->e, w->sid);
    return s && s->got >= w->n;
}

static int c_closed_st(struct pair *p, void *a) {
    (void)p;
    struct want *w = a;
    struct strm *s = strm_get(w->e, w->sid);
    return s && s->closed;
}

static int c_writable(struct pair *p, void *a) {
    (void)p;
    struct want *w = a;
    struct strm *s = strm_get(w->e, w->sid);
    return s && s->writable;
}

static int open_stream(struct pair *p, int64_t *sid) {
    int rc = QC_EAGAIN;
    uint64_t end = ms_now() + 10000ull * g_tx;
    while ((rc = qc_stream_open(p->c.q, sid)) == QC_EAGAIN && ms_now() < end) pass(p);
    return rc;
}

static void name(char *buf, size_t cap, const char *what) {
    snprintf(buf, cap, "%s%s", what, g_nb ? " [no_batch]" : "");
}

static void handshake_completes_only_on_the_same_alpn(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    check("alpn: pair opens", 0, pair_open(&p, &cc, &sc));
    check("alpn h3/h3: both handshakes", 1, pump_until(&p, c_both_hs, NULL, 10000));
    check("alpn h3/h3: client on_handshake once", 1, p.c.hs);
    check("alpn h3/h3: server on_handshake once", 1, p.s.hs);
    pair_free(&p);

    cli_cfg(&cc, "hq");
    srv_cfg(&sc, "h3");
    check("alpn hq/h3: pair opens", 0, pair_open(&p, &cc, &sc));
    check("alpn hq/h3: client closed", 1, pump_until(&p, c_cli_closed, NULL, 10000));
    check("alpn hq/h3: reason handshake", QC_CLOSE_HANDSHAKE, p.c.reason);
    check("alpn hq/h3: no client on_handshake", 0, p.c.hs);
    pair_free(&p);
}

static void a_megabyte_on_a_stream_arrives_intact_both_ways(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    char nm[128];
    int64_t sid = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    pair_open(&p, &cc, &sc);
    p.s.echo = 1;
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    g_seg_cmsgs = 0;
    name(nm, sizeof nm, "1 MiB echo: stream opens");
    check(nm, 0, open_stream(&p, &sid));
    out_static(&p.c, sid, g_pat, MIB, 1);
    struct want w = { &p.c, sid, 0 };
    name(nm, sizeof nm, "1 MiB echo: client stream closes");
    check(nm, 1, pump_until(&p, c_closed_st, &w, 10000));
    struct strm *s = strm_get(&p.c, sid);
    name(nm, sizeof nm, "1 MiB echo: bytes back");
    check(nm, MIB, (long)s->got);
    name(nm, sizeof nm, "1 MiB echo: bytes intact");
    check(nm, 0, (long)s->bad);
    name(nm, sizeof nm, "1 MiB echo: FIN seen");
    check(nm, 1, s->fin);
    name(nm, sizeof nm, "1 MiB echo: close rx_reset 0");
    check(nm, 0, s->rx_reset);
    name(nm, sizeof nm, "1 MiB echo: close rx_err 0");
    check(nm, 0, (long)s->rx_err);
    name(nm, sizeof nm, "1 MiB echo: close tx_stopped 0");
    check(nm, 0, s->tx_stopped);
    name(nm, sizeof nm, "1 MiB echo: close tx_err 0");
    check(nm, 0, (long)s->tx_err);
    name(nm, sizeof nm, "1 MiB echo: no peer abort on a clean FIN");
    check(nm, 0, (long)(p.c.aborts + p.s.aborts));
    struct qc_stats st;
    qc_stats_get(p.c.q, &st);
    if (g_nb) {
        check("1 MiB echo: no_batch leaves GSO off", 0, st.gso);
        check("1 MiB echo: no_batch leaves GRO off", 0, st.gro);
    } else {
        int probe = kernel_takes_segment();
        printf("     batched path: probe %d gso %d gro %d rcvbuf %u sndbuf %u\n", probe, st.gso, st.gro, st.rcvbuf, st.sndbuf);
        check("1 MiB echo: the send buffer obtained is reported", 1, st.sndbuf > 0);
        check("1 MiB echo: GSO on exactly when the kernel answers UDP_SEGMENT", probe, st.gso);
        check("1 MiB echo: segmented sends seen exactly when GSO is on", probe, g_seg_cmsgs > 0);
    }
    pair_free(&p);
}

static void a_kernel_without_udp_segment_gets_plain_datagrams(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    int64_t sid = -1;
    g_fail_seg_probe = 1;
    g_seg_cmsgs = 0;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    check("no UDP_SEGMENT: pair opens", 0, pair_open(&p, &cc, &sc));
    p.s.echo = 1;
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    check("no UDP_SEGMENT: handshake", 1, pump_until(&p, c_both_hs, NULL, 10000));
    check("no UDP_SEGMENT: stream opens", 0, open_stream(&p, &sid));
    out_static(&p.c, sid, g_pat, MIB, 1);
    struct want w = { &p.c, sid, 0 };
    check("no UDP_SEGMENT: echo stream closes", 1, pump_until(&p, c_closed_st, &w, 10000));
    struct strm *s = strm_get(&p.c, sid);
    check("no UDP_SEGMENT: 1 MiB back", MIB, (long)s->got);
    check("no UDP_SEGMENT: intact", 0, (long)s->bad);
    struct qc_stats a, b;
    qc_stats_get(p.c.q, &a);
    qc_stats_get(p.s.q, &b);
    check("no UDP_SEGMENT: client gso 0", 0, a.gso);
    check("no UDP_SEGMENT: server gso 0", 0, b.gso);
    check("no UDP_SEGMENT: no send carried UDP_SEGMENT", 0, (long)g_seg_cmsgs);
    pair_free(&p);
    g_fail_seg_probe = 0;
}

static void a_datagram_arrives_intact_and_an_oversized_one_is_refused(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    char nm[128];
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.datagram_max = 1200;
    sc.datagram_max = 1200;
    pair_open(&p, &cc, &sc);
    p.s.echo = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    uint8_t d[1000];
    for (size_t i = 0; i < sizeof d; i++) d[i] = pat(i);
    int ok = 0;
    for (int i = 0; i < 20 && !ok; i++) {
        (void)qc_datagram_send(p.c.q, d, sizeof d);
        ok = pump_until(&p, c_cli_dg, NULL, 500);
    }
    name(nm, sizeof nm, "datagram: echo arrives");
    check(nm, 1, ok);
    name(nm, sizeof nm, "datagram: length 1000");
    check(nm, 1000, (long)p.c.dg_len);
    name(nm, sizeof nm, "datagram: bytes intact");
    check(nm, 1, memcmp(p.c.dg, d, sizeof d) == 0);
    size_t max = qc_datagram_max(p.c.q);
    name(nm, sizeof nm, "datagram: max holds 1000");
    check(nm, 1, max >= 1000);
    uint8_t *big = calloc(1, max + 1);
    name(nm, sizeof nm, "datagram: max+1 refused");
    check(nm, QC_ETOOBIG, qc_datagram_send(p.c.q, big, max + 1));
    free(big);
    pair_free(&p);
}

static void window_round(const char *tag, uint64_t max_data, uint64_t max_stream_data, size_t stall) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    char nm[128];
    int64_t sid = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.max_data = max_data;
    cc.max_stream_data = max_stream_data;
    pair_open(&p, &cc, &sc);
    p.s.respond = MIB;
    p.s.consume_in_cb = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    snprintf(nm, sizeof nm, "%s: stream opens", tag);
    check(nm, 0, open_stream(&p, &sid));
    out_static(&p.c, sid, (const uint8_t *)"x", 1, 0);
    struct want w = { &p.c, sid, stall };
    snprintf(nm, sizeof nm, "%s: %zu bytes arrive", tag, stall);
    check(nm, 1, pump_until(&p, c_got, &w, 10000));
    pump_for(&p, 300);
    struct strm *s = strm_get(&p.c, sid);
    snprintf(nm, sizeof nm, "%s: and stay at %zu", tag, stall);
    check(nm, (long)stall, (long)s->got);
    uint64_t t0 = ms_now(), moved = 0, end = t0 + 10000ull * g_tx;
    while (s->got < MIB && ms_now() < end) {
        if (s->got > s->consumed) {
            qc_stream_consumed(p.c.q, sid, s->got - s->consumed);
            s->consumed = s->got;
            qc_flush(p.c.q);
        }
        pass(&p);
        if (!moved && s->got > stall) moved = ms_now();
    }
    snprintf(nm, sizeof nm, "%s: count moves within 2 s of the first consume", tag);
    check(nm, 1, moved && moved - t0 <= 2000ull * g_tx);
    snprintf(nm, sizeof nm, "%s: 1 MiB in the end", tag);
    check(nm, MIB, (long)s->got);
    snprintf(nm, sizeof nm, "%s: intact", tag);
    check(nm, 0, (long)s->bad);
    pair_free(&p);
}

static void unread_stream_data_stops_at_the_window(void) {
    window_round("stream window", 0, 65536, 65536);
    window_round("connection window", 131072, 0, 131072);
}

static void a_pin_decides_alone(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    uint8_t pins[64];
    memset(pins, 0, sizeof pins);
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.pin_sha256 = pins;
    cc.pin_n = 1;
    check("pin zeros: pair opens", 0, pair_open(&p, &cc, &sc));
    check("pin zeros: client closed", 1, pump_until(&p, c_cli_closed_or_hs, NULL, 10000) && p.c.closed);
    check("pin zeros: reason handshake", QC_CLOSE_HANDSHAKE, p.c.reason);
    check("pin zeros: why says pin", 1, strstr(p.c.why, "pin") != NULL);
    check("pin zeros: no on_handshake", 0, p.c.hs);
    pair_free(&p);

    struct qc_tls *t = qc_tls_new(0, (const uint8_t *)g_ca1_pem, strlen(g_ca1_pem), NULL);
    check("pin zeros, shared roots: context", 1, t != NULL);
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.tls = t;
    cc.pin_sha256 = pins;
    cc.pin_n = 1;
    check("pin zeros, shared roots: pair opens", 0, pair_open(&p, &cc, &sc));
    check("pin zeros, shared roots: client closed", 1, pump_until(&p, c_cli_closed_or_hs, NULL, 10000) && p.c.closed);
    check("pin zeros, shared roots: why says pin", 1, strstr(p.c.why, "pin") != NULL);
    check("pin zeros, shared roots: no on_handshake", 0, p.c.hs);
    pair_free(&p);
    qc_tls_free(t);

    sc_hash(SC_SHA256, g_leaf, g_leaf_n, pins + 32);
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.ca_pem = NULL;
    cc.ca_pem_n = 0;
    cc.ca_file = "/nonexistent/roots.pem";
    cc.pin_sha256 = pins;
    cc.pin_n = 2;
    check("pin second matches: pair opens", 0, pair_open(&p, &cc, &sc));
    check("pin second matches: completes", 1, pump_until(&p, c_both_hs, NULL, 10000));
    check("pin second matches: not closed", 0, p.c.closed);
    pair_free(&p);

    char chain[8192];
    snprintf(chain, sizeof chain, "%s%s", g_leaf_pem, g_ca2_pem);
    sc_hash(SC_SHA256, g_ca2, g_ca2_n, pins);
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    sc.chain_pem = chain;
    sc.chain_pem_n = strlen(chain);
    cc.pin_sha256 = pins;
    cc.pin_n = 1;
    check("pin of a chain certificate only: pair opens", 0, pair_open(&p, &cc, &sc));
    check("pin of a chain certificate only: client closed", 1,
          pump_until(&p, c_cli_closed_or_hs, NULL, 10000) && p.c.closed);
    check("pin of a chain certificate only: why says pin", 1, strstr(p.c.why, "pin") != NULL);
    check("pin of a chain certificate only: no on_handshake", 0, p.c.hs);
    pair_free(&p);
}

static void one_check(const char *what, const char *sni, const char *vname, const char *pem, int insecure,
                      int ip_leaf, int want_hs, const char *want_why) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    char nm[128];
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.sni = sni;
    cc.verify_name = vname;
    cc.ca_pem = (const uint8_t *)pem;
    cc.ca_pem_n = strlen(pem);
    cc.insecure = insecure;
    if (ip_leaf) {
        sc.cert_der = g_leaf_ip;
        sc.cert_n = g_leaf_ip_n;
    }
    snprintf(nm, sizeof nm, "%s: pair opens", what);
    check(nm, 0, pair_open(&p, &cc, &sc));
    if (want_hs) {
        snprintf(nm, sizeof nm, "%s: completes", what);
        check(nm, 1, pump_until(&p, c_both_hs, NULL, 10000) && !p.c.closed);
    } else {
        snprintf(nm, sizeof nm, "%s: closed", what);
        check(nm, 1, pump_until(&p, c_cli_closed_or_hs, NULL, 10000) && p.c.closed);
        snprintf(nm, sizeof nm, "%s: reason handshake", what);
        check(nm, QC_CLOSE_HANDSHAKE, p.c.reason);
        snprintf(nm, sizeof nm, "%s: why says %s", what, want_why);
        check(nm, 1, strstr(p.c.why, want_why) != NULL);
        snprintf(nm, sizeof nm, "%s: no on_handshake", what);
        check(nm, 0, p.c.hs);
    }
    pair_free(&p);
}

static void chain_and_name_are_checked_without_a_pin(void) {
    one_check("sni other.test", "other.test", NULL, g_ca1_pem, 0, 0, 0, "name");
    one_check("verify_name node.test", "other.test", "node.test", g_ca1_pem, 0, 0, 1, NULL);
    one_check("unrelated CA", "node.test", NULL, g_ca2_pem, 0, 0, 0, "chain");
    one_check("unrelated CA, insecure", "node.test", NULL, g_ca2_pem, 1, 0, 1, NULL);
    one_check("no names, IP SAN 127.0.0.1", NULL, NULL, g_ca1_pem, 0, 1, 1, NULL);
    one_check("no names, no IP SAN", NULL, NULL, g_ca1_pem, 0, 0, 0, "name");
}

static void a_server_without_alpn_is_refused(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "");
    check("no alpn from server: pair opens", 0, pair_open(&p, &cc, &sc));
    check("no alpn from server: client closed", 1, pump_until(&p, c_cli_closed_or_hs, NULL, 10000) && p.c.closed);
    check("no alpn from server: reason handshake", QC_CLOSE_HANDSHAKE, p.c.reason);
    check("no alpn from server: why says alpn", 1, strstr(p.c.why, "alpn") != NULL);
    check("no alpn from server: no on_handshake", 0, p.c.hs);
    pair_free(&p);
}

static void a_refused_port_is_fatal_only_before_the_handshake(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    int64_t sid = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    pair_open(&p, &cc, &sc);
    p.s.consume_in_cb = 1;
    check("refused after handshake: handshake", 1, pump_until(&p, c_both_hs, NULL, 10000));
    open_stream(&p, &sid);
    qc_free(p.s.q);
    p.s.q = NULL;
    out_static(&p.c, sid, g_pat, 65536, 0);
    pump_for(&p, 500);
    check("refused after handshake: connection stays", 0, p.c.closed);
    pair_free(&p);

    srv_cfg(&sc, "h3");
    struct qc *dead = NULL;
    qc_listen(&sc, &g_ops, NULL, &dead);
    uint16_t port = qc_local_port(dead);
    qc_free(dead);
    memset(&p, 0, sizeof p);
    p.ep = epoll_create1(0);
    cli_cfg(&cc, "h3");
    cc.port = port;
    check("refused before handshake: open", 0, qc_open(&cc, &g_ops, &p.c, &p.c.q));
    ep_add(&p, &p.c);
    check("refused before handshake: closed", 1, pump_until(&p, c_cli_closed, NULL, 3000));
    check("refused before handshake: reason error", QC_CLOSE_ERROR, p.c.reason);
    check("refused before handshake: why says refused", 1, strstr(p.c.why, "refused") != NULL);
    pair_free(&p);
}

static void an_oversized_filter_overhead_is_refused(void) {
    struct fstate f;
    struct qc_filter fl = { NULL, NULL, &f, 65 };
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    struct qc *q = NULL;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.port = 9;
    cc.filter = &fl;
    sc.filter = &fl;
    check("overhead 65: qc_open refuses", QC_EINVAL, qc_open(&cc, &g_ops, NULL, &q));
    check("overhead 65: qc_listen refuses", QC_EINVAL, qc_listen(&sc, &g_ops, NULL, &q));
}

static size_t f_tx(void *u, uint8_t *dst, const uint8_t *src, size_t n) {
    struct fstate *f = u;
    memset(dst, 0xA5, 8);
    for (size_t i = 0; i < n; i++) dst[8 + i] = src[i] ^ 0x5C;
    f->tx_n++;
    if (n + 8 > f->largest) f->largest = n + 8;
    return n + 8;
}

static size_t f_rx(void *u, uint8_t *dst, const uint8_t *src, size_t n) {
    struct fstate *f = u;
    int ok = n >= 8;
    for (size_t i = 0; ok && i < 8; i++)
        if (src[i] != 0xA5) ok = 0;
    if (!ok) { f->bad++; return 0; }
    for (size_t i = 8; i < n; i++) dst[i - 8] = src[i] ^ 0x5C;
    return n - 8;
}

static void a_filter_wraps_every_datagram_on_the_wire(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    char nm[128];
    int64_t sid = -1;
    struct fstate fc, fs;
    memset(&fc, 0, sizeof fc);
    memset(&fs, 0, sizeof fs);
    struct qc_filter flc = { f_tx, f_rx, &fc, 8 }, fls = { f_tx, f_rx, &fs, 8 };
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.filter = &flc;
    sc.filter = &fls;
    name(nm, sizeof nm, "filter: pair opens");
    check(nm, 0, pair_open(&p, &cc, &sc));
    p.s.echo = 1;
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    name(nm, sizeof nm, "filter: handshake");
    check(nm, 1, pump_until(&p, c_both_hs, NULL, 10000));
    open_stream(&p, &sid);
    out_static(&p.c, sid, g_pat, MIB, 1);
    struct want w = { &p.c, sid, 0 };
    pump_until(&p, c_closed_st, &w, 10000);
    struct strm *s = strm_get(&p.c, sid);
    name(nm, sizeof nm, "filter: 1 MiB echo back intact");
    check(nm, 1, s->got == MIB && s->bad == 0 && s->fin);
    qc_close(p.c.q, 7);
    name(nm, sizeof nm, "filter: server sees the close");
    check(nm, 1, pump_until(&p, c_srv_closed, NULL, 10000));
    name(nm, sizeof nm, "filter: close is an application close");
    check(nm, 1, p.s.app);
    name(nm, sizeof nm, "filter: close code 7");
    check(nm, 7, (long)p.s.code);
    name(nm, sizeof nm, "filter: no datagram without the prefix");
    check(nm, 0, (long)fs.bad);
    name(nm, sizeof nm, "filter: largest output <= 1452");
    check(nm, 1, fc.largest <= 1452);
    name(nm, sizeof nm, "filter: largest output > 1280");
    check(nm, 1, fc.largest > 1280);
    struct qc_stats st;
    qc_stats_get(p.c.q, &st);
    name(nm, sizeof nm, "filter: dg_tx equals the tx hook calls");
    check(nm, (long)fc.tx_n, (long)st.dg_tx);
    pair_free(&p);

    memset(&fc, 0, sizeof fc);
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.filter = &flc;
    cc.handshake_ms = 500;
    uint64_t t0 = ms_now();
    pair_open(&p, &cc, &sc);
    name(nm, sizeof nm, "filter on one side: client closed");
    check(nm, 1, pump_until(&p, c_cli_closed, NULL, 10000));
    uint64_t dt = p.c.closed_ms - t0;
    name(nm, sizeof nm, "filter on one side: no handshake");
    check(nm, 0, p.c.hs + p.s.hs);
    name(nm, sizeof nm, "filter on one side: reason handshake");
    check(nm, QC_CLOSE_HANDSHAKE, p.c.reason);
    name(nm, sizeof nm, "filter on one side: closed in 400..3000 ms");
    check(nm, 1, dt >= 400 && dt <= 3000ull * g_tx);
    pair_free(&p);
}

static void an_idle_connection_closes_at_the_idle_limit(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.idle_ms = 1000;
    sc.idle_ms = 1000;
    pair_open(&p, &cc, &sc);
    check("idle: handshake", 1, pump_until(&p, c_both_hs, NULL, 10000));
    uint64_t last = ms_now(), seen = 0, end = last + 10000ull * g_tx;
    while (!p.c.closed && ms_now() < end) {
        struct qc_stats a, b;
        qc_stats_get(p.c.q, &a);
        qc_stats_get(p.s.q, &b);
        uint64_t sum = a.pkt_sent + a.pkt_recv + b.pkt_sent + b.pkt_recv;
        if (sum != seen) { seen = sum; last = ms_now(); }
        pass(&p);
    }
    check("idle: client closed", 1, p.c.closed);
    check("idle: reason idle", QC_CLOSE_IDLE, p.c.reason);
    uint64_t dt = p.c.closed_ms - last;
    check("idle: 900..5000 ms after the last packet", 1, dt >= 900 && dt <= 5000ull * g_tx);
    pair_free(&p);
}

static void stop_and_reset_reach_the_peer_with_their_codes(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    int64_t sid = -1, sid2 = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    pair_open(&p, &cc, &sc);
    p.s.echo = 1;
    p.s.echo_nofin = 1;
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    check("stop: stream opens", 0, open_stream(&p, &sid));
    out_static(&p.c, sid, g_pat, 3, 1);
    struct want wc = { &p.c, sid, 3 }, ws = { &p.s, sid, 0 };
    check("stop: echo arrives", 1, pump_until(&p, c_got, &wc, 10000));
    check("stop: qc_stream_stop", 0, qc_stream_stop(p.c.q, sid, 5));
    check("stop: server stream closes", 1, pump_until(&p, c_closed_st, &ws, 10000));
    struct strm *s = strm_get(&p.s, sid);
    check("stop: server tx_stopped 1", 1, s->tx_stopped);
    check("stop: server tx_err 5", 5, (long)s->tx_err);
    check("stop: server rx_reset 0", 0, s->rx_reset);
    check("stop: a server send after it fails", 1, qc_stream_send(p.s.q, sid, (const uint8_t *)"z", 1, 0) < 0);
    check("stop: a send from inside on_stream_close fails", QC_ENOSTREAM, s->send_in_close);

    check("reset: stream opens", 0, open_stream(&p, &sid2));
    out_static(&p.c, sid2, g_pat, 3, 0);
    struct want ws2 = { &p.s, sid2, 3 };
    check("reset: server got the bytes", 1, pump_until(&p, c_got, &ws2, 10000));
    check("reset: qc_stream_reset", 0, qc_stream_reset(p.c.q, sid2, 7));
    check("reset: server stream closes", 1, pump_until(&p, c_closed_st, &ws2, 10000));
    s = strm_get(&p.s, sid2);
    check("reset: server rx_reset 1", 1, s->rx_reset);
    check("reset: server rx_err 7", 7, (long)s->rx_err);
    pair_free(&p);
}

static void room_coming_back_is_announced(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    int64_t sid = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.send_buf = 65536;
    pair_open(&p, &cc, &sc);
    p.s.consume_in_cb = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    check("room: stream opens", 0, open_stream(&p, &sid));
    ssize_t w = qc_stream_send(p.c.q, sid, g_pat, 100000, 0);
    check("room: send returns short", 65536, (long)w);
    check("room: no room left", 0, (long)qc_stream_room(p.c.q, sid));
    struct strm *s = strm_get(&p.c, sid);
    check("room: nothing announced yet", 0, (long)s->writable);
    struct want ww = { &p.c, sid, 0 };
    check("room: on_stream_writable fires", 1, pump_until(&p, c_writable, &ww, 10000));
    check("room: a further send succeeds", 1, qc_stream_send(p.c.q, sid, g_pat + 65536, 1000, 0) > 0);
    check("room: none on a stream that does not exist", 0, (long)qc_stream_room(p.c.q, sid + 400));
    pair_free(&p);
}

static void suite_round(int chacha, unsigned want) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    char nm[128];
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.prefer_chacha = chacha;
    pair_open(&p, &cc, &sc);
    snprintf(nm, sizeof nm, "suite prefer_chacha %d: handshake", chacha);
    check(nm, 1, pump_until(&p, c_both_hs, NULL, 10000));
    struct qc_stats a, b;
    qc_stats_get(p.c.q, &a);
    qc_stats_get(p.s.q, &b);
    snprintf(nm, sizeof nm, "suite prefer_chacha %d: client 0x%04x", chacha, want);
    check(nm, (long)want, (long)a.cipher);
    snprintf(nm, sizeof nm, "suite prefer_chacha %d: server 0x%04x", chacha, want);
    check(nm, (long)want, (long)b.cipher);
    pair_free(&p);
}

static void the_preferred_suite_is_negotiated(void) {
    suite_round(1, 0x1303);
    suite_round(0, 0x1301);
}

static void credit_round(int give_back) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    char nm[128];
    const char *tag = give_back ? "credit returned" : "credit kept";
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.max_data = MIB;
    cc.max_stream_data = 262144;
    pair_open(&p, &cc, &sc);
    p.s.respond = 131072;
    p.s.consume_in_cb = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    int ok = 1;
    for (int i = 0; i < 8; i++) {
        int64_t sid = -1;
        if (open_stream(&p, &sid) != 0) { ok = 0; break; }
        out_static(&p.c, sid, (const uint8_t *)"x", 1, 0);
        struct want w = { &p.c, sid, 131072 };
        if (!pump_until(&p, c_got, &w, 10000)) { ok = 0; break; }
        if (qc_stream_reset(p.c.q, sid, 1) != 0) ok = 0;
        if (give_back) qc_conn_consumed(p.c.q, 131072);
    }
    snprintf(nm, sizeof nm, "%s: eight streams of 128 KiB each", tag);
    check(nm, 1, ok);
    p.s.respond = 262144;
    int64_t sid9 = -1;
    snprintf(nm, sizeof nm, "%s: ninth stream opens", tag);
    check(nm, 0, open_stream(&p, &sid9));
    out_static(&p.c, sid9, (const uint8_t *)"x", 1, 0);
    struct want w9 = { &p.c, sid9, give_back ? 262144 : 0 };
    snprintf(nm, sizeof nm, "%s: ninth stream reaches %d bytes", tag, give_back ? 262144 : 0);
    check(nm, 1, pump_until(&p, c_got, &w9, 10000));
    pump_for(&p, 300);
    struct strm *s = strm_get(&p.c, sid9);
    snprintf(nm, sizeof nm, "%s: and stays there", tag);
    check(nm, give_back ? 262144 : 0, s ? (long)s->got : 0);
    snprintf(nm, sizeof nm, "%s: connection alive", tag);
    check(nm, 0, p.c.closed);
    pair_free(&p);
}

static void connection_credit_of_a_dead_stream_comes_back(void) {
    credit_round(1);
    credit_round(0);
}

static int certs_make(void) {
    struct tcg_key *k1 = tcg_key_new(), *k2 = tcg_key_new(), *kl = tcg_key_new();
    int rc = -1;
    if (!k1 || !k2 || !kl) goto out;
    if (tcg_issue(k1, "Test CA One", NULL, 1, NULL, NULL, 0, g_ca1, sizeof g_ca1, &g_ca1_n) != 0) goto out;
    if (tcg_issue(k2, "Test CA Two", NULL, 1, NULL, NULL, 0, g_ca2, sizeof g_ca2, &g_ca2_n) != 0) goto out;
    if (tcg_issue(kl, "node.test", NULL, 0, k1, g_ca1, g_ca1_n, g_leaf, sizeof g_leaf, &g_leaf_n) != 0) goto out;
    static const unsigned char lo[4] = { 127, 0, 0, 1 };
    if (tcg_issue_ip4(kl, "node.test", lo, k1, g_ca1, g_ca1_n, g_leaf_ip, sizeof g_leaf_ip, &g_leaf_ip_n) != 0) goto out;
    if (tcg_key_der(kl, g_key, sizeof g_key, &g_key_n) != 0) goto out;
    if (tcg_der_to_pem(g_leaf, g_leaf_n, g_leaf_pem, sizeof g_leaf_pem) != 0) goto out;
    g_srv_der = g_leaf;
    g_srv_n = g_leaf_n;
    if (tcg_der_to_pem(g_ca1, g_ca1_n, g_ca1_pem, sizeof g_ca1_pem) != 0) goto out;
    if (tcg_der_to_pem(g_ca2, g_ca2_n, g_ca2_pem, sizeof g_ca2_pem) != 0) goto out;
    rc = 0;
out:
    tcg_key_free(k1);
    tcg_key_free(k2);
    tcg_key_free(kl);
    return rc;
}

static void forget(struct end *e, int64_t sid) {
    for (int i = 0; i < e->nst; i++)
        if (e->st[i].sid == sid) {
            e->st[i] = e->st[--e->nst];
            break;
        }
    for (int i = 0; i < MAXOUT; i++)
        if (e->ob[i].used && e->ob[i].sid == sid) {
            if (e->ob[i].own) free(e->ob[i].buf);
            memset(&e->ob[i], 0, sizeof e->ob[i]);
        }
}

static int c_open_ok(struct pair *p, void *a) {
    int64_t *sid = a;
    return qc_stream_open(p->c.q, sid) == 0;
}

static void streams_come_back_after_they_close(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    sc.max_streams = 4;
    pair_open(&p, &cc, &sc);
    p.s.echo = 1;
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    check("stream limit: handshake", 1, pump_until(&p, c_both_hs, NULL, 10000));
    int done = 0;
    for (int i = 0; i < 40; i++) {
        int64_t sid = -1;
        if (!pump_until(&p, c_open_ok, &sid, 10000)) break;
        out_static(&p.c, sid, g_pat, 3, 1);
        struct want w = { &p.c, sid, 3 };
        if (!pump_until(&p, c_closed_st, &w, 10000)) break;
        struct strm *s = strm_get(&p.c, sid);
        if (s->got == 3 && s->bad == 0 && s->fin) done++;
        forget(&p.c, sid);
        forget(&p.s, sid);
    }
    check("stream limit 4: 40 streams in turn all echo", 40, done);
    pair_free(&p);

    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    sc.max_streams = 4;
    pair_open(&p, &cc, &sc);
    p.s.echo = 1;
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    int64_t ids[4];
    int opened = 0;
    for (int i = 0; i < 4; i++)
        if (qc_stream_open(p.c.q, &ids[i]) == 0) {
            opened++;
            out_static(&p.c, ids[i], g_pat, 1, 0);
        }
    check("stream limit 4: four open at once", 4, opened);
    int64_t fifth = -1;
    check("stream limit 4: the fifth waits", QC_EAGAIN, qc_stream_open(p.c.q, &fifth));
    pump_for(&p, 300);
    check("stream limit 4: and still waits while four stay open", QC_EAGAIN, qc_stream_open(p.c.q, &fifth));
    check("stream limit 4: closing one", 0, (long)qc_stream_send(p.c.q, ids[0], NULL, 0, 1));
    check("stream limit 4: the fifth opens after one closed", 1, pump_until(&p, c_open_ok, &fifth, 10000));
    pair_free(&p);
}

static void unsent_counts_only_what_no_packet_carried(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    int64_t sid = -1, sid2 = -1;
    const size_t window = 16384, sent = 40000, small = 100;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    sc.max_stream_data = window;
    pair_open(&p, &cc, &sc);
    pump_until(&p, c_both_hs, NULL, 10000);
    check("unsent: stream opens", 0, open_stream(&p, &sid));
    check("unsent: unknown stream is 0", 0, (long)qc_stream_unsent(p.c.q, sid + 400));
    check("unsent: all accepted", (long)sent, (long)qc_stream_send(p.c.q, sid, g_pat, sent, 0));
    struct want ws = { &p.s, sid, window };
    check("unsent: the peer gets its window", 1, pump_until(&p, c_got, &ws, 10000));
    pump_for(&p, 300);
    struct strm *ss = strm_get(&p.s, sid);
    check("unsent: and no more", (long)window, (long)ss->got);
    check("unsent: sent minus the window", (long)(sent - window), (long)qc_stream_unsent(p.c.q, sid));
    uint64_t end = ms_now() + 10000ull * g_tx;
    while (ss->got < sent && ms_now() < end) {
        if (ss->got > ss->consumed) {
            qc_stream_consumed(p.s.q, sid, ss->got - ss->consumed);
            ss->consumed = ss->got;
        }
        pass(&p);
    }
    pump_for(&p, 300);
    check("unsent: the peer read everything", (long)sent, (long)ss->got);
    check("unsent: acknowledged, room is back to the default eighth of the budget", 524288, (long)qc_stream_room(p.c.q, sid));
    check("unsent: 0 after the peer read it", 0, (long)qc_stream_unsent(p.c.q, sid));
    check("unsent: second stream opens", 0, open_stream(&p, &sid2));
    pump_for(&p, 300);
    check("unsent: small send accepted", (long)small, (long)qc_stream_send(p.c.q, sid2, g_pat, small, 0));
    check("unsent: still unacknowledged", (long)(524288 - small), (long)qc_stream_room(p.c.q, sid2));
    check("unsent: 0 once it went out", 0, (long)qc_stream_unsent(p.c.q, sid2));
    pair_free(&p);
}

struct tagf {
    uint8_t tag[4];
    unsigned foreign;
};

static size_t tag_tx(void *u, uint8_t *dst, const uint8_t *src, size_t n) {
    struct tagf *t = u;
    memcpy(dst, t->tag, 4);
    memcpy(dst + 4, src, n);
    return n + 4;
}

static size_t tag_rx(void *u, uint8_t *dst, const uint8_t *src, size_t n) {
    struct tagf *t = u;
    if (n < 4 || memcmp(src, t->tag, 4) != 0) {
        t->foreign++;
        return 0;
    }
    memcpy(dst, src + 4, n - 4);
    return n - 4;
}

static void a_callback_may_drive_another_connection(void) {
    static struct pair pa, pb;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    int64_t sa = -1, sb = -1;
    struct tagf ta = { { 0xA1, 0xA2, 0xA3, 0xA4 }, 0 }, tb = { { 0xB1, 0xB2, 0xB3, 0xB4 }, 0 };
    struct qc_filter fa = { tag_tx, tag_rx, &ta, 4 }, fb = { tag_tx, tag_rx, &tb, 4 };
    unsigned long n0, n1;
    size_t max0, max1;
    qc_nested_stats(&n0, &max0);
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.filter = sc.filter = &fa;
    check("two connections: A opens", 0, pair_open(&pa, &cc, &sc));
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.filter = sc.filter = &fb;
    check("two connections: B opens", 0, pair_open(&pb, &cc, &sc));
    int ep = epoll_create1(0);
    struct end *ends[4] = { &pa.c, &pa.s, &pb.c, &pb.s };
    for (int i = 0; i < 4; i++) {
        struct epoll_event ev = { .events = EPOLLIN, .data.ptr = ends[i] };
        epoll_ctl(ep, EPOLL_CTL_ADD, qc_fd(ends[i]->q), &ev);
    }
    pa.s.echo = pb.s.echo = 1;
    pa.s.consume_in_cb = pb.s.consume_in_cb = pa.c.consume_in_cb = pb.c.consume_in_cb = 1;
    uint64_t end = ms_now() + 10000ull * g_tx;
    while (!(pa.c.hs && pb.c.hs && pa.s.hs && pb.s.hs) && ms_now() < end) pass_ends(ep, ends, 4);
    check("two connections: both handshakes", 1, pa.c.hs && pb.c.hs);
    check("two connections: A stream", 0, qc_stream_open(pa.c.q, &sa));
    check("two connections: B stream", 0, qc_stream_open(pb.c.q, &sb));
    pa.c.fwd = &pb.c;
    pa.c.fwd_sid = sb;
    out_static(&pa.c, sa, g_pat, MIB, 1);
    struct strm *a = strm_get(&pa.c, sa), *b = strm_get(&pb.c, sb);
    end = ms_now() + 20000ull * g_tx;
    while (!(a->closed && b->closed) && ms_now() < end) pass_ends(ep, ends, 4);
    check("two connections: A got 1 MiB back", MIB, (long)a->got);
    check("two connections: A intact", 0, (long)a->bad);
    check("two connections: B got 1 MiB back", MIB, (long)b->got);
    check("two connections: B intact", 0, (long)b->bad);
    check("two connections: both streams closed cleanly", 1, a->closed && b->closed && a->fin && b->fin);
    check("two connections: neither connection closed", 0, pa.c.closed + pb.c.closed);
    check("two connections: no datagram of B reached pair A", 0, (long)ta.foreign);
    check("two connections: no datagram of A reached pair B", 0, (long)tb.foreign);
    qc_nested_stats(&n1, &max1);
    (void)n0;
    (void)max0;
    printf("     nested receives: %lu, largest %zu B\n", n1, max1);
    check("two connections: a nested receive happened", 1, n1 > 0);
    if (g_nb) check("two connections: nested no_batch receive asked for no more than 32 x 2048 + filter + 16 KiB", 1,
                    max1 <= 32 * 2048 + QC_FILTER_RX_MAX + 16384);
    close(ep);
    pair_free(&pa);
    pair_free(&pb);
}

static int c_sopen(struct pair *p, void *a) { (void)a; return p->c.sopen > 0; }

static void the_owner_hears_when_streams_open_again(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    int64_t a = -1, b = -1, c = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    sc.max_streams = 2;
    pair_open(&p, &cc, &sc);
    p.s.echo = 1;
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    check("streams open: two allowed", 1, qc_stream_open(p.c.q, &a) == 0 && qc_stream_open(p.c.q, &b) == 0);
    out_static(&p.c, a, g_pat, 1, 0);
    out_static(&p.c, b, g_pat, 1, 0);
    check("streams open: the third waits", QC_EAGAIN, qc_stream_open(p.c.q, &c));
    pump_for(&p, 300);
    check("streams open: nothing announced while both stay open", 0, (long)p.c.sopen);
    qc_stream_send(p.c.q, a, NULL, 0, 1);
    check("streams open: on_streams_open fires after one closed", 1, pump_until(&p, c_sopen, NULL, 10000));
    check("streams open: once", 1, (long)p.c.sopen);
    check("streams open: the next open succeeds", 0, qc_stream_open(p.c.q, &c));
    pair_free(&p);
}

static int c_all_back(struct pair *p, void *a) {
    int64_t *ids = a;
    for (int i = 0; i < 600; i++) {
        struct strm *s = strm_find(&p->c, ids[i]);
        if (!s || !s->closed) return 0;
    }
    return 1;
}

static void six_hundred_streams_at_once(void) {
    static struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    static int64_t ids[600];
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    sc.max_streams = 600;
    pair_open(&p, &cc, &sc);
    p.s.echo = 1;
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    int opened = 0;
    for (int i = 0; i < 600; i++)
        if (qc_stream_open(p.c.q, &ids[i]) == 0) {
            opened++;
            strm_get(&p.c, ids[i]);
            out_static(&p.c, ids[i], g_pat, 4096, 1);
        }
    check("600 streams: all open at once", 600, opened);
    check("600 streams: all echo and close", 1, pump_until(&p, c_all_back, ids, 20000));
    int good = 0;
    for (int i = 0; i < 600; i++) {
        struct strm *s = strm_find(&p.c, ids[i]);
        if (s && s->got == 4096 && s->bad == 0 && s->fin) good++;
    }
    check("600 streams: 4 KiB each intact", 600, good);
    uint64_t cs, co, ss, so;
    qc_probe_stats(p.c.q, &cs, &co);
    qc_probe_stats(p.s.q, &ss, &so);
    printf("     probes: client %llu steps / %llu ops, server %llu / %llu\n", (unsigned long long)cs,
           (unsigned long long)co, (unsigned long long)ss, (unsigned long long)so);
    check("600 streams: client stream operations counted", 1, co >= 600);
    check("600 streams: server stream operations counted", 1, so >= 600);
    check("600 streams: client under 20 probe steps per operation", 1, cs < 20 * co);
    check("600 streams: server under 20 probe steps per operation", 1, ss < 20 * so);
    pair_free(&p);
}

static int c_ab(struct pair *p, void *a) { (void)a; return p->c.aborts > 0; }

static void a_peer_abort_of_one_direction_is_heard(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    int64_t sid = -1, sid2 = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    pair_open(&p, &cc, &sc);
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    check("peer stop: stream opens", 0, open_stream(&p, &sid));
    out_static(&p.c, sid, g_pat, 3, 0);
    struct want ws = { &p.s, sid, 3 };
    check("peer stop: server got the bytes", 1, pump_until(&p, c_got, &ws, 10000));
    check("peer stop: server stops reading", 0, qc_stream_stop(p.s.q, sid, 5));
    check("peer stop: on_stream_peer_abort", 1, pump_until(&p, c_ab, NULL, 10000));
    check("peer stop: once", 1, (long)p.c.aborts);
    check("peer stop: sid", (long)sid, (long)p.c.ab_sid);
    check("peer stop: reset 0", 0, p.c.ab_reset);
    check("peer stop: rx_err 0", 0, (long)p.c.ab_rx);
    check("peer stop: stopped 1", 1, p.c.ab_stopped);
    check("peer stop: tx_err 5", 5, (long)p.c.ab_tx);
    check("peer stop: no on_stream_close yet", 0, strm_get(&p.c, sid)->closed);
    check("peer stop: server still sends", 3, (long)qc_stream_send(p.s.q, sid, g_pat, 3, 0));
    struct want wc = { &p.c, sid, 3 };
    check("peer stop: client still reads", 1, pump_until(&p, c_got, &wc, 10000));

    p.c.aborts = 0;
    check("peer reset: stream opens", 0, open_stream(&p, &sid2));
    out_static(&p.c, sid2, g_pat, 3, 0);
    struct want ws2 = { &p.s, sid2, 3 };
    check("peer reset: server got the bytes", 1, pump_until(&p, c_got, &ws2, 10000));
    check("peer reset: server resets its sending side", 0, qc_stream_reset_write(p.s.q, sid2, 7));
    check("peer reset: on_stream_peer_abort", 1, pump_until(&p, c_ab, NULL, 10000));
    pump_for(&p, 300);
    check("peer reset: once", 1, (long)p.c.aborts);
    check("peer reset: sid", (long)sid2, (long)p.c.ab_sid);
    check("peer reset: reset 1", 1, p.c.ab_reset);
    check("peer reset: rx_err 7", 7, (long)p.c.ab_rx);
    check("peer reset: stopped 0", 0, p.c.ab_stopped);
    check("peer reset: tx_err 0", 0, (long)p.c.ab_tx);
    check("peer reset: client can still send", 3, (long)qc_stream_send(p.c.q, sid2, g_pat + 3, 3, 0));
    struct want ws3 = { &p.s, sid2, 6 };
    check("peer reset: server gets it", 1, pump_until(&p, c_got, &ws3, 10000));
    pair_free(&p);
}

static void a_reset_stream_forgets_what_it_had_to_send(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    int64_t sid = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.send_buf = 65536;
    pair_open(&p, &cc, &sc);
    p.s.consume_in_cb = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    check("reset unsent: stream opens", 0, open_stream(&p, &sid));
    check("reset unsent: send returns short", 65536, (long)qc_stream_send(p.c.q, sid, g_pat, 100000, 0));
    check("reset unsent: something still unsent", 1, qc_stream_unsent(p.c.q, sid) > 0);
    check("reset unsent: reset", 0, qc_stream_reset(p.c.q, sid, 3));
    check("reset unsent: unsent 0 at once", 0, (long)qc_stream_unsent(p.c.q, sid));
    pump_for(&p, 500);
    struct strm *s = strm_get(&p.c, sid);
    check("reset unsent: no on_stream_writable for a reset stream", 0, (long)s->writable);
    pair_free(&p);
}

static int c_srv_all_100(struct pair *p, void *a) {
    int64_t *ids = a;
    for (int i = 0; i < 600; i++) {
        struct strm *s = strm_find(&p->s, ids[i]);
        if (!s || s->got < 100) return 0;
    }
    return 1;
}

static void acknowledged_data_holds_no_chunk(void) {
    static struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    static int64_t ids[600];
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    sc.max_streams = 600;
    pair_open(&p, &cc, &sc);
    p.s.consume_in_cb = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    int ok = 0;
    for (int i = 0; i < 600; i++)
        if (qc_stream_open(p.c.q, &ids[i]) == 0 && qc_stream_send(p.c.q, ids[i], g_pat, 100, 0) == 100) ok++;
    check("send chunks: 600 streams sent 100 bytes", 600, ok);
    size_t held = qc_send_held(p.c.q);
    printf("     held while unacknowledged: %zu B\n", held);
    check("send chunks: unacknowledged hold at most 600 x 4096", 1, held >= 600 * 100 && held <= 600 * 4096);
    check("send chunks: the server got all 600", 1, pump_until(&p, c_srv_all_100, ids, 10000));
    pump_for(&p, 300);
    check("send chunks: all acknowledged, nothing held", 0, (long)qc_send_held(p.c.q));
    check("send chunks: 5000 bytes accepted", 5000, (long)qc_stream_send(p.c.q, ids[1], g_pat + 100, 5000, 0));
    check("send chunks: a first send of 5000 holds 8192", 8192, (long)qc_send_held(p.c.q));
    out_static(&p.c, ids[0], g_pat, MIB, 0);
    struct want w = { &p.s, ids[0], 100 + MIB };
    check("send chunks: 1 MiB more arrives", 1, pump_until(&p, c_got, &w, 10000));
    pump_for(&p, 300);
    check("send chunks: after 1 MiB acknowledged, nothing held", 0, (long)qc_send_held(p.c.q));
    pair_free(&p);
}


static void dont_fragment_is_set_on_both_families(void) {
    static const char *const host[2] = { "127.0.0.1", "::1" };
    static const int level[2] = { IPPROTO_IP, IPPROTO_IPV6 };
    static const int opt[2] = { IP_MTU_DISCOVER, IPV6_MTU_DISCOVER };
    static const int want[2] = { IP_PMTUDISC_PROBE, IPV6_PMTUDISC_PROBE };
    for (int i = 0; i < 2; i++) {
        struct qc_cfg cc;
        struct qc *q = NULL;
        struct end e;
        char nm[128];
        memset(&e, 0, sizeof e);
        cli_cfg(&cc, "h3");
        cc.host = host[i];
        cc.port = 9;
        snprintf(nm, sizeof nm, "df %s: opens", host[i]);
        check(nm, 0, qc_open(&cc, &g_ops, &e, &q));
        int v = -1;
        socklen_t l = sizeof v;
        snprintf(nm, sizeof nm, "df %s: reads back the probe mode", host[i]);
        check(nm, want[i], q && __real_getsockopt(qc_fd(q), level[i], opt[i], &v, &l) == 0 ? v : -1);
        qc_free(q);
    }
}

static void an_oversized_datagram_is_lost_not_fatal(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    char nm[128];
    int64_t sid = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    g_emsg_over = 1300;
    g_emsg_n = 0;
    g_largest = 0;
    pair_open(&p, &cc, &sc);
    p.s.echo = 1;
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    name(nm, sizeof nm, "EMSGSIZE: handshake");
    check(nm, 1, pump_until(&p, c_both_hs, NULL, 10000));
    open_stream(&p, &sid);
    out_static(&p.c, sid, g_pat, MIB, 1);
    struct want w = { &p.c, sid, 0 };
    name(nm, sizeof nm, "EMSGSIZE: 1 MiB echo closes");
    check(nm, 1, pump_until(&p, c_closed_st, &w, 10000));
    struct strm *s = strm_get(&p.c, sid);
    name(nm, sizeof nm, "EMSGSIZE: 1 MiB back intact with fin");
    check(nm, 1, s->got == MIB && s->bad == 0 && s->fin);
    name(nm, sizeof nm, "EMSGSIZE: connection alive");
    check(nm, 0, p.c.closed + p.s.closed);
    name(nm, sizeof nm, "EMSGSIZE: some datagram was refused");
    check(nm, 1, g_emsg_n > 0);
    printf("     refused %u, largest through %zu\n", g_emsg_n, g_largest);
    name(nm, sizeof nm, "EMSGSIZE: the largest datagram through is at most 1300");
    check(nm, 1, g_largest > 0 && g_largest <= 1300);
    g_emsg_over = 0;
    pair_free(&p);
}

static void credit_round_no_flush(int defer) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    char nm[128];
    int64_t sid = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.max_stream_data = 65536;
    cc.defer_flush = defer;
    pair_open(&p, &cc, &sc);
    p.s.respond = MIB;
    p.s.consume_in_cb = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    open_stream(&p, &sid);
    out_static(&p.c, sid, (const uint8_t *)"x", 1, 0);
    g_quiet = &p.c;
    struct strm *s = strm_get(&p.c, sid);
    uint64_t end = ms_now() + 10000ull * g_tx;
    while (s->got < MIB && ms_now() < end) {
        if (s->got > s->consumed) {
            qc_stream_consumed(p.c.q, sid, s->got - s->consumed);
            s->consumed = s->got;
        }
        pass(&p);
    }
    g_quiet = NULL;
    snprintf(nm, sizeof nm, "credit without qc_flush, defer %d: 1 MiB through a 65536 window", defer);
    check(nm, MIB, (long)s->got);
    snprintf(nm, sizeof nm, "credit without qc_flush, defer %d: intact", defer);
    check(nm, 0, (long)s->bad);
    pair_free(&p);
}

static void credit_needs_no_flush_from_the_owner(void) {
    credit_round_no_flush(0);
    credit_round_no_flush(1);
}

static unsigned long burst_calls(int defer) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    int64_t warm = -1, sid = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.defer_flush = defer;
    pair_open(&p, &cc, &sc);
    p.s.consume_in_cb = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    open_stream(&p, &warm);
    out_static(&p.c, warm, g_pat, MIB, 0);
    struct want w = { &p.s, warm, MIB };
    pump_until(&p, c_got, &w, 10000);
    open_stream(&p, &sid);
    pump_for(&p, 300);
    struct qc_stats a, b;
    qc_stats_get(p.c.q, &a);
    int took = 0;
    for (int i = 0; i < 64; i++) took += qc_stream_send(p.c.q, sid, g_pat + (size_t)i * 1024, 1024, 0) == 1024;
    qc_flush(p.c.q);
    qc_stats_get(p.c.q, &b);
    char nm[128];
    snprintf(nm, sizeof nm, "64 sends of 1 KiB, defer %d: all taken", defer);
    check(nm, 64, took);
    struct want w2 = { &p.s, sid, 65536 };
    snprintf(nm, sizeof nm, "64 sends of 1 KiB, defer %d: the peer gets them", defer);
    check(nm, 1, pump_until(&p, c_got, &w2, 10000) && strm_get(&p.s, sid)->bad == 0);
    pair_free(&p);
    printf("     defer %d: %llu send calls\n", defer, (unsigned long long)(b.tx_calls - a.tx_calls));
    return (unsigned long)(b.tx_calls - a.tx_calls);
}

static void deferred_sends_leave_together(void) {
    char nm[128];
    name(nm, sizeof nm, "defer_flush 1: 64 sends cost at most 2 send calls after one qc_flush");
    check(nm, 1, burst_calls(1) <= 2);
    name(nm, sizeof nm, "defer_flush 0: 64 sends cost at least 32 send calls");
    check(nm, 1, burst_calls(0) >= 32);
}

static void four_megabytes_with_bounded_work(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    char nm[128];
    int64_t sid = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    pair_open(&p, &cc, &sc);
    p.s.echo = 1;
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    unsigned rx;
    size_t fl;
    qc_work_stats(p.c.q, &rx, &fl);
    qc_work_stats(p.s.q, &rx, &fl);
    open_stream(&p, &sid);
    out_static(&p.c, sid, g_pat, 4 * MIB, 1);
    struct want w = { &p.c, sid, 0 };
    name(nm, sizeof nm, "4 MiB echo: closes");
    check(nm, 1, pump_until(&p, c_closed_st, &w, 20000));
    struct strm *s = strm_get(&p.c, sid);
    name(nm, sizeof nm, "4 MiB echo: intact with fin");
    check(nm, 1, s->got == 4 * MIB && s->bad == 0 && s->fin);
    unsigned crx, srx;
    size_t cfl, sfl;
    qc_work_stats(p.c.q, &crx, &cfl);
    qc_work_stats(p.s.q, &srx, &sfl);
    printf("     most datagrams in one read call: client %u, server %u; most bytes in one flush: client %zu, server %zu\n",
           crx, srx, cfl, sfl);
    name(nm, sizeof nm, "4 MiB echo: no read call handled more than 128 datagrams");
    check(nm, 1, crx <= 128 && srx <= 128);
    name(nm, sizeof nm, "4 MiB echo: no flush wrote more than 64 KiB and one datagram");
    check(nm, 1, cfl <= 65536 + 1452 && sfl <= 65536 + 1452);
    name(nm, sizeof nm, "4 MiB echo: the work was there to bound");
    check(nm, 1, crx > 0 && cfl > 0);
    pair_free(&p);
}

static void one_clock_read_per_batch(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    int64_t sid = -1;
    int nb = g_nb;
    g_nb = 1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    g_nb = nb;
    pair_open(&p, &cc, &sc);
    p.s.respond = MIB;
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    open_stream(&p, &sid);
    struct qc_stats a, b;
    qc_stats_get(p.c.q, &a);
    g_clk_n = 0;
    g_clk_calls = 0;
    g_clk_end = &p.c;
    out_static(&p.c, sid, (const uint8_t *)"x", 1, 0);
    struct want w = { &p.c, sid, MIB };
    check("clock: 1 MiB received", 1, pump_until(&p, c_got, &w, 10000));
    g_clk_end = NULL;
    qc_stats_get(p.c.q, &b);
    uint64_t dg = b.pkt_recv - a.pkt_recv;
    uint64_t rxc = b.rx_calls - a.rx_calls;
    printf("     clock reads %lu for %llu datagrams received in %lu calls and %llu receive calls\n", g_clk_n,
           (unsigned long long)dg, g_clk_calls, (unsigned long long)rxc);
    check("clock: reads were counted", 1, g_clk_n > 0);
    if (g_tx == 1)
        check("clock: fewer than 1 read per 8 datagrams received", 1, g_clk_n * 8 < dg);
    else
        check("clock: at most 1 read per call and 1 per receive call", 1, g_clk_n <= g_clk_calls + rxc);
    pair_free(&p);
}

static int c_srv_got_all(struct pair *p, void *a) {
    int64_t *ids = a;
    for (int i = 0; i < 8; i++) {
        struct strm *s = strm_find(&p->s, ids[i]);
        if (!s || s->got < MIB || !s->fin) return 0;
    }
    return 1;
}

struct qsend { size_t off; unsigned seen; int waiting; };

static void budget_drain(struct pair *p, int64_t *ids, struct qsend *qs) {
    for (int i = 0; i < 8; i++) {
        struct strm *s = strm_get(&p->c, ids[i]);
        if (qs[i].off >= MIB || (qs[i].waiting && s->writable == qs[i].seen)) continue;
        ssize_t w = qc_stream_send(p->c.q, ids[i], g_pat + qs[i].off, MIB - qs[i].off, 1);
        if (w > 0) qs[i].off += (size_t)w;
        qs[i].waiting = qs[i].off < MIB;
        qs[i].seen = s->writable;
    }
}

static void srv_consume_all(struct end *e) {
    for (int i = 0; i < e->nst; i++) {
        struct strm *s = &e->st[i];
        if (s->got > s->consumed) {
            qc_stream_consumed(e->q, s->sid, s->got - s->consumed);
            s->consumed = s->got;
        }
    }
}

static void the_connection_budget_bounds_what_streams_queue(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    int64_t ids[8];
    struct qsend qs[8];
    memset(qs, 0, sizeof qs);
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.send_total = MIB;
    cc.send_buf = MIB;
    sc.max_stream_data = 65536;
    pair_open(&p, &cc, &sc);
    check("budget: handshake", 1, pump_until(&p, c_both_hs, NULL, 10000));
    int opened = 0;
    for (int i = 0; i < 8; i++) {
        if (qc_stream_open(p.c.q, &ids[i]) != 0) break;
        strm_get(&p.c, ids[i]);
        opened++;
    }
    check("budget: eight streams open", 8, opened);
    size_t taken = 0;
    int again = 0;
    for (int i = 0; i < 8; i++) {
        ssize_t w = qc_stream_send(p.c.q, ids[i], g_pat, MIB, 1);
        if (w > 0) { taken += (size_t)w; qs[i].off = (size_t)w; }
        if (w == 4096) again++;
        qs[i].waiting = qs[i].off < MIB;
        qs[i].seen = strm_get(&p.c, ids[i])->writable;
    }
    check("budget: 1048576 plus seven exempt 4096 accepted across eight streams", MIB + 7 * 4096, (long)taken);
    check("budget: seven take only their exempt first 4096", 7, again);
    check("budget: a refused stream has no room", 0, (long)qc_stream_room(p.c.q, ids[1]));
    uint64_t end = ms_now() + 300ull * g_tx;
    while (ms_now() < end) {
        pass(&p);
        budget_drain(&p, ids, qs);
    }
    p.s.consume_in_cb = 1;
    srv_consume_all(&p.s);
    end = ms_now() + 20000ull * g_tx;
    while (!c_srv_got_all(&p, ids) && ms_now() < end) {
        pass(&p);
        budget_drain(&p, ids, qs);
        srv_consume_all(&p.s);
    }
    int told = 0, good = 0;
    for (int i = 1; i < 8; i++) told += strm_get(&p.c, ids[i])->writable > 0;
    for (int i = 0; i < 8; i++) {
        struct strm *s = strm_find(&p.s, ids[i]);
        good += s && s->got == MIB && s->bad == 0 && s->fin;
    }
    check("budget: every refused stream is told it is writable", 7, told);
    check("budget: all 8 MiB arrive intact with fin", 8, good);
    pair_free(&p);
}

static void a_dead_write_side_frees_its_chunks_at_once(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    int64_t a = -1, b = -1, c = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.send_total = MIB;
    cc.send_buf = MIB;
    sc.max_stream_data = 65536;
    pair_open(&p, &cc, &sc);
    pump_until(&p, c_both_hs, NULL, 10000);
    check("dead write side: streams open", 1, open_stream(&p, &a) == 0 && open_stream(&p, &b) == 0);
    check("dead write side: 1 MiB queued", MIB, (long)qc_stream_send(p.c.q, a, g_pat, MIB, 0));
    check("dead write side: the budget is spent, B keeps its exempt 4096", 4096, (long)qc_stream_room(p.c.q, b));
    struct want w = { &p.s, a, 65536 };
    check("dead write side: the peer holds its window", 1, pump_until(&p, c_got, &w, 10000));
    pump_for(&p, 300);
    check("dead write side: chunks held before the reset", 1, qc_send_held(p.c.q) >= MIB - 65536);
    check("dead write side: reset of the write side", 0, qc_stream_reset_write(p.c.q, a, 3));
    check("dead write side: nothing held at once", 0, (long)qc_send_held(p.c.q));
    check("dead write side: nothing unsent", 0, (long)qc_stream_unsent(p.c.q, a));
    check("dead write side: the budget is back", MIB, (long)qc_stream_room(p.c.q, b));
    pump_for(&p, 300);
    check("dead write side: the peer keeps its side open", 0, strm_get(&p.s, a)->closed);
    check("dead write side: still nothing held", 0, (long)qc_send_held(p.c.q));

    check("peer stop: stream opens", 0, open_stream(&p, &c));
    check("peer stop: 1 MiB queued", MIB, (long)qc_stream_send(p.c.q, c, g_pat, MIB, 0));
    struct want w2 = { &p.s, c, 65536 };
    check("peer stop: the peer holds its window", 1, pump_until(&p, c_got, &w2, 10000));
    p.c.aborts = 0;
    check("peer stop: the peer stops", 0, qc_stream_stop(p.s.q, c, 5));
    check("peer stop: heard", 1, pump_until(&p, c_ab, NULL, 10000));
    check("peer stop: nothing held at once", 0, (long)qc_send_held(p.c.q));
    check("peer stop: the budget is back", MIB, (long)qc_stream_room(p.c.q, b));
    pair_free(&p);
}

static void pump_srv_only(struct pair *p, int (*cond)(struct pair *, void *), void *arg, unsigned limit_ms) {
    int ep = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN, .data.ptr = &p->s };
    epoll_ctl(ep, EPOLL_CTL_ADD, qc_fd(p->s.q), &ev);
    uint64_t end = ms_now() + (uint64_t)limit_ms * g_tx;
    while (!cond(p, arg) && ms_now() < end) {
        int t = qc_timeout_ms(p->s.q);
        struct epoll_event got;
        if (epoll_wait(ep, &got, 1, t < 0 || t > 20 ? 20 : t) > 0) (void)qc_on_readable(p->s.q);
        if (qc_timeout_ms(p->s.q) == 0) (void)qc_on_timer(p->s.q);
        qc_flush(p->s.q);
    }
    close(ep);
}

static int c_srv_64x200(struct pair *p, void *a) {
    int64_t *ids = a;
    for (int i = 0; i < 64; i++) {
        struct strm *s = strm_find(&p->s, ids[i]);
        if (!s || s->got < 200) return 0;
    }
    return 1;
}

static int good_64x200(struct pair *p, const int64_t *ids) {
    int good = 0;
    for (int i = 0; i < 64; i++) {
        struct strm *s = strm_find(&p->s, ids[i]);
        good += s && s->got == 200 && s->bad == 0;
    }
    return good;
}

static void small_sends_of_many_streams_share_packets(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    char nm[128];
    int64_t warm = -1, ids[64];
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    cc.defer_flush = 1;
    sc.max_streams = 100;
    pair_open(&p, &cc, &sc);
    p.s.consume_in_cb = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    open_stream(&p, &warm);
    out_static(&p.c, warm, g_pat, MIB, 0);
    struct want w = { &p.s, warm, MIB };
    pump_until(&p, c_got, &w, 10000);
    int opened = 0;
    for (int i = 0; i < 64; i++) opened += qc_stream_open(p.c.q, &ids[i]) == 0;
    pump_for(&p, 300);
    struct qc_stats a, b;
    qc_stats_get(p.c.q, &a);
    int took = 0;
    for (int i = 0; i < 64; i++) took += qc_stream_send(p.c.q, ids[i], g_pat, 200, 0) == 200;
    qc_flush(p.c.q);
    qc_stats_get(p.c.q, &b);
    name(nm, sizeof nm, "64 x 200 B: 64 streams took 200 bytes each");
    check(nm, 1, opened == 64 && took == 64);
    printf("     64 x 200 B: %llu datagrams in one flush\n", (unsigned long long)(b.dg_tx - a.dg_tx));
    if (g_tx == 1) {
        pump_srv_only(&p, c_srv_64x200, ids, 10000);
        name(nm, sizeof nm, "64 x 200 B: all 12800 bytes left in that one flush");
        check(nm, 64, good_64x200(&p, ids));
    }
    pump_until(&p, c_srv_64x200, ids, 10000);
    struct qc_stats c;
    qc_stats_get(p.c.q, &c);
    printf("     64 x 200 B: %llu datagrams until all arrived\n", (unsigned long long)(c.dg_tx - a.dg_tx));
    name(nm, sizeof nm, "64 x 200 B: all 12800 bytes arrive");
    check(nm, 64, good_64x200(&p, ids));
    name(nm, sizeof nm, "64 x 200 B: in at most 12 datagrams");
    check(nm, 1, c.dg_tx - a.dg_tx >= 1 && c.dg_tx - a.dg_tx <= 12);
    pair_free(&p);
}

static void a_path_that_shrinks_closes_the_connection(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    char nm[128];
    int64_t sid = -1, sid2 = -1;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    pair_open(&p, &cc, &sc);
    p.s.echo = 1;
    p.s.consume_in_cb = 1;
    p.c.consume_in_cb = 1;
    pump_until(&p, c_both_hs, NULL, 10000);
    open_stream(&p, &sid);
    out_static(&p.c, sid, g_pat, MIB, 1);
    struct want w = { &p.c, sid, 0 };
    name(nm, sizeof nm, "mtu drop: 1 MiB echo at full size");
    check(nm, 1, pump_until(&p, c_closed_st, &w, 10000) && strm_get(&p.c, sid)->got == MIB);
    struct qc_stats st;
    qc_stats_get(p.c.q, &st);
    g_emsg_n = 0;
    g_emsg_over = 1100;
    open_stream(&p, &sid2);
    out_static(&p.c, sid2, g_pat, 65536, 0);
    name(nm, sizeof nm, "mtu drop: the client closes");
    check(nm, 1, pump_until(&p, c_cli_closed, NULL, 10000));
    g_emsg_over = 0;
    name(nm, sizeof nm, "mtu drop: refused sends seen");
    check(nm, 1, g_emsg_n > 0);
    name(nm, sizeof nm, "mtu drop: a transport close");
    check(nm, 1, p.c.reason == QC_CLOSE_ERROR && !p.c.app);
    name(nm, sizeof nm, "mtu drop: why says path mtu");
    check(nm, 1, strstr(p.c.why, "path mtu") != NULL);
    pair_free(&p);
}

static void idle_flushes_cost_nothing(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    pair_open(&p, &cc, &sc);
    pump_until(&p, c_both_hs, NULL, 10000);
    pump_for(&p, 300);
    struct qc_stats a, b;
    qc_stats_get(p.c.q, &a);
    unsigned long c0 = qc_clock_reads();
    for (int i = 0; i < 100; i++) qc_flush(p.c.q);
    unsigned long c1 = qc_clock_reads();
    qc_stats_get(p.c.q, &b);
    check("idle qc_flush: 100 calls read the clock 0 times", 0, (long)(c1 - c0));
    check("idle qc_flush: and send nothing", 0, (long)(b.tx_calls - a.tx_calls));
    pair_free(&p);
}

static int c_fifth_mib(struct pair *p, void *a) {
    struct strm *s = strm_find(&p->s, *(int64_t *)a);
    return s && s->got >= MIB;
}

static void slow_streams_leave_room_for_another(void) {
    struct pair p;
    struct qc_cfg cc;
    struct qc_srv_cfg sc;
    int64_t ids[5];
    cli_cfg(&cc, "h3");
    srv_cfg(&sc, "h3");
    sc.max_stream_data = 65536;
    pair_open(&p, &cc, &sc);
    check("slow peers: handshake", 1, pump_until(&p, c_both_hs, NULL, 10000));
    int opened = 0;
    for (int i = 0; i < 5; i++) opened += open_stream(&p, &ids[i]) == 0;
    check("slow peers: five streams", 5, opened);
    long full = 0;
    for (int i = 0; i < 4; i++) full += qc_stream_send(p.c.q, ids[i], g_pat, MIB, 0) == 524288;
    check("slow peers: four fill their 512 KiB send_buf", 4, full);
    check("slow peers: the fifth still takes its 512 KiB at once", 524288, (long)qc_stream_send(p.c.q, ids[4], g_pat, MIB, 0));
    size_t off = 524288;
    uint64_t end = ms_now() + 20000ull * g_tx;
    while (!c_fifth_mib(&p, &ids[4]) && ms_now() < end) {
        pass(&p);
        if (off < MIB) {
            ssize_t w = qc_stream_send(p.c.q, ids[4], g_pat + off, MIB - off, 0);
            if (w > 0) off += (size_t)w;
        }
        struct strm *s = strm_find(&p.s, ids[4]);
        if (s && s->got > s->consumed) {
            qc_stream_consumed(p.s.q, ids[4], s->got - s->consumed);
            s->consumed = s->got;
        }
    }
    struct strm *f = strm_find(&p.s, ids[4]);
    check("slow peers: the fifth delivers 1 MiB intact", 1, f && f->got >= MIB && f->bad == 0);
    int stuck = 0;
    for (int i = 0; i < 4; i++) {
        struct strm *s = strm_find(&p.s, ids[i]);
        stuck += s && s->got <= 65536;
    }
    check("slow peers: the four stay at their window", 4, stuck);
    pair_free(&p);
}

int main(void) {
    g_pat = malloc(4 * MIB);
    for (size_t i = 0; i < 4 * MIB; i++) g_pat[i] = pat(i);
    check("wolfSSL is built for strict alignment", 1, tcg_wolfssl_aligned());
    check("certificates issued", 0, certs_make());
    const char *tx = getenv("QC_TEST_TIME_X");
    if (tx && atoi(tx) > 0) g_tx = (unsigned)atoi(tx);
    const char *env = getenv("QC_TEST_NO_BATCH");
    int only_nb = env && !strcmp(env, "1");
    g_nb = only_nb;
    handshake_completes_only_on_the_same_alpn();
    for (int m = only_nb; m < 2; m++) {
        g_nb = m;
        a_megabyte_on_a_stream_arrives_intact_both_ways();
        a_datagram_arrives_intact_and_an_oversized_one_is_refused();
        a_filter_wraps_every_datagram_on_the_wire();
        an_oversized_datagram_is_lost_not_fatal();
        deferred_sends_leave_together();
        four_megabytes_with_bounded_work();
        small_sends_of_many_streams_share_packets();
        a_path_that_shrinks_closes_the_connection();
    }
    g_nb = only_nb;
    unread_stream_data_stops_at_the_window();
    a_pin_decides_alone();
    chain_and_name_are_checked_without_a_pin();
    an_idle_connection_closes_at_the_idle_limit();
    stop_and_reset_reach_the_peer_with_their_codes();
    room_coming_back_is_announced();
    the_preferred_suite_is_negotiated();
    connection_credit_of_a_dead_stream_comes_back();
    a_kernel_without_udp_segment_gets_plain_datagrams();
    a_server_without_alpn_is_refused();
    a_refused_port_is_fatal_only_before_the_handshake();
    an_oversized_filter_overhead_is_refused();
    streams_come_back_after_they_close();
    the_owner_hears_when_streams_open_again();
    six_hundred_streams_at_once();
    a_peer_abort_of_one_direction_is_heard();
    a_reset_stream_forgets_what_it_had_to_send();
    acknowledged_data_holds_no_chunk();
    unsent_counts_only_what_no_packet_carried();
    dont_fragment_is_set_on_both_families();
    credit_needs_no_flush_from_the_owner();
    one_clock_read_per_batch();
    the_connection_budget_bounds_what_streams_queue();
    a_dead_write_side_frees_its_chunks_at_once();
    idle_flushes_cost_nothing();
    slow_streams_leave_room_for_another();
    for (int m = only_nb; m < 2; m++) {
        g_nb = m;
        a_callback_may_drive_another_connection();
    }
    g_nb = only_nb;
    free(g_pat);
    return unit_done("quicmatch");
}
