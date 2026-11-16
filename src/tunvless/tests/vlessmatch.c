/* vless_connect failure paths: the descriptor and the keys after each "no".
 *
 * WHAT IS CHECKED. Each failure path of connection setup decides on its own how to clean up:
 * close(fd), transport_close, or nothing when it fails before the socket exists. The choice
 * matters. Once the traffic keys are expanded, the connection holds cipher contexts that
 * transport_close must wipe, and certificate verification allocates on the heap (wolfSSL chain
 * parsing), which the descriptor does not hold. Callers do not clean up either: the spare pool
 * only marks the slot empty, and the node probe returns at once. So a wrong choice leaks on EVERY
 * attempt, and the attempts never stop: the pool refills on every SYN. On every path the test
 * watches three things: the return code, the process descriptors (their count must come back to
 * where it was) and the heap, through LeakSanitizer, checked after each case rather than in one
 * report at exit.
 *
 * Setup lives in the transport (src/proto/transport: transport_open, tr_link_open, security in
 * trsec.c); vless_connect only hands it the node.
 *
 * HOW IT WORKS WITHOUT A NODE OR A NETWORK. TCP setup goes through the g_tcp_dial seam
 * (src/proto/transport/trdial.c). The test hands the client one end of a socketpair and speaks
 * the server half of TLS 1.3 on the other: it parses the ClientHello, takes its key_share,
 * computes X25519, derives the handshake key schedule (RFC 8446 §7.1), sends encrypted
 * EncryptedExtensions, Certificate when needed, and Finished, and checks the client's Finished as
 * a real server would. tests/fake-vless.py speaks only security=none, and tests/run-reality.sh
 * needs sing-box, root and network namespaces.
 *
 * WHY THE SERVER HALF IS IN C, NOT PYTHON. The test is part of `make crypto-test`, and CI also runs
 * it under qemu for other architectures; it needs nothing beyond the crypto library the client is
 * built on. Second, the key schedule must match the client's to the byte: with both halves on
 * the same primitives (the scrypto layer), a mismatch means a bug in our TLS code, not a
 * difference between implementations. The HKDF label and the signature prefix are still built
 * here by separate copies, or a bug in them would agree with itself.
 *
 * security=tls WITH OUR OWN ROOTS. Reality proves itself by an HMAC in the signature field of a
 * temporary certificate: no X.509 chain, no root store. So the Reality cases never reach chain
 * verification, and only security=tls tests it. The TR_ENOH2 path (traffic keys already expanded,
 * so it must close through transport_close) is reachable only after a server check PASSES.
 *
 * So the test issues its own chain: a root and leaves for the SNI name, ECDSA P-256 keys, validity
 * from the current time (a certificate frozen in the repository would one day expire and fail
 * the test for no fault of its own). The root goes to a PEM file whose path reaches the engine
 * through the g_cert_roots seam in src/proto/tls/roots.c. The server half signs CertificateVerify
 * with a real signature over the transcript up to and including Certificate (RFC 8446 §4.4.3,
 * the prefix of 64 spaces and the label), and the client checks it with its own code: a mismatch
 * here means a bug in the engine.
 *
 * Covered this way: full success (handshake, chain, name against sni), the TR_ENOH2 path with
 * its transport_close, a wrong name, no CertificateVerify, a bad signature, a signature algorithm
 * we did not offer, and a self-signed leaf.
 *
 * Certificates are issued by tests/certgen.c on wolfCrypt with WOLFSSL_CERT_GEN (the Makefile
 * builds the tests' library with it; the program's build cannot issue certificates). The
 * Makefile always defines STEER_HAVE_X509WRITE; built by hand without it, the test SKIPS the
 * security=tls cases and says so loudly, since a silent skip would read as a pass.
 */
/* Before any include: the included sources need GNU extensions, and the first header fixes the
 * feature set. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <dirent.h>
#include <stdint.h>

/* Three sources are included whole, not linked, to reach their static seams: g_tcp_dial
 * (trdial.c), g_cert_roots (roots.c) and g_fm_new (trsec.c). The VLESS client and the other
 * transport layers are linked as separate objects (Makefile). */
#include "../src/proto/transport/trdial.c"
#include "../src/proto/tls/roots.c"
#include "../src/proto/transport/trsec.c"
#include "../src/proto/tls/certverify.c"
#include "fmrelay.h"
#include "client.h"
#include "vless_proto.h"

#include "scrypto.h"
#include "reality.h"
#include "vision.h"
#if defined(STEER_HAVE_X509WRITE)
# include "certgen.h"
#endif

/* The shared secret with the peer's ephemeral key: the function tls13.c uses, not a copy. A
 * copy of crypto code is a second place where scalar clamping could differ. */
int x25519_shared_ext(const unsigned char priv[32], const unsigned char peer[32],
                      unsigned char out[32]);
void tr_venc_test_set_vmess_counts(struct transport *t, uint32_t tx_cnt, uint32_t rx_cnt);

int run_quiet(const char *const argv[]) { (void)argv; return 0; }

#if defined(__SANITIZE_ADDRESS__)
# include <sanitizer/lsan_interface.h>
# define LEAK_CHECK() __lsan_do_recoverable_leak_check()
#else
/* No sanitizer: the return code and descriptor checks still run, but the test must not stay
 * silent about the heap, since a silent skip reads as a pass. main says so once. */
# define LEAK_CHECK() 0
#endif

static int fails;

static void check(const char *what, long want, long got) {
    printf("%-64s %s\n", what, want == got ? "ok" : "FAIL");
    if (want != got) {
        printf("     want: %ld\n     got:  %ld\n", want, got);
        fails++;
    }
}

static void check_str(const char *what, const char *want, const char *got) {
    int ok = got && strstr(got, want) != NULL;
    printf("%-64s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok) {
        printf("     want substring: %s\n     got:            %s\n", want, got ? got : "(none)");
        fails++;
    }
}

/* Descriptors open in the process. A descriptor leak shows here without any sanitizer; one per
 * attempt on the TR_ENOH2 path (a grpc node with security=reality) reaches RLIMIT_NOFILE within
 * a day of probing. */
static int fd_count(void) {
    DIR *d = opendir("/proc/self/fd");
    if (!d) return -1;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d))) if (e->d_name[0] != '.') n++;
    closedir(d);
    return n;
}

/* ---- server half of TLS 1.3 ----------------------------------------------------
 *
 * Just enough for the client to finish the handshake: one cipher suite (0x1301, AES-128-GCM
 * with SHA-256), one group (X25519), no resumption. */

#define SUITE_HI 0x13
#define SUITE_LO 0x01
#define HLEN 32u                       /* SHA-256: both the transcript hash and the secret size */

struct plan {
    const char *name;
    int no_keyshare;      /* ServerHello without key_share: fails BEFORE key derivation */
    int bad_finished;     /* corrupt the server Finished */
    int cert;             /* 0: send none, 1: a garbage Certificate, 2: a compressed one (0x19) */
    const char *alpn;     /* ALPN string in EncryptedExtensions, or NULL */
    int hangup;           /* close the connection right after ClientHello */
    /* The security=tls path: a real chain issued by the test. `cert` is not read for these
     * cases; `chain` decides what to send. */
    int chain;            /* 0: not the tls path; otherwise the leaf index in g_leaf[] */
    int no_cv;            /* send Certificate and NO CertificateVerify */
    int cv_bad_sig;       /* corrupt a signature byte */
    int cv_bad_alg;       /* sign with a scheme we did not offer (rsa_pkcs1_sha256) */
    /* reality_ok: a Reality temporary certificate with a real HMAC-SHA512 signature over the
     * authkey (the only way to a SUCCESSFUL Reality in this test). upg: after the handshake the
     * server carries data too: traffic keys, the Upgrade request, a 101 answer with the first
     * data in the SAME record, and the client's reply (1: ws, 2: httpupgrade). */
    int reality_ok;
    int upg;
    /* ws with early data (path `?ed=2048`): the client writes "hello" BEFORE reading, and it
     * must go in the request's Sec-WebSocket-Protocol: with Ed > 0 Xray holds the request until
     * the first write. */
    int ed_first;
    int compress;
    int compress_junk;
    int compress_empty;
    int compress_short;
    int cert_trail;
    int cert_twice;
    int cv_twice;
    int firefox;
    unsigned keyshare_group;
    int hrr;
    int dc;
    int hold;
    int after_peer;
    int tell_peer;
    int send_root;
};

struct srv {
    int fd;
    const struct plan *plan;
    /* Server write keys and record counter. */
    unsigned char key[16], iv[12];
    unsigned char s_hs[HLEN];
    uint64_t seq;
    struct sc_hash_ctx tr;             /* handshake transcript */
    int rc;                            /* != 0: the half broke by itself, not by plan */
    int fin_sent;                      /* the server Finished went out */
    /* Data path (plan.upg): handshake secrets and what the server saw. */
    unsigned char hs[HLEN], c_hs[HLEN];
    int alpn_h11;                      /* the ClientHello ALPN is http/1.1 alone */
    char req[4096];                    /* the Upgrade request as received */
    int got_hello;                     /* the client's "hello" arrived and parsed */
    int overlap;
};

#define HOLD_MS 3000
static pthread_mutex_t g_meet_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_meet_cv = PTHREAD_COND_INITIALIZER;
static int g_meet;

static int g_peer_fin;

static int peer_wait(void) {
    struct timespec dl;
    clock_gettime(CLOCK_REALTIME, &dl);
    dl.tv_sec += HOLD_MS / 1000;
    dl.tv_nsec += (long)(HOLD_MS % 1000) * 1000000L;
    if (dl.tv_nsec >= 1000000000L) { dl.tv_sec++; dl.tv_nsec -= 1000000000L; }
    pthread_mutex_lock(&g_meet_mu);
    while (!g_peer_fin && pthread_cond_timedwait(&g_meet_cv, &g_meet_mu, &dl) == 0) {}
    int done = g_peer_fin;
    pthread_mutex_unlock(&g_meet_mu);
    return done;
}

static void peer_tell(void) {
    pthread_mutex_lock(&g_meet_mu);
    g_peer_fin = 1;
    pthread_cond_broadcast(&g_meet_cv);
    pthread_mutex_unlock(&g_meet_mu);
}

static int hello_meet(void) {
    struct timespec dl;
    clock_gettime(CLOCK_REALTIME, &dl);
    dl.tv_sec += HOLD_MS / 1000;
    dl.tv_nsec += (long)(HOLD_MS % 1000) * 1000000L;
    if (dl.tv_nsec >= 1000000000L) { dl.tv_sec++; dl.tv_nsec -= 1000000000L; }
    pthread_mutex_lock(&g_meet_mu);
    g_meet++;
    pthread_cond_broadcast(&g_meet_cv);
    while (g_meet < 2 && pthread_cond_timedwait(&g_meet_cv, &g_meet_mu, &dl) == 0) {}
    int both = g_meet >= 2;
    pthread_mutex_unlock(&g_meet_mu);
    return both;
}

/* Static key pair of the Reality server for plan.reality_ok: the node's pbk is its public half. */
static unsigned char g_rs_priv[32], g_rs_pub[32];
/* What the server saw in the ALPN of the last ClientHello (for runs through run_case). */
static int g_seen_h11 = -1;
/* After the last run_case: 1 if the client's Finished came and verifies, 0 if the client sent
 * nothing after its ClientHello, -1 for anything else. */
static int g_cfin = -1;

/* HKDF-Expand-Label from RFC 8446 §7.1. Our own copy, not a call to the static one in tls13.c:
 * the test must compute the label ITSELF, or a bug in the client's wrapper would agree with
 * itself and go unnoticed. */
static int xlabel(const unsigned char *secret, const char *label,
                  const unsigned char *ctx, size_t ctx_n,
                  unsigned char *out, size_t out_n) {
    unsigned char info[128];
    size_t n = 0, ln = strlen(label);
    if (2 + 1 + 6 + ln + 1 + ctx_n > sizeof(info)) return -1;
    info[n++] = (unsigned char)(out_n >> 8);
    info[n++] = (unsigned char)out_n;
    info[n++] = (unsigned char)(6 + ln);
    memcpy(info + n, "tls13 ", 6); n += 6;
    memcpy(info + n, label, ln);    n += ln;
    info[n++] = (unsigned char)ctx_n;
    if (ctx_n) { memcpy(info + n, ctx, ctx_n); n += ctx_n; }
    return sc_hkdf_expand(SC_SHA256, secret, HLEN, info, n, out, out_n);
}

static void tr_snapshot(const struct sc_hash_ctx *tr, unsigned char out[HLEN]) {
    struct sc_hash_ctx c;
    if (sc_hash_clone(&c, tr) != 0) { memset(out, 0, HLEN); return; }
    sc_hash_final(&c, out);
    sc_hash_free(&c);
}

static int wr_all(int fd, const unsigned char *b, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, b + sent, n - sent);
        if (w <= 0) return -1;
        sent += (size_t)w;
    }
    return 0;
}

static int rd_all(int fd, unsigned char *b, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, b + got, n - got);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

/* One record: a five-byte header, then the body. */
static int rd_rec(int fd, unsigned char *type, unsigned char *body, size_t cap, size_t *n) {
    unsigned char h[5];
    if (rd_all(fd, h, 5)) return -1;
    size_t len = ((size_t)h[3] << 8) | h[4];
    if (len > cap) return -1;
    if (rd_all(fd, body, len)) return -1;
    *type = h[0];
    *n = len;
    return 0;
}

/* ---- our own X.509 chain for security=tls -------------------------------------------
 *
 * Three leaves:
 *   LEAF_OK   for the SNI name, signed by the root: the check passes, which is the way to the
 *             TR_ENOH2 path and its transport_close;
 *   LEAF_NAME signed by the same root, for another name: the check must fail on the name, not
 *             pass because "the chain verified";
 *   LEAF_SELF self-signed: the root plays no part, the chain check fails.
 *
 * ECDSA P-256 keys, not RSA: RSA-2048 generation takes seconds and would slow the test with no
 * gain for what is tested. certverify.c accepts both, and the CertificateVerify signature goes
 * through the same sc_cert_verify_sig (tests/scryptomatch.c checks RSA and PSS against OpenSSL
 * signatures).
 *
 * Validity is counted FROM THE CURRENT TIME, not fixed in a string: a frozen certificate expires
 * one day and fails the test for no fault of its own, so it is issued anew on every run.
 */
#if defined(STEER_HAVE_X509WRITE)

#define LEAF_OK   1
#define LEAF_NAME 2
#define LEAF_SELF 3
#define LEAF_LATE 4
#define LEAF_EARLY 5

/* The name the good leaf is issued for, also the node's SNI: the certificate is checked against
 * sni, not host (trsec.c, verify_host). */
#define TLS_SNI "tls.node.invalid"

struct leaf {
    unsigned char der[2048];
    size_t der_n;
    struct tcg_key *key;         /* the leaf's key: it signs CertificateVerify */
};

static int64_t g_time_shift;
time_t __real_time(time_t *t);
time_t __wrap_time(time_t *t) {
    time_t now = __real_time(NULL) + (time_t)g_time_shift;
    if (t) *t = now;
    return now;
}
#if (defined(__GLIBC__) && defined(__USE_TIME_BITS64) && __TIMESIZE == 32) || (defined(_REDIR_TIME64) && _REDIR_TIME64)
time_t __real___time64(time_t *t);
time_t __wrap___time64(time_t *t) {
    time_t now = __real___time64(NULL) + (time_t)g_time_shift;
    if (t) *t = now;
    return now;
}
#endif

static struct leaf g_leaf[6];        /* [0] unused: indexes match LEAF_* */
static unsigned char g_root_der[2048];
static size_t g_root_n;
static char g_roots_file[64];
static int g_chain_ready;

/* Root, three leaves and the store file, once per process: certverify.c loads the roots under
 * pthread_once, so a second store in the same process would have no effect, and all cases must
 * run against ONE root set. The name goes in the CN: the test issues no SAN, and the name check
 * must find it there. */
static int chain_build(void) {
    struct tcg_key *root_key = tcg_key_new();
    if (!root_key) return -1;

    static char pem[4096];
    unsigned char root_der[2048];
    size_t root_n = 0;
    if (tcg_issue(root_key, "steer test root", NULL, 1, NULL, NULL, 0,
                  root_der, sizeof(root_der), &root_n) != 0 ||
        tcg_der_to_pem(root_der, root_n, pem, sizeof(pem)) != 0) {
        tcg_key_free(root_key);
        return -1;
    }
    memcpy(g_root_der, root_der, root_n);
    g_root_n = root_n;

    struct { int idx; const char *cn; int self; } want[] = {
        { LEAF_OK,   TLS_SNI,          0 },
        { LEAF_NAME, "other.invalid",  0 },
        { LEAF_SELF, TLS_SNI,          1 },
        { LEAF_LATE, TLS_SNI,          0 },
        { LEAF_EARLY, TLS_SNI,         0 },
    };
    for (size_t i = 0; i < sizeof(want) / sizeof(*want); i++) {
        struct leaf *l = &g_leaf[want[i].idx];
        if (!(l->key = tcg_key_new())) { tcg_key_free(root_key); return -1; }
        g_time_shift = want[i].idx == LEAF_LATE ? 82800 : want[i].idx == LEAF_EARLY ? -172800 : 0;
        int rc = want[i].self
            ? tcg_issue(l->key, want[i].cn, NULL, 0, NULL, NULL, 0, l->der, sizeof(l->der), &l->der_n)
            : tcg_issue(l->key, want[i].cn, NULL, 0, root_key, root_der, root_n,
                        l->der, sizeof(l->der), &l->der_n);
        g_time_shift = 0;
        if (rc != 0) { tcg_key_free(root_key); return -1; }
    }
    tcg_key_free(root_key);

    snprintf(g_roots_file, sizeof(g_roots_file), "%s", "/tmp/vlessmatch-roots-XXXXXX");
    int fd = mkstemp(g_roots_file);
    if (fd < 0) return -1;
    size_t pn = strlen(pem);
    int ok = wr_all(fd, (const unsigned char *)pem, pn) == 0;
    close(fd);
    if (!ok) return -1;
    g_chain_ready = 1;
    return 0;
}

static void chain_free(void) {
    for (int i = 1; i <= LEAF_EARLY; i++) { tcg_key_free(g_leaf[i].key); g_leaf[i].key = NULL; }
    if (g_roots_file[0]) unlink(g_roots_file);
}

/* A Certificate message with one leaf (RFC 8446 §4.4.2): a context byte, a list with a 3-byte
 * length, holding one entry "3-byte length + DER + 2-byte extensions". The root is left out on
 * purpose: it is already in the store, and the chain must verify without it, or the test would
 * check the server's generosity instead of the verification. */
static size_t cert_msg(const struct leaf *l, int dc, int send_root, unsigned char *out, size_t cap) {
    static const unsigned char dcx[] = { 0x00, 0x0C, 0x00, 0x22, 0x00, 0x08, 0x00, 0x01, 0x51, 0x80,
                                         0x04, 0x03, 0x00, 0x00 };
    size_t xn = dc ? sizeof dcx : 2;
    size_t rn = send_root ? 3 + g_root_n + 2 : 0;
    size_t body = 1 + 3 + 3 + l->der_n + xn + rn;
    if (4 + body > cap) return 0;
    size_t n = 0;
    out[n++] = 0x0B;
    out[n++] = (unsigned char)(body >> 16);
    out[n++] = (unsigned char)(body >> 8);
    out[n++] = (unsigned char)body;
    out[n++] = 0x00;                                     /* certificate_request_context */
    size_t list = 3 + l->der_n + xn + rn;
    out[n++] = (unsigned char)(list >> 16);
    out[n++] = (unsigned char)(list >> 8);
    out[n++] = (unsigned char)list;
    out[n++] = (unsigned char)(l->der_n >> 16);
    out[n++] = (unsigned char)(l->der_n >> 8);
    out[n++] = (unsigned char)l->der_n;
    memcpy(out + n, l->der, l->der_n); n += l->der_n;
    if (dc) { memcpy(out + n, dcx, sizeof dcx); n += sizeof dcx; }
    else { out[n++] = 0x00; out[n++] = 0x00; }
    if (send_root) {
        out[n++] = (unsigned char)(g_root_n >> 16);
        out[n++] = (unsigned char)(g_root_n >> 8);
        out[n++] = (unsigned char)g_root_n;
        memcpy(out + n, g_root_der, g_root_n); n += g_root_n;
        out[n++] = 0x00; out[n++] = 0x00;
    }
    return n;
}

static size_t stored_stream(int alg, const unsigned char *in, size_t n, unsigned char *out) {
    size_t k = 0;
    if (alg == 1) {
        uint32_t a = 1, b = 0;
        for (size_t i = 0; i < n; i++) { a = (a + in[i]) % 65521; b = (b + a) % 65521; }
        out[k++] = 0x78; out[k++] = 0x01; out[k++] = 0x01;
        out[k++] = (unsigned char)n; out[k++] = (unsigned char)(n >> 8);
        out[k++] = (unsigned char)~n; out[k++] = (unsigned char)(~n >> 8);
        memcpy(out + k, in, n); k += n;
        out[k++] = (unsigned char)(b >> 8); out[k++] = (unsigned char)b;
        out[k++] = (unsigned char)(a >> 8); out[k++] = (unsigned char)a;
    } else if (alg == 2) {
        uint32_t h = ((uint32_t)(n - 1) << 4) | (1u << 20);
        out[k++] = (unsigned char)h; out[k++] = (unsigned char)(h >> 8); out[k++] = (unsigned char)(h >> 16);
        memcpy(out + k, in, n); k += n;
        out[k++] = 0x03;
    } else {
        uint32_t h = 1u | ((uint32_t)n << 3);
        out[k++] = 0x28; out[k++] = 0xB5; out[k++] = 0x2F; out[k++] = 0xFD;
        out[k++] = 0x00; out[k++] = 0x30;
        out[k++] = (unsigned char)h; out[k++] = (unsigned char)(h >> 8); out[k++] = (unsigned char)(h >> 16);
        memcpy(out + k, in, n); k += n;
    }
    return k;
}

static pthread_mutex_t g_sec_mu = PTHREAD_MUTEX_INITIALIZER;
static unsigned char g_sec[3 * HLEN + 16];
static int g_sec_set, g_sec_wipes;

static void note_secrets(const unsigned char *hs, const unsigned char *c_hs, const unsigned char *s_hs,
                         const unsigned char *s_key) {
    pthread_mutex_lock(&g_sec_mu);
    memcpy(g_sec, hs, HLEN);
    memcpy(g_sec + HLEN, c_hs, HLEN);
    memcpy(g_sec + 2 * HLEN, s_hs, HLEN);
    memcpy(g_sec + 3 * HLEN, s_key, 16);
    g_sec_set = 1;
    pthread_mutex_unlock(&g_sec_mu);
}

void __real_sc_wipe(void *p, size_t n);
void __wrap_sc_wipe(void *p, size_t n) {
    pthread_mutex_lock(&g_sec_mu);
    int all = g_sec_set;
    for (int i = 0; all && i < 4; i++)
        all = memmem(p, n, g_sec + i * HLEN, i < 3 ? HLEN : 16) != NULL;
    pthread_mutex_unlock(&g_sec_mu);
    __real_sc_wipe(p, n);
    if (!all) return;
    size_t left = 0;
    for (size_t i = 0; i < n; i++) left += ((const unsigned char *)p)[i] != 0;
    if (!left) __atomic_add_fetch(&g_sec_wipes, 1, __ATOMIC_SEQ_CST);
}

static size_t compressed_msg(int alg, int junk, unsigned char *msg, size_t n, size_t cap) {
    unsigned char z[3072];
    size_t bn = n - 4;
    if (bn + 16 > sizeof z) return 0;
    size_t zn = stored_stream(alg, msg + 4, bn, z);
    size_t body = 2 + 3 + 3 + zn + (junk ? 1 : 0);
    if (4 + body > cap) return 0;
    size_t k = 0;
    msg[k++] = 0x19;
    msg[k++] = (unsigned char)(body >> 16); msg[k++] = (unsigned char)(body >> 8); msg[k++] = (unsigned char)body;
    msg[k++] = 0x00; msg[k++] = (unsigned char)alg;
    msg[k++] = (unsigned char)(bn >> 16); msg[k++] = (unsigned char)(bn >> 8); msg[k++] = (unsigned char)bn;
    msg[k++] = (unsigned char)(zn >> 16); msg[k++] = (unsigned char)(zn >> 8); msg[k++] = (unsigned char)zn;
    memcpy(msg + k, z, zn); k += zn;
    if (junk) msg[k++] = 0x00;
    return k;
}

/* CertificateVerify: a signature over 64 spaces, the label, a zero byte and the transcript hash
 * up to and including Certificate. The prefix is built HERE, not taken from certverify.c: the
 * two halves must reach the same answer independently, or a bug in the prefix would agree with
 * itself. */
static size_t cv_msg(const struct leaf *l, const unsigned char thash[HLEN],
                     const struct plan *pl, unsigned char *out, size_t cap) {
    unsigned char content[64 + 33 + 1 + HLEN];
    size_t cn = 0;
    memset(content, 0x20, 64); cn = 64;
    memcpy(content + cn, "TLS 1.3, server CertificateVerify", 33); cn += 33;
    content[cn++] = 0x00;
    memcpy(content + cn, thash, HLEN); cn += HLEN;

    unsigned char digest[HLEN];
    if (sc_hash(SC_SHA256, content, cn, digest) != 0) return 0;

    /* A DER ECDSA P-256 signature is at most 72 bytes; room to spare. */
    unsigned char sig[160];
    size_t sig_n = 0;
    if (tcg_sign_sha256(l->key, digest, sig, sizeof(sig), &sig_n) != 0) return 0;
    if (pl->cv_bad_sig) sig[sig_n / 2] ^= 0xFF;

    if (4 + 4 + sig_n > cap) return 0;
    size_t n = 0;
    out[n++] = 0x0F;
    out[n++] = 0; out[n++] = 0; out[n++] = (unsigned char)(4 + sig_n);
    /* 0x0403 is ecdsa_secp256r1_sha256, which our signature_algorithms lists. 0x0401 is
     * rsa_pkcs1_sha256, which TLS 1.3 forbids for CertificateVerify, and we do not offer it: a
     * server choosing it must get its own reason, not "bad signature". */
    out[n++] = 0x04; out[n++] = pl->cv_bad_alg ? 0x01 : 0x03;
    out[n++] = (unsigned char)(sig_n >> 8);
    out[n++] = (unsigned char)sig_n;
    memcpy(out + n, sig, sig_n); n += sig_n;
    return n;
}
#endif /* STEER_HAVE_X509WRITE */

/* ClientHello: we need the client's key_share and the session_id, which the server must echo
 * as is. Parsed by extension type, not by offset: reality.c's Hello changes with the browser
 * look. */
static int ch_pick(const unsigned char *b, size_t n, unsigned char pub[32],
                   unsigned char *sid, size_t *sid_n) {
    if (n < 40 || b[0] != 0x01) return -1;
    size_t p = 4 + 2 + 32;
    size_t sn = b[p++];
    if (sn > 32 || p + sn > n) return -1;
    memcpy(sid, b + p, sn);
    *sid_n = sn;
    p += sn;
    if (p + 2 > n) return -1;
    size_t cs = ((size_t)b[p] << 8) | b[p + 1];
    p += 2 + cs;
    if (p >= n) return -1;
    p += 1 + b[p];                                  /* compression_methods */
    if (p + 2 > n) return -1;
    size_t exts = ((size_t)b[p] << 8) | b[p + 1];
    p += 2;
    size_t end = p + exts;
    if (end > n) return -1;
    while (p + 4 <= end) {
        unsigned etype = ((unsigned)b[p] << 8) | b[p + 1];
        size_t elen = ((size_t)b[p + 2] << 8) | b[p + 3];
        p += 4;
        if (p + elen > end) return -1;
        if (etype == 0x0033) {
            /* client_shares: list length (2), then group (2) + length (2) + key. Take X25519
             * (0x001d) specifically: reality.c may offer the post-quantum group, and it comes
             * first in the list. */
            size_t q = 2;
            while (q + 4 <= elen) {
                unsigned grp = ((unsigned)b[p + q] << 8) | b[p + q + 1];
                size_t kn = ((size_t)b[p + q + 2] << 8) | b[p + q + 3];
                if (q + 4 + kn > elen) break;
                if (grp == 0x001d && kn == 32) {
                    memcpy(pub, b + p + q + 4, 32);
                    return 0;
                }
                q += 4 + kn;
            }
        }
        p += elen;
    }
    return -1;
}

/* An encrypted handshake record with one message: the client collects messages across record
 * boundaries, so this is tested too. */
static int send_enc(struct srv *s, const unsigned char *msg, size_t n) {
    unsigned char out[4096];
    if (n + 1 + 16 + 5 > sizeof(out)) return -1;
    size_t total = n + 1 + 16;
    out[0] = 0x17; out[1] = 0x03; out[2] = 0x03;
    out[3] = (unsigned char)(total >> 8);
    out[4] = (unsigned char)total;
    memcpy(out + 5, msg, n);
    out[5 + n] = 0x16;                              /* the real record type */

    unsigned char nonce[12];
    memcpy(nonce, s->iv, 12);
    for (int i = 0; i < 8; i++) nonce[11 - i] ^= (unsigned char)(s->seq >> (8 * i));

    /* A one-off key per record: the server half is not about speed. The context goes on the
     * heap: at over a kilobyte it does not belong on this thread's stack. */
    struct sc_aead *g = malloc(sizeof(*g));
    if (!g) return -1;
    int rc = sc_aead_setkey(g, SC_AES128_GCM, s->key);
    if (rc == 0) rc = sc_aead_seal(g, nonce, out, 5, out + 5, n + 1, out + 5 + n + 1);
    sc_aead_free(g);
    free(g);
    if (rc) return -1;
    s->seq++;
    return wr_all(s->fd, out, 5 + total);
}

/* ---- data path after the handshake: ws and httpupgrade (plan.upg) -------------------------
 *
 * Here the server half takes the connection on to data: the application traffic keys (RFC 8446
 * §7.1, from the master secret and the transcript up to the server Finished), the client
 * Finished under the handshake key, the Upgrade request, a 101 answer followed in the SAME record
 * by the first stream data (a ws frame or raw httpupgrade bytes: a remainder the transport must
 * not lose), and whatever the client sends back. Each direction has its own key and counter
 * (struct dir). */
struct dir { struct sc_aead g; unsigned char iv[12]; uint64_t seq; int ready; };

static int dir_set(struct dir *d, const unsigned char secret[HLEN]) {
    unsigned char key[16];
    if (xlabel(secret, "key", NULL, 0, key, 16) || xlabel(secret, "iv", NULL, 0, d->iv, 12)) return -1;
    if (d->ready) sc_aead_free(&d->g);
    d->ready = 0;
    if (sc_aead_setkey(&d->g, SC_AES128_GCM, key)) return -1;
    d->ready = 1;
    d->seq = 0;
    return 0;
}

static void dir_nonce(const struct dir *d, unsigned char n[12]) {
    memcpy(n, d->iv, 12);
    for (int i = 0; i < 8; i++) n[11 - i] ^= (unsigned char)(d->seq >> (8 * i));
}

/* The next record from the client: ChangeCipherSpec is skipped, the rest is decrypted. */
static int rec_open(struct dir *d, int fd, unsigned char *out, size_t cap, size_t *n,
                    unsigned char *inner) {
    for (;;) {
        unsigned char type;
        size_t len;
        if (rd_rec(fd, &type, out, cap, &len)) return -1;
        if (type == 0x14) continue;
        if (type != 0x17 || len < 17) return -1;
        unsigned char hdr[5] = { 0x17, 0x03, 0x03, (unsigned char)(len >> 8), (unsigned char)len };
        unsigned char nonce[12];
        dir_nonce(d, nonce);
        if (sc_aead_open(&d->g, nonce, hdr, 5, out, len - 16, out + len - 16)) return -1;
        d->seq++;
        size_t pt = len - 16;
        while (pt && !out[pt - 1]) pt--;
        if (!pt) return -1;
        *inner = out[--pt];
        *n = pt;
        return 0;
    }
}

static size_t rec_wrap(struct dir *d, const unsigned char *msg, size_t n, unsigned char *out) {
    if (n + 17 > 4096 + 17) return 0;
    size_t total = n + 1 + 16;
    out[0] = 0x17; out[1] = 0x03; out[2] = 0x03;
    out[3] = (unsigned char)(total >> 8); out[4] = (unsigned char)total;
    memcpy(out + 5, msg, n);
    out[5 + n] = 0x17;
    unsigned char nonce[12];
    dir_nonce(d, nonce);
    if (sc_aead_seal(&d->g, nonce, out, 5, out + 5, n + 1, out + 5 + n + 1)) return 0;
    d->seq++;
    return 5 + total;
}

static int rec_seal(struct dir *d, int fd, const unsigned char *msg, size_t n) {
    static __thread unsigned char out[5 + 4096 + 17];
    size_t k = rec_wrap(d, msg, n, out);
    return k ? wr_all(fd, out, k) : -1;
}

/* The client's Finished (RFC 8446 §4.4.4), checked as a real server checks it: a record under the
 * client handshake key holding an HMAC, keyed by the client finished key, over the transcript up
 * to the server Finished. 1 if it verifies, -1 for anything else. */
static int client_finished(struct srv *s, struct dir *d) {
    unsigned char rec[512], th[HLEN], fkey[HLEN], vd[HLEN], inner;
    size_t n;
    tr_snapshot(&s->tr, th);
    if (dir_set(d, s->c_hs) || rec_open(d, s->fd, rec, sizeof(rec), &n, &inner)) return -1;
    if (inner != 0x16 || n != 4 + HLEN || memcmp(rec, "\x14\x00\x00\x20", 4)) return -1;
    if (xlabel(s->c_hs, "finished", NULL, 0, fkey, HLEN)) return -1;
    if (sc_hmac(SC_SHA256, fkey, HLEN, th, HLEN, vd) != 0) return -1;
    return memcmp(rec + 4, vd, HLEN) ? -1 : 1;
}

/* Sec-WebSocket-Accept (RFC 6455 §1.3): base64 of SHA-1 over the key and the GUID. Computed
 * here, not by tr_ws_accept: the client checks the answer with that function, and a bug in it
 * would agree with itself. */
static int ws_accept(const char *key, char out[29]) {
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char in[96];
    unsigned char h[21] = { 0 };                  /* SHA-1 and a zero byte: 7 groups of 3 */
    int n = snprintf(in, sizeof(in), "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key);
    if (n < 0 || (size_t)n >= sizeof(in) || sc_hash(SC_SHA1, in, (size_t)n, h) != 0) return -1;
    for (int i = 0, o = 0; i < 21; i += 3) {
        unsigned v = ((unsigned)h[i] << 16) | ((unsigned)h[i + 1] << 8) | h[i + 2];
        out[o++] = T[(v >> 18) & 63];
        out[o++] = T[(v >> 12) & 63];
        out[o++] = T[(v >> 6) & 63];
        out[o++] = i < 18 ? T[v & 63] : '=';
    }
    out[28] = '\0';
    return 0;
}

static int app_phase_dirs(struct srv *s, struct dir *cd, struct dir *sd) {
    unsigned char zeros[HLEN] = {0}, empty[HLEN], derived[HLEN], master[HLEN], th[HLEN];
    unsigned char c_ap[HLEN], s_ap[HLEN];
    if (sc_hash(SC_SHA256, zeros, 0, empty) != 0) return -1;
    if (xlabel(s->hs, "derived", empty, HLEN, derived, HLEN) != 0) return -1;
    if (sc_hkdf_extract(SC_SHA256, derived, HLEN, zeros, HLEN, master) != 0) return -1;
    tr_snapshot(&s->tr, th);
    if (xlabel(master, "c ap traffic", th, HLEN, c_ap, HLEN) != 0) return -1;
    if (xlabel(master, "s ap traffic", th, HLEN, s_ap, HLEN) != 0) return -1;

    static __thread unsigned char buf[16384 + 256];
    size_t n;
    unsigned char inner;
    /* A wrong client Finished ends the connection here, before the Upgrade answer. */
    if (client_finished(s, cd) != 1) return -1;
    if (dir_set(cd, c_ap) || dir_set(sd, s_ap)) return -1;

    size_t rn = 0;
    while (!strstr(s->req, "\r\n\r\n")) {
        if (rec_open(cd, s->fd, buf, sizeof(buf), &n, &inner) || inner != 0x17) return -1;
        if (rn + n >= sizeof(s->req)) return -1;
        memcpy(s->req + rn, buf, n);
        rn += n;
        s->req[rn] = '\0';
    }

    char resp[512];
    int k;
    if (s->plan->upg == 1) {
        char key[32] = "", acc[29];
        const char *kp = strstr(s->req, "\r\nSec-WebSocket-Key: ");
        if (!kp) return -1;
        sscanf(kp + 21, "%31[^\r]", key);
        if (ws_accept(key, acc)) return -1;
        k = snprintf(resp, sizeof(resp), "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                     "Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", acc);
        resp[k++] = (char)0x82; resp[k++] = 5;           /* server frame: unmasked */
        memcpy(resp + k, "FIRST", 5); k += 5;
    } else {
        k = snprintf(resp, sizeof(resp), "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n"
                     "Upgrade: websocket\r\n\r\nFIRST");
    }
    if (rec_seal(sd, s->fd, (const unsigned char *)resp, (size_t)k)) return -1;

    /* ws early data (Ed > 0): the client's "hello" came in the request itself, base64url
     * without `=`. */
    if (s->plan->ed_first) {
        s->got_hello = strstr(s->req, "\r\nSec-WebSocket-Protocol: aGVsbG8\r\n") != NULL;
        return 0;
    }
    if (rec_open(cd, s->fd, buf, sizeof(buf), &n, &inner) || inner != 0x17) return -1;
    if (s->plan->upg == 1) {
        /* 0x82, 0x80|5, the mask, "hello" masked. */
        if (n != 11 || buf[0] != 0x82 || buf[1] != (0x80 | 5)) return -1;
        for (int i = 0; i < 5; i++) buf[6 + i] ^= buf[2 + (i & 3)];
        s->got_hello = !memcmp(buf + 6, "hello", 5);
    } else {
        s->got_hello = n == 5 && !memcmp(buf, "hello", 5);
    }
    return 0;
}

static int app_phase(struct srv *s) {
    struct dir *cd = calloc(1, sizeof(*cd)), *sd = calloc(1, sizeof(*sd));
    int rc = cd && sd ? app_phase_dirs(s, cd, sd) : -1;
    if (cd && cd->ready) sc_aead_free(&cd->g);
    if (sd && sd->ready) sc_aead_free(&sd->g);
    free(cd);
    free(sd);
    return rc;
}

static void *server_half(void *arg) {
    struct srv *s = arg;
    const struct plan *pl = s->plan;
    unsigned char ch[4096];
    unsigned char type;
    size_t ch_n = 0;

    s->rc = -1;
    if (rd_rec(s->fd, &type, ch, sizeof(ch), &ch_n) || type != 0x16) return NULL;
    if (pl->hold) s->overlap = hello_meet();
    if (pl->after_peer) s->overlap = peer_wait();
    if (pl->hangup) { s->rc = 0; close(s->fd); s->fd = -1; return NULL; }
    /* ALPN exactly "http/1.1": extension 0x0010 of length 11, list of length 9 (ws and
     * httpupgrade; the other transports send "h2, http/1.1"). All 15 bytes are compared, the
     * name included. */
    static const char H11[] = "\x00\x10\x00\x0b\x00\x09\x08http/1.1";
    s->alpn_h11 = memmem(ch, ch_n, H11, sizeof(H11) - 1) != NULL;
    __atomic_store_n(&g_seen_h11, s->alpn_h11, __ATOMIC_SEQ_CST);

    unsigned char cpub[32], sid[32];
    size_t sid_n = 0;
    if (ch_pick(ch, ch_n, cpub, sid, &sid_n)) return NULL;

    unsigned char spriv[32], spub[32];
    if (xc_x25519_keypair(spriv, spub) != 0) return NULL;

    /* ---- ServerHello ---- */
    unsigned char sh[256];
    size_t m = 0;
    sh[m++] = 0x02; m += 3;                          /* length filled in below */
    sh[m++] = 0x03; sh[m++] = 0x03;
    static const unsigned char HRR[32] = {
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
    };
    if (pl->hrr) memcpy(sh + m, HRR, 32);
    else if (xc_random(sh + m, 32) != 0) return NULL;
    m += 32;
    sh[m++] = (unsigned char)sid_n;
    memcpy(sh + m, sid, sid_n); m += sid_n;
    sh[m++] = SUITE_HI; sh[m++] = SUITE_LO;
    sh[m++] = 0x00;                                  /* compression */
    size_t exts_at = m; m += 2;
    sh[m++] = 0x00; sh[m++] = 0x2b; sh[m++] = 0x00; sh[m++] = 0x02;
    sh[m++] = 0x03; sh[m++] = 0x04;                  /* supported_versions: TLS 1.3 */
    if (pl->hrr) {
        sh[m++] = 0x00; sh[m++] = 0x33; sh[m++] = 0x00; sh[m++] = 0x02;
        sh[m++] = 0x00; sh[m++] = 0x18;
    } else if (pl->keyshare_group) {
        sh[m++] = 0x00; sh[m++] = 0x33; sh[m++] = 0x00; sh[m++] = 0x45;
        sh[m++] = (unsigned char)(pl->keyshare_group >> 8); sh[m++] = (unsigned char)pl->keyshare_group;
        sh[m++] = 0x00; sh[m++] = 0x41; sh[m++] = 0x04;
        if (xc_random(sh + m, 64) != 0) return NULL;
        m += 64;
    } else if (!pl->no_keyshare) {
        sh[m++] = 0x00; sh[m++] = 0x33; sh[m++] = 0x00; sh[m++] = 0x24;
        sh[m++] = 0x00; sh[m++] = 0x1d; sh[m++] = 0x00; sh[m++] = 0x20;
        memcpy(sh + m, spub, 32); m += 32;
    }
    sh[exts_at]     = (unsigned char)((m - exts_at - 2) >> 8);
    sh[exts_at + 1] = (unsigned char)(m - exts_at - 2);
    sh[1] = (unsigned char)((m - 4) >> 16);
    sh[2] = (unsigned char)((m - 4) >> 8);
    sh[3] = (unsigned char)(m - 4);

    unsigned char rec[5 + 256];
    rec[0] = 0x16; rec[1] = 0x03; rec[2] = 0x03;
    rec[3] = (unsigned char)(m >> 8); rec[4] = (unsigned char)m;
    memcpy(rec + 5, sh, m);
    if (wr_all(s->fd, rec, 5 + m)) return NULL;

    if (sc_hash_init(&s->tr, SC_SHA256) != 0) return NULL;
    sc_hash_update(&s->tr, ch, ch_n);
    sc_hash_update(&s->tr, sh, m);

    if (pl->no_keyshare || pl->hrr || pl->keyshare_group) { s->rc = 0; return NULL; }   /* the client stops listening here */

    /* ---- handshake key schedule, RFC 8446 §7.1 ---- */
    unsigned char zeros[HLEN] = {0}, empty[HLEN];
    unsigned char early[HLEN], derived[HLEN], hs[HLEN], ecdhe[32], th[HLEN];
    if (sc_hash(SC_SHA256, zeros, 0, empty) != 0) return NULL;
    if (sc_hkdf_extract(SC_SHA256, NULL, 0, zeros, HLEN, early) != 0) return NULL;
    if (xlabel(early, "derived", empty, HLEN, derived, HLEN) != 0) return NULL;
    if (x25519_shared_ext(spriv, cpub, ecdhe) != 0) return NULL;
    if (sc_hkdf_extract(SC_SHA256, derived, HLEN, ecdhe, 32, hs) != 0) return NULL;
    tr_snapshot(&s->tr, th);
    if (xlabel(hs, "s hs traffic", th, HLEN, s->s_hs, HLEN) != 0) return NULL;
    if (xlabel(hs, "c hs traffic", th, HLEN, s->c_hs, HLEN) != 0) return NULL;
    memcpy(s->hs, hs, HLEN);
    if (xlabel(s->s_hs, "key", NULL, 0, s->key, sizeof(s->key)) != 0) return NULL;
    if (xlabel(s->s_hs, "iv", NULL, 0, s->iv, sizeof(s->iv)) != 0) return NULL;
#if defined(STEER_HAVE_X509WRITE)
    note_secrets(s->hs, s->c_hs, s->s_hs, s->key);
#endif

    /* ---- EncryptedExtensions ---- */
    unsigned char ee[64];
    size_t en = 0;
    ee[en++] = 0x08; en += 3;
    size_t elist_at = en; en += 2;
    if (pl->alpn) {
        size_t pn = strlen(pl->alpn);
        ee[en++] = 0x00; ee[en++] = 0x10;
        ee[en++] = 0x00; ee[en++] = (unsigned char)(3 + pn);
        ee[en++] = 0x00; ee[en++] = (unsigned char)(1 + pn);
        ee[en++] = (unsigned char)pn;
        memcpy(ee + en, pl->alpn, pn); en += pn;
    }
    ee[elist_at]     = (unsigned char)((en - elist_at - 2) >> 8);
    ee[elist_at + 1] = (unsigned char)(en - elist_at - 2);
    ee[1] = 0; ee[2] = (unsigned char)((en - 4) >> 8); ee[3] = (unsigned char)(en - 4);
    if (send_enc(s, ee, en)) return NULL;
    sc_hash_update(&s->tr, ee, en);

#if defined(STEER_HAVE_X509WRITE)
    /* ---- Certificate and CertificateVerify with a real chain (security=tls path) ---- */
    if (pl->chain) {
        const struct leaf *l = &g_leaf[pl->chain];
        unsigned char msg[3072];
        size_t mn = cert_msg(l, pl->dc, pl->send_root, msg, sizeof(msg));
        if (mn && mn < sizeof msg && pl->cert_trail) {
            msg[mn++] = 0x00;
            msg[1] = (unsigned char)((mn - 4) >> 16); msg[2] = (unsigned char)((mn - 4) >> 8); msg[3] = (unsigned char)(mn - 4);
        }
        if (mn && pl->compress) mn = compressed_msg(pl->compress, pl->compress_junk, msg, mn, sizeof(msg));
        if (!mn) return NULL;
        if (pl->compress_short) {
            static const unsigned char cut[5] = { 0x19, 0x00, 0x00, 0x01, 0x00 };
            if (send_enc(s, cut, sizeof cut)) return NULL;
            sc_hash_update(&s->tr, cut, sizeof cut);
        }
        if (pl->compress_empty) {
            static const unsigned char none[1];
            unsigned char e[32];
            size_t zn = stored_stream(pl->compress_empty, none, 0, e + 12);
            size_t body = 8 + zn;
            e[0] = 0x19; e[1] = 0; e[2] = 0; e[3] = (unsigned char)body;
            e[4] = 0; e[5] = (unsigned char)pl->compress_empty;
            e[6] = 0; e[7] = 0; e[8] = 0;
            e[9] = 0; e[10] = 0; e[11] = (unsigned char)zn;
            if (send_enc(s, e, 12 + zn)) return NULL;
            sc_hash_update(&s->tr, e, 12 + zn);
        }
        if (send_enc(s, msg, mn)) return NULL;
        sc_hash_update(&s->tr, msg, mn);
        if (pl->cert_twice) {
            if (send_enc(s, msg, mn)) return NULL;
            sc_hash_update(&s->tr, msg, mn);
        }

        if (!pl->no_cv) {
            /* The hash is taken AFTER Certificate and BEFORE CertificateVerify: what the
             * server signs per RFC 8446 §4.4.3, and where the client takes its own (tls13.c,
             * message 0x0F). One step off here would give "bad signature" and look like a bug
             * in the engine. */
            unsigned char th_cv[HLEN];
            tr_snapshot(&s->tr, th_cv);
            size_t cn = cv_msg(l, th_cv, pl, msg, sizeof(msg));
            if (!cn) return NULL;
            if (send_enc(s, msg, cn)) return NULL;
            sc_hash_update(&s->tr, msg, cn);
            if (pl->cv_twice) {
                if (send_enc(s, msg, cn)) return NULL;
                sc_hash_update(&s->tr, msg, cn);
            }
        }
        goto finished;
    }
#endif

    /* ---- Certificate or its compressed form ---- */
    if (pl->cert == 2) {
        /* CompressedCertificate: the client fails on it at once, without waiting for
         * Finished; a compressed certificate means we were handed to the camouflage site. */
        unsigned char cc[16] = { 0x19, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00,
                                 0x04, 0x01, 0x02, 0x03 };
        s->rc = send_enc(s, cc, 12) ? -1 : 0;
        return NULL;
    }
    if (pl->reality_ok) {
        /* Reality temporary certificate: an Ed25519 key (any 32 bytes: nobody checks it as a
         * key) and the signature field = HMAC-SHA512(authkey, key), where authkey is
         * HKDF-SHA256 of ECDH(server static key, client ephemeral key) with salt Random[0..20)
         * and info "REALITY" (Xray's reality.go; the client half is reality.c). The DER is just
         * what cert_reality_check reads:
         * SEQUENCE { tbs with an Ed25519 SPKI, algid, BIT STRING }. */
        unsigned char shared[32], authkey[32], epub[32], sig[64];
        if (x25519_shared_ext(g_rs_priv, cpub, shared) != 0) return NULL;
        if (sc_hkdf(SC_SHA256, ch + 6, 20, shared, 32, "REALITY", 7, authkey, 32) != 0) return NULL;
        for (int i = 0; i < 32; i++) epub[i] = (unsigned char)(0x40 + i);
        if (sc_hmac(SC_SHA512, authkey, 32, epub, 32, sig) != 0) return NULL;
        static const unsigned char spki[] = { 0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70,
                                              0x03, 0x21, 0x00 };
        unsigned char der[128];
        size_t dn = 0;
        der[dn++] = 0x30; der[dn++] = 0x78;                  /* Certificate, 120 bytes */
        der[dn++] = 0x30; der[dn++] = 0x2C;                  /* tbsCertificate: SPKI only */
        memcpy(der + dn, spki, sizeof(spki)); dn += sizeof(spki);
        memcpy(der + dn, epub, 32); dn += 32;
        static const unsigned char alg[] = { 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70 };
        memcpy(der + dn, alg, sizeof(alg)); dn += sizeof(alg);
        der[dn++] = 0x03; der[dn++] = 0x41; der[dn++] = 0x00;
        memcpy(der + dn, sig, 64); dn += 64;
        unsigned char cm[256];
        size_t cn = 0, body = 1 + 3 + 3 + dn + 2;
        cm[cn++] = 0x0B;
        cm[cn++] = 0; cm[cn++] = (unsigned char)(body >> 8); cm[cn++] = (unsigned char)body;
        cm[cn++] = 0;                                        /* certificate_request_context */
        size_t list = 3 + dn + 2;
        cm[cn++] = 0; cm[cn++] = (unsigned char)(list >> 8); cm[cn++] = (unsigned char)list;
        cm[cn++] = 0; cm[cn++] = (unsigned char)(dn >> 8); cm[cn++] = (unsigned char)dn;
        memcpy(cm + cn, der, dn); cn += dn;
        cm[cn++] = 0; cm[cn++] = 0;                          /* no entry extensions */
        if (send_enc(s, cm, cn)) return NULL;
        sc_hash_update(&s->tr, cm, cn);
    }
    if (pl->cert == 1) {
        /* The body deliberately parses as no certificate at all: what is tested is not X.509
         * parsing but how a failed check is closed. */
        unsigned char cr[40];
        cr[0] = 0x0B; cr[1] = 0; cr[2] = 0; cr[3] = 32;
        memset(cr + 4, 0xA5, 32);
        if (send_enc(s, cr, 36)) return NULL;
        sc_hash_update(&s->tr, cr, 36);
    }

    /* ---- Finished ---- */
#if defined(STEER_HAVE_X509WRITE)
finished:;
#endif
    unsigned char fkey[HLEN], hash[HLEN], vd[HLEN];
    tr_snapshot(&s->tr, hash);
    if (xlabel(s->s_hs, "finished", NULL, 0, fkey, HLEN) != 0) return NULL;
    if (sc_hmac(SC_SHA256, fkey, HLEN, hash, HLEN, vd) != 0) return NULL;
    if (pl->bad_finished) vd[0] ^= 0xFF;
    unsigned char fin[4 + HLEN];
    fin[0] = 0x14; fin[1] = 0; fin[2] = 0; fin[3] = (unsigned char)HLEN;
    memcpy(fin + 4, vd, HLEN);
    if (send_enc(s, fin, sizeof(fin))) return NULL;
    sc_hash_update(&s->tr, fin, sizeof(fin));
    s->fin_sent = 1;
    if (pl->tell_peer) {
        struct dir *d = calloc(1, sizeof(*d));
        s->overlap = d && client_finished(s, d) == 1;
        if (d && d->ready) sc_aead_free(&d->g);
        free(d);
        peer_tell();
    }

    if (pl->upg) { s->rc = app_phase(s); return NULL; }
    s->rc = 0;
    return NULL;
}

/* ---- TCP setup seam ------------------------------------------------------------ */

static int g_give_fd = -1;
static int g_fm_relay;
static struct fmrelay g_relay;

static int fake_dial(const char *host, uint16_t port, int timeout_s) {
    (void)host; (void)port;
    int fd = g_give_fd;
    g_give_fd = -1;
    if (fd < 0) return TR_ECONNECT;
    if (g_fm_relay) fd = fmrelay_wrap(&g_relay, fd);
    /* What tcp_connect does with the winning socket: read and write timeouts. Without them a
     * bug in the server half would hang the test instead of failing it. */
    sock_ready(fd, timeout_s);
    return fd;
}

static int g_give2[2] = { -1, -1 };
static char g_dialed[2][64];
static int g_dial_n;

static int fake_dial2(const char *host, uint16_t port, int timeout_s) {
    (void)port;
    if (g_dial_n >= 2) return TR_ECONNECT;
    int i = g_dial_n++;
    snprintf(g_dialed[i], sizeof g_dialed[i], "%s", host);
    int fd = g_give2[i];
    g_give2[i] = -1;
    if (fd < 0) return TR_ECONNECT;
    sock_ready(fd, timeout_s);
    return fd;
}

/* A Reality node over tcp. Reality, not security=tls: the proof here is the temporary
 * certificate's signature over the authkey, so failing the check needs no root store and no
 * X.509 chain, and the ECERT path is reachable without issuing certificates. The pbk is
 * arbitrary: X25519 multiplies any 32 bytes, and the server for this pair is fake anyway. */
static void node_reality(struct vless_node *n, const char *type) {
    memset(n, 0, sizeof(*n));
    snprintf(n->host, sizeof(n->host), "%s", "node.invalid");
    n->port = 443;
    snprintf(n->uuid, sizeof(n->uuid), "%s", "00000000-0000-0000-0000-000000000001");
    snprintf(n->type, sizeof(n->type), "%s", type);
    snprintf(n->security, sizeof(n->security), "%s", "reality");
    snprintf(n->sni, sizeof(n->sni), "%s", "www.example.com");
    snprintf(n->fp, sizeof(n->fp), "%s", "chrome");
    snprintf(n->pbk, sizeof(n->pbk), "%s", "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA");
    snprintf(n->sid, sizeof(n->sid), "%s", "0123456789abcdef");
}

#if defined(STEER_HAVE_X509WRITE)
/* A security=tls node: the proof is the chain to a root and the name, nothing else. pbk and sid
 * are left empty on purpose: plain TLS has none, and reality_build_hello does not read them with
 * .plain = 1 (trsec.c). The name is checked against sni, not host, so sni is the name the good
 * leaf is issued for. */
static void node_tls(struct vless_node *n, const char *type) {
    memset(n, 0, sizeof(*n));
    snprintf(n->host, sizeof(n->host), "%s", "node.invalid");
    n->port = 443;
    snprintf(n->uuid, sizeof(n->uuid), "%s", "00000000-0000-0000-0000-000000000001");
    snprintf(n->type, sizeof(n->type), "%s", type);
    snprintf(n->security, sizeof(n->security), "%s", "tls");
    snprintf(n->sni, sizeof(n->sni), "%s", TLS_SNI);
    snprintf(n->fp, sizeof(n->fp), "%s", "chrome");
}
#endif

#if defined(STEER_HAVE_X509WRITE)
enum hy2_mock_mode {
    HY2_MOCK_NO_CERT = 1,
    HY2_MOCK_NO_CV = 2,
    HY2_MOCK_STATUS_200_FAKE_233 = 3,
    HY2_MOCK_OOO_SPLIT_233_OK = 4,
};

struct hy2_mock {
    int fd;
    enum hy2_mock_mode mode;
    int got_1rtt;
};

static size_t hy2_put_varint(unsigned char *p, uint64_t v) {
    if (v <= 63) { p[0] = (unsigned char)v; return 1; }
    if (v <= 16383) {
        p[0] = (unsigned char)(0x40u | (v >> 8));
        p[1] = (unsigned char)v;
        return 2;
    }
    p[0] = (unsigned char)(0x80u | (v >> 24));
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)v;
    return 4;
}

static int hy2_seal_long(int fd, int ptype, const unsigned char dcid[8], const unsigned char scid[8],
                         const unsigned char secret[32], uint64_t pn,
                         const unsigned char *frames, size_t flen) {
    unsigned char key[16], iv[12], hp[16], pkt[1500];
    if (xlabel(secret, "quic key", NULL, 0, key, 16) != 0 ||
        xlabel(secret, "quic iv",  NULL, 0, iv,  12) != 0 ||
        xlabel(secret, "quic hp",  NULL, 0, hp,  16) != 0)
        return -1;
    size_t o = 0;
    pkt[o++] = (unsigned char)(0xC0u | ((ptype & 3) << 4) | 0x01u);
    pkt[o++] = 0; pkt[o++] = 0; pkt[o++] = 0; pkt[o++] = 1;
    pkt[o++] = 8; memcpy(pkt + o, dcid, 8); o += 8;
    pkt[o++] = 8; memcpy(pkt + o, scid, 8); o += 8;
    if (ptype == 0) pkt[o++] = 0;
    size_t pay_len = flen < 4 ? 4 : flen;
    size_t rem_len = 2 + pay_len + 16;
    pkt[o++] = (unsigned char)(0x40u | (rem_len >> 8));
    pkt[o++] = (unsigned char)rem_len;
    size_t pn_off = o;
    pkt[o++] = (unsigned char)(pn >> 8);
    pkt[o++] = (unsigned char)pn;
    size_t hdr_len = o;
    memcpy(pkt + hdr_len, frames, flen);
    if (pay_len > flen) memset(pkt + hdr_len + flen, 0, pay_len - flen);

    unsigned char nonce[12];
    memcpy(nonce, iv, 12);
    for (int i = 0; i < 8; i++) nonce[11 - i] ^= (unsigned char)(pn >> (8 * i));
    struct sc_aead aead;
    if (sc_aead_setkey(&aead, SC_AES128_GCM, key) != 0) return -1;
    int rc = sc_aead_seal(&aead, nonce, pkt, hdr_len, pkt + hdr_len, pay_len, pkt + hdr_len + pay_len);
    sc_aead_free(&aead);
    if (rc != 0) return -1;

    unsigned char blk[16];
    if (sc_aes_block(hp, 16, 0, pkt + pn_off + 4, blk) != 0) return -1;
    pkt[0] ^= (unsigned char)(blk[0] & 0x0Fu);
    pkt[pn_off]     ^= blk[1];
    pkt[pn_off + 1] ^= blk[2];
    return send(fd, pkt, hdr_len + pay_len + 16, MSG_NOSIGNAL) == (ssize_t)(hdr_len + pay_len + 16) ? 0 : -1;
}

static int hy2_seal_1rtt(int fd, const unsigned char dcid[8], const unsigned char secret[32],
                         uint64_t pn, const unsigned char *frames, size_t flen) {
    unsigned char key[16], iv[12], hp[16], pkt[1500];
    if (xlabel(secret, "quic key", NULL, 0, key, 16) != 0 ||
        xlabel(secret, "quic iv",  NULL, 0, iv,  12) != 0 ||
        xlabel(secret, "quic hp",  NULL, 0, hp,  16) != 0)
        return -1;
    size_t o = 0;
    pkt[o++] = 0x41u;
    memcpy(pkt + o, dcid, 8); o += 8;
    size_t pn_off = o;
    pkt[o++] = (unsigned char)(pn >> 8);
    pkt[o++] = (unsigned char)pn;
    size_t hdr_len = o;
    size_t pay_len = flen < 4 ? 4 : flen;
    memcpy(pkt + hdr_len, frames, flen);
    if (pay_len > flen) memset(pkt + hdr_len + flen, 0, pay_len - flen);

    unsigned char nonce[12];
    memcpy(nonce, iv, 12);
    for (int i = 0; i < 8; i++) nonce[11 - i] ^= (unsigned char)(pn >> (8 * i));
    struct sc_aead aead;
    if (sc_aead_setkey(&aead, SC_AES128_GCM, key) != 0) return -1;
    int rc = sc_aead_seal(&aead, nonce, pkt, hdr_len, pkt + hdr_len, pay_len, pkt + hdr_len + pay_len);
    sc_aead_free(&aead);
    if (rc != 0) return -1;

    unsigned char blk[16];
    if (sc_aes_block(hp, 16, 0, pkt + pn_off + 4, blk) != 0) return -1;
    pkt[0] ^= (unsigned char)(blk[0] & 0x1Fu);
    pkt[pn_off]     ^= blk[1];
    pkt[pn_off + 1] ^= blk[2];
    return send(fd, pkt, hdr_len + pay_len + 16, MSG_NOSIGNAL) == (ssize_t)(hdr_len + pay_len + 16) ? 0 : -1;
}

static void *hy2_mock_srv(void *arg) {
    struct hy2_mock *m = arg;
    struct pollfd pfd = { .fd = m->fd, .events = POLLIN, .revents = 0 };
    if (poll(&pfd, 1, 2000) <= 0) return NULL;
    unsigned char dgram[2048];
    ssize_t r = recv(m->fd, dgram, sizeof(dgram), 0);
    if (r < 64) return NULL;

    unsigned char init_dcid[8], cli_scid[8];
    memcpy(init_dcid, dgram + 6, 8);
    memcpy(cli_scid, dgram + 15, 8);

    static const unsigned char quic_v1_salt[20] = {
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
        0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
    };
    unsigned char init_sec[32], c_in[32], s_in[32];
    sc_hkdf_extract(SC_SHA256, quic_v1_salt, 20, init_dcid, 8, init_sec);
    xlabel(init_sec, "client in", NULL, 0, c_in, 32);
    xlabel(init_sec, "server in", NULL, 0, s_in, 32);

    unsigned char c_key[16], c_iv[12], c_hp[16], blk[16];
    xlabel(c_in, "quic key", NULL, 0, c_key, 16);
    xlabel(c_in, "quic iv",  NULL, 0, c_iv,  12);
    xlabel(c_in, "quic hp",  NULL, 0, c_hp,  16);

    size_t rem_len = ((size_t)(dgram[24] & 0x3Fu) << 8) | dgram[25];
    size_t pn_off = 26;
    if (pn_off + rem_len > (size_t)r || rem_len < 20) return NULL;
    sc_aes_block(c_hp, 16, 0, dgram + pn_off + 4, blk);
    dgram[0] ^= (unsigned char)(blk[0] & 0x0Fu);
    dgram[pn_off]     ^= blk[1];
    dgram[pn_off + 1] ^= blk[2];
    uint64_t pn = ((uint64_t)dgram[pn_off] << 8) | dgram[pn_off + 1];
    size_t pay_len = rem_len - 2 - 16;

    unsigned char nonce[12];
    memcpy(nonce, c_iv, 12);
    for (int i = 0; i < 8; i++) nonce[11 - i] ^= (unsigned char)(pn >> (8 * i));
    struct sc_aead c_aead;
    sc_aead_setkey(&c_aead, SC_AES128_GCM, c_key);
    int orc = sc_aead_open(&c_aead, nonce, dgram, 28, dgram + 28, pay_len, dgram + 28 + pay_len);
    sc_aead_free(&c_aead);
    if (orc != 0) return NULL;

    /* Extract CRYPTO frame at dgram + 28: [0x06][0x00][varint ch_len][ClientHello] */
    const unsigned char *fp = dgram + 28;
    if (fp[0] != 0x06 || fp[1] != 0x00) return NULL;
    size_t vlen = 1u << (fp[2] >> 6);
    size_t ch_len = fp[2] & 0x3Fu;
    for (size_t i = 1; i < vlen; i++) ch_len = (ch_len << 8) | fp[2 + i];
    const unsigned char *ch = fp + 2 + vlen;
    unsigned char cpub[32], sid[32];
    size_t sid_n = 0;
    if (ch_pick(ch, ch_len, cpub, sid, &sid_n) != 0) return NULL;

    unsigned char spriv[32], spub[32];
    if (xc_x25519_keypair(spriv, spub) != 0) return NULL;

    /* Build ServerHello (suite 0x1301) */
    unsigned char sh[160];
    size_t mlen = 0;
    sh[mlen++] = 0x02; mlen += 3;
    sh[mlen++] = 0x03; sh[mlen++] = 0x03;
    memset(sh + mlen, 0x22, 32); mlen += 32;
    sh[mlen++] = (unsigned char)sid_n;
    memcpy(sh + mlen, sid, sid_n); mlen += sid_n;
    sh[mlen++] = 0x13; sh[mlen++] = 0x01;
    sh[mlen++] = 0x00;
    size_t exts_at = mlen; mlen += 2;
    sh[mlen++] = 0x00; sh[mlen++] = 0x2b; sh[mlen++] = 0x00; sh[mlen++] = 0x02;
    sh[mlen++] = 0x03; sh[mlen++] = 0x04;
    sh[mlen++] = 0x00; sh[mlen++] = 0x33; sh[mlen++] = 0x00; sh[mlen++] = 0x24;
    sh[mlen++] = 0x00; sh[mlen++] = 0x1d; sh[mlen++] = 0x00; sh[mlen++] = 0x20;
    memcpy(sh + mlen, spub, 32); mlen += 32;
    sh[exts_at]     = (unsigned char)((mlen - exts_at - 2) >> 8);
    sh[exts_at + 1] = (unsigned char)(mlen - exts_at - 2);
    sh[1] = 0; sh[2] = (unsigned char)((mlen - 4) >> 8); sh[3] = (unsigned char)(mlen - 4);

    static const unsigned char srv_scid[8] = { 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98 };
    unsigned char sh_cf[180];
    size_t scfo = 0;
    sh_cf[scfo++] = 0x06;
    sh_cf[scfo++] = 0x00;
    scfo += hy2_put_varint(sh_cf + scfo, mlen);
    memcpy(sh_cf + scfo, sh, mlen); scfo += mlen;
    if (hy2_seal_long(m->fd, 0, cli_scid, srv_scid, s_in, 0, sh_cf, scfo) != 0) return NULL;

    struct sc_hash_ctx tr;
    sc_hash_init(&tr, SC_SHA256);
    sc_hash_update(&tr, ch, ch_len);
    sc_hash_update(&tr, sh, mlen);

    unsigned char zeros[32] = {0}, empty[32], early[32], derived[32], hs_sec[32], ecdhe[32], sh_th[32];
    unsigned char c_hs[32], s_hs[32];
    sc_hash(SC_SHA256, NULL, 0, empty);
    sc_hkdf_extract(SC_SHA256, zeros, 32, zeros, 32, early);
    xlabel(early, "derived", empty, 32, derived, 32);
    x25519_shared_ext(spriv, cpub, ecdhe);
    sc_hkdf_extract(SC_SHA256, derived, 32, ecdhe, 32, hs_sec);
    tr_snapshot(&tr, sh_th);
    xlabel(hs_sec, "c hs traffic", sh_th, 32, c_hs, 32);
    xlabel(hs_sec, "s hs traffic", sh_th, 32, s_hs, 32);

    /* Build Handshake flight in hs_buf */
    unsigned char hs_buf[3072];
    size_t hlen = 0;
    /* EncryptedExtensions: ALPN "h3" (0x0010) + empty quic_transport_parameters (0x0039) */
    static const unsigned char ee[19] = {
        0x08, 0x00, 0x00, 15,
        0x00, 13,
        0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '3',
        0x00, 0x39, 0x00, 0x00
    };
    memcpy(hs_buf + hlen, ee, sizeof(ee)); hlen += sizeof(ee);
    sc_hash_update(&tr, ee, sizeof(ee));

    if (m->mode != HY2_MOCK_NO_CERT) {
        const struct leaf *l = &g_leaf[LEAF_OK];
        size_t cmn = cert_msg(l, 0, 0, hs_buf + hlen, sizeof(hs_buf) - hlen);
        sc_hash_update(&tr, hs_buf + hlen, cmn);
        hlen += cmn;
        if (m->mode != HY2_MOCK_NO_CV) {
            unsigned char cert_th[32];
            tr_snapshot(&tr, cert_th);
            struct plan dummy_pl = {0};
            size_t cvn = cv_msg(l, cert_th, &dummy_pl, hs_buf + hlen, sizeof(hs_buf) - hlen);
            sc_hash_update(&tr, hs_buf + hlen, cvn);
            hlen += cvn;
        }
    }

    unsigned char fin_th[32], fk[32], vd[32];
    tr_snapshot(&tr, fin_th);
    xlabel(s_hs, "finished", NULL, 0, fk, 32);
    sc_hmac(SC_SHA256, fk, 32, fin_th, 32, vd);
    hs_buf[hlen++] = 20; hs_buf[hlen++] = 0; hs_buf[hlen++] = 0; hs_buf[hlen++] = 32;
    memcpy(hs_buf + hlen, vd, 32);
    sc_hash_update(&tr, hs_buf + hlen - 4, 36);
    hlen += 32;

    unsigned char sf_th[32], d_sec[32], master[32], s_ap[32];
    tr_snapshot(&tr, sf_th);
    sc_hash_free(&tr);
    xlabel(hs_sec, "derived", empty, 32, d_sec, 32);
    sc_hkdf_extract(SC_SHA256, d_sec, 32, zeros, 32, master);
    xlabel(master, "s ap traffic", sf_th, 32, s_ap, 32);

    if (m->mode == HY2_MOCK_STATUS_200_FAKE_233 || m->mode == HY2_MOCK_OOO_SPLIT_233_OK) {
        /* Send Handshake CRYPTO frames out-of-order: second half [half..hlen) first, then [0..half) */
        size_t half = hlen / 2;
        unsigned char f_hi[2048], f_lo[2048];
        size_t o_hi = 0, o_lo = 0;
        f_hi[o_hi++] = 0x06;
        o_hi += hy2_put_varint(f_hi + o_hi, half);
        o_hi += hy2_put_varint(f_hi + o_hi, hlen - half);
        memcpy(f_hi + o_hi, hs_buf + half, hlen - half);
        o_hi += hlen - half;
        hy2_seal_long(m->fd, 2, cli_scid, srv_scid, s_hs, 0, f_hi, o_hi);

        f_lo[o_lo++] = 0x06;
        o_lo += hy2_put_varint(f_lo + o_lo, 0);
        o_lo += hy2_put_varint(f_lo + o_lo, half);
        memcpy(f_lo + o_lo, hs_buf, half);
        o_lo += half;
        hy2_seal_long(m->fd, 2, cli_scid, srv_scid, s_hs, 1, f_lo, o_lo);
    } else {
        unsigned char f_all[2048];
        size_t o_all = 0;
        f_all[o_all++] = 0x06;
        o_all += hy2_put_varint(f_all + o_all, 0);
        o_all += hy2_put_varint(f_all + o_all, hlen);
        memcpy(f_all + o_all, hs_buf, hlen);
        o_all += hlen;
        hy2_seal_long(m->fd, 2, cli_scid, srv_scid, s_hs, 0, f_all, o_all);
    }

    /* Wait for client Finished + 1-RTT POST /auth (skip Initial/Handshake ACK & Finished packets) */
    for (int i = 0; i < 16; i++) {
        if (poll(&pfd, 1, 200) <= 0) break;
        ssize_t nr = recv(m->fd, dgram, sizeof(dgram), 0);
        if (nr <= 0) break;
        if ((dgram[0] & 0x80) == 0) {
            m->got_1rtt = 1;
            break;
        }
    }
    if (!m->got_1rtt) return NULL;

    if (m->mode == HY2_MOCK_STATUS_200_FAKE_233) {
        /* Stream 0 HTTP/3 HEADERS with :status = 200 (0xD9) AND x-pad: 233 (contains 0x03 '2' '3' '3') */
        static const unsigned char h3_bad[] = {
            0x01, 0x0D,             /* HEADERS frame, len = 13 */
            0x00, 0x00,             /* QPACK prefix: RIC=0, DeltaBase=0 */
            0xD9,                   /* Indexed static 25 -> :status = 200 */
            0x25, 'x', '-', 'p', 'a', 'd',
            0x03, '2', '3', '3'     /* Literal value "233" for header x-pad */
        };
        unsigned char sf[64];
        size_t sfo = 0;
        sf[sfo++] = 0x0B; /* STREAM(sid=0, off=0, len, fin=1) */
        sf[sfo++] = 0x00;
        sf[sfo++] = (unsigned char)sizeof(h3_bad);
        memcpy(sf + sfo, h3_bad, sizeof(h3_bad));
        sfo += sizeof(h3_bad);
        hy2_seal_1rtt(m->fd, cli_scid, s_ap, 0, sf, sfo);
    } else if (m->mode == HY2_MOCK_OOO_SPLIT_233_OK) {
        /* Valid HTTP/3 HEADERS with :status = 233 split across two out-of-order STREAM frames */
        static const unsigned char h3_ok[10] = {
            0x01, 0x08,             /* HEADERS frame, len = 8 */
            0x00, 0x00,             /* QPACK prefix: RIC=0, DeltaBase=0 */
            0x5F, 0x09,             /* Literal with static name index 24 (:status) */
            0x03, '2', '3', '3'     /* Value "233" */
        };
        unsigned char sf_hi[32], sf_lo[32];
        size_t o1 = 0, o2 = 0;
        /* Frame 1: offset = 4, len = 6, fin = 1 */
        sf_hi[o1++] = 0x0F; /* STREAM(OFF=1, LEN=1, FIN=1) */
        sf_hi[o1++] = 0x00; /* sid = 0 */
        sf_hi[o1++] = 0x04; /* off = 4 */
        sf_hi[o1++] = 0x06; /* len = 6 */
        memcpy(sf_hi + o1, h3_ok + 4, 6);
        o1 += 6;
        hy2_seal_1rtt(m->fd, cli_scid, s_ap, 0, sf_hi, o1);

        /* Frame 2: offset = 0, len = 4, fin = 0 */
        sf_lo[o2++] = 0x0A; /* STREAM(OFF=0, LEN=1, FIN=0) */
        sf_lo[o2++] = 0x00; /* sid = 0 */
        sf_lo[o2++] = 0x04; /* len = 4 */
        memcpy(sf_lo + o2, h3_ok, 4);
        o2 += 4;
        hy2_seal_1rtt(m->fd, cli_scid, s_ap, 1, sf_lo, o2);
    }
    return NULL;
}

static int run_hy2_mock(enum hy2_mock_mode mode, int *got_1rtt) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) return -100;
    struct hy2_mock m = { .fd = sv[1], .mode = mode, .got_1rtt = 0 };
    pthread_t th;
    if (pthread_create(&th, NULL, hy2_mock_srv, &m) != 0) {
        close(sv[0]); close(sv[1]);
        return -101;
    }
    struct vless_node hyn;
    memset(&hyn, 0, sizeof(hyn));
    snprintf(hyn.proto, sizeof(hyn.proto), "%s", "hy2");
    snprintf(hyn.host, sizeof(hyn.host), "%s", "node.invalid");
    hyn.port = 8443;
    snprintf(hyn.uuid, sizeof(hyn.uuid), "%s", "hy2-secret");
    snprintf(hyn.type, sizeof(hyn.type), "%s", "quic");
    snprintf(hyn.security, sizeof(hyn.security), "%s", "tls");
    snprintf(hyn.sni, sizeof(hyn.sni), "%s", TLS_SNI);

    g_give_fd = sv[0];
    g_tcp_dial = fake_dial;
    struct transport c;
    int rc = vless_connect(&hyn, &c, 2);
    g_tcp_dial = NULL;
    if (rc == 0) transport_close(&c);
    pthread_join(th, NULL);
    close(sv[1]);
    if (got_1rtt) *got_1rtt = m.got_1rtt;
    return rc;
}
static int hy2_get_varint(const unsigned char *p, size_t len, uint64_t *val, size_t *consumed) {
    if (len == 0) return -1;
    unsigned int pfx = p[0] >> 6;
    size_t vlen = 1u << pfx;
    if (len < vlen) return -1;
    uint64_t v = p[0] & 0x3Fu;
    for (size_t i = 1; i < vlen; i++) v = (v << 8) | p[i];
    *val = v;
    *consumed = vlen;
    return 0;
}

static int hy2_open_1rtt(unsigned char *dgram, size_t dlen, const unsigned char secret[32],
                         uint64_t *out_pn, const unsigned char **out_frames, size_t *out_flen) {
    if (dlen < 1 + 8 + 2 + 16 || (dgram[0] & 0x80) != 0) return -1;
    unsigned char key[16], iv[12], hp[16], blk[16];
    if (xlabel(secret, "quic key", NULL, 0, key, 16) != 0 ||
        xlabel(secret, "quic iv",  NULL, 0, iv,  12) != 0 ||
        xlabel(secret, "quic hp",  NULL, 0, hp,  16) != 0)
        return -1;
    size_t pn_off = 9;
    if (pn_off + 20 > dlen) return -1;
    if (sc_aes_block(hp, 16, 0, dgram + pn_off + 4, blk) != 0) return -1;
    dgram[0] ^= (unsigned char)(blk[0] & 0x1Fu);
    size_t pn_len = (dgram[0] & 0x03u) + 1;
    for (size_t i = 0; i < pn_len; i++) dgram[pn_off + i] ^= blk[1 + i];
    uint64_t pn = 0;
    for (size_t i = 0; i < pn_len; i++) pn = (pn << 8) | dgram[pn_off + i];
    size_t hdr_len = pn_off + pn_len;
    if (dlen < hdr_len + 16) return -1;
    size_t pay_len = dlen - hdr_len - 16;

    unsigned char nonce[12];
    memcpy(nonce, iv, 12);
    for (int i = 0; i < 8; i++) nonce[11 - i] ^= (unsigned char)(pn >> (8 * i));
    struct sc_aead aead;
    if (sc_aead_setkey(&aead, SC_AES128_GCM, key) != 0) return -1;
    int rc = sc_aead_open(&aead, nonce, dgram, hdr_len, dgram + hdr_len, pay_len, dgram + hdr_len + pay_len);
    sc_aead_free(&aead);
    if (rc != 0) return -1;
    *out_pn = pn;
    *out_frames = dgram + hdr_len;
    *out_flen = pay_len;
    return 0;
}

static int hy2_open_long(unsigned char *dgram, size_t dlen, const unsigned char secret[32],
                         uint64_t *out_pn, const unsigned char **out_frames, size_t *out_flen) {
    if (dlen < 30 || (dgram[0] & 0x80) == 0) return -1;
    unsigned char key[16], iv[12], hp[16], blk[16];
    if (xlabel(secret, "quic key", NULL, 0, key, 16) != 0 ||
        xlabel(secret, "quic iv",  NULL, 0, iv,  12) != 0 ||
        xlabel(secret, "quic hp",  NULL, 0, hp,  16) != 0)
        return -1;
    int ptype = (dgram[0] >> 4) & 0x03;
    size_t pos = 5;
    size_t dcid_len = dgram[pos++];
    pos += dcid_len;
    size_t scid_len = dgram[pos++];
    pos += scid_len;
    if (ptype == 0) {
        uint64_t tok_len = 0; size_t c = 0;
        if (hy2_get_varint(dgram + pos, dlen - pos, &tok_len, &c) != 0) return -1;
        pos += c + (size_t)tok_len;
    }
    uint64_t rem_len = 0; size_t c = 0;
    if (hy2_get_varint(dgram + pos, dlen - pos, &rem_len, &c) != 0) return -1;
    size_t pn_off = pos + c;
    if (pn_off + rem_len > dlen || rem_len < 20) return -1;
    if (sc_aes_block(hp, 16, 0, dgram + pn_off + 4, blk) != 0) return -1;
    dgram[0] ^= (unsigned char)(blk[0] & 0x0Fu);
    size_t pn_len = (dgram[0] & 0x03u) + 1;
    for (size_t i = 0; i < pn_len; i++) dgram[pn_off + i] ^= blk[1 + i];
    uint64_t pn = 0;
    for (size_t i = 0; i < pn_len; i++) pn = (pn << 8) | dgram[pn_off + i];
    size_t hdr_len = pn_off + pn_len;
    size_t pay_len = (size_t)rem_len - pn_len - 16;

    unsigned char nonce[12];
    memcpy(nonce, iv, 12);
    for (int i = 0; i < 8; i++) nonce[11 - i] ^= (unsigned char)(pn >> (8 * i));
    struct sc_aead aead;
    if (sc_aead_setkey(&aead, SC_AES128_GCM, key) != 0) return -1;
    int rc = sc_aead_open(&aead, nonce, dgram, hdr_len, dgram + hdr_len, pay_len, dgram + hdr_len + pay_len);
    sc_aead_free(&aead);
    if (rc != 0) return -1;
    *out_pn = pn;
    *out_frames = dgram + hdr_len;
    *out_flen = pay_len;
    return 0;
}

static int hy2_handshake_srv(int fd, uint64_t init_max_data, uint64_t init_max_s4_data,
                             unsigned char cli_scid[8], unsigned char c_ap[32], unsigned char s_ap[32],
                             uint64_t *srv_1rtt_pn) {
    struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
    if (poll(&pfd, 1, 2000) <= 0) return -1;
    unsigned char dgram[2048];
    ssize_t r = recv(fd, dgram, sizeof(dgram), 0);
    if (r < 64) return -1;

    unsigned char init_dcid[8];
    memcpy(init_dcid, dgram + 6, 8);
    memcpy(cli_scid, dgram + 15, 8);

    static const unsigned char quic_v1_salt[20] = {
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
        0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
    };
    unsigned char init_sec[32], c_in[32], s_in[32];
    sc_hkdf_extract(SC_SHA256, quic_v1_salt, 20, init_dcid, 8, init_sec);
    xlabel(init_sec, "client in", NULL, 0, c_in, 32);
    xlabel(init_sec, "server in", NULL, 0, s_in, 32);

    uint64_t pn = 0;
    const unsigned char *fp = NULL;
    size_t pay_len = 0;
    if (hy2_open_long(dgram, (size_t)r, c_in, &pn, &fp, &pay_len) != 0) return -1;
    if (pay_len < 4 || fp[0] != 0x06 || fp[1] != 0x00) return -1;
    uint64_t ch_len = 0; size_t c = 0;
    if (hy2_get_varint(fp + 2, pay_len - 2, &ch_len, &c) != 0) return -1;
    const unsigned char *ch = fp + 2 + c;
    unsigned char cpub[32], sid[32];
    size_t sid_n = 0;
    if (ch_pick(ch, (size_t)ch_len, cpub, sid, &sid_n) != 0) return -1;

    unsigned char spriv[32], spub[32];
    if (xc_x25519_keypair(spriv, spub) != 0) return -1;

    unsigned char sh[160];
    size_t mlen = 0;
    sh[mlen++] = 0x02; mlen += 3;
    sh[mlen++] = 0x03; sh[mlen++] = 0x03;
    memset(sh + mlen, 0x22, 32); mlen += 32;
    sh[mlen++] = (unsigned char)sid_n;
    memcpy(sh + mlen, sid, sid_n); mlen += sid_n;
    sh[mlen++] = 0x13; sh[mlen++] = 0x01;
    sh[mlen++] = 0x00;
    size_t exts_at = mlen; mlen += 2;
    sh[mlen++] = 0x00; sh[mlen++] = 0x2b; sh[mlen++] = 0x00; sh[mlen++] = 0x02;
    sh[mlen++] = 0x03; sh[mlen++] = 0x04;
    sh[mlen++] = 0x00; sh[mlen++] = 0x33; sh[mlen++] = 0x00; sh[mlen++] = 0x24;
    sh[mlen++] = 0x00; sh[mlen++] = 0x1d; sh[mlen++] = 0x00; sh[mlen++] = 0x20;
    memcpy(sh + mlen, spub, 32); mlen += 32;
    sh[exts_at]     = (unsigned char)((mlen - exts_at - 2) >> 8);
    sh[exts_at + 1] = (unsigned char)(mlen - exts_at - 2);
    sh[1] = 0; sh[2] = (unsigned char)((mlen - 4) >> 8); sh[3] = (unsigned char)(mlen - 4);

    static const unsigned char srv_scid[8] = { 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98 };
    unsigned char sh_cf[180];
    size_t scfo = 0;
    sh_cf[scfo++] = 0x06;
    sh_cf[scfo++] = 0x00;
    scfo += hy2_put_varint(sh_cf + scfo, mlen);
    memcpy(sh_cf + scfo, sh, mlen); scfo += mlen;
    if (hy2_seal_long(fd, 0, cli_scid, srv_scid, s_in, 0, sh_cf, scfo) != 0) return -1;

    struct sc_hash_ctx tr;
    sc_hash_init(&tr, SC_SHA256);
    sc_hash_update(&tr, ch, (size_t)ch_len);
    sc_hash_update(&tr, sh, mlen);

    unsigned char zeros[32] = {0}, empty[32], early[32], derived[32], hs_sec[32], ecdhe[32], sh_th[32];
    unsigned char c_hs[32], s_hs[32];
    sc_hash(SC_SHA256, NULL, 0, empty);
    sc_hkdf_extract(SC_SHA256, zeros, 32, zeros, 32, early);
    xlabel(early, "derived", empty, 32, derived, 32);
    x25519_shared_ext(spriv, cpub, ecdhe);
    sc_hkdf_extract(SC_SHA256, derived, 32, ecdhe, 32, hs_sec);
    tr_snapshot(&tr, sh_th);
    xlabel(hs_sec, "c hs traffic", sh_th, 32, c_hs, 32);
    xlabel(hs_sec, "s hs traffic", sh_th, 32, s_hs, 32);

    unsigned char hs_buf[3072];
    size_t hlen = 0;
    /* EncryptedExtensions with optional quic_transport_parameters (0x0039) */
    unsigned char tp[64];
    size_t tpo = 0;
    if (init_max_data > 0) {
        tpo += hy2_put_varint(tp + tpo, 0x04);
        unsigned char vb[8];
        size_t vn = hy2_put_varint(vb, init_max_data);
        tpo += hy2_put_varint(tp + tpo, vn);
        memcpy(tp + tpo, vb, vn); tpo += vn;
    }
    if (init_max_s4_data > 0) {
        tpo += hy2_put_varint(tp + tpo, 0x06);
        unsigned char vb[8];
        size_t vn = hy2_put_varint(vb, init_max_s4_data);
        tpo += hy2_put_varint(tp + tpo, vn);
        memcpy(tp + tpo, vb, vn); tpo += vn;
    }
    static const unsigned char alpn_h3[9] = {
        0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '3'
    };
    unsigned char ee[80];
    size_t eeo = 0;
    size_t ext_tot = sizeof(alpn_h3) + 4 + tpo;
    size_t msg_len = 2 + ext_tot;
    ee[eeo++] = 0x08;
    ee[eeo++] = 0x00; ee[eeo++] = (unsigned char)(msg_len >> 8); ee[eeo++] = (unsigned char)msg_len;
    ee[eeo++] = (unsigned char)(ext_tot >> 8); ee[eeo++] = (unsigned char)ext_tot;
    memcpy(ee + eeo, alpn_h3, sizeof(alpn_h3)); eeo += sizeof(alpn_h3);
    ee[eeo++] = 0x00; ee[eeo++] = 0x39;
    ee[eeo++] = (unsigned char)(tpo >> 8); ee[eeo++] = (unsigned char)tpo;
    if (tpo > 0) { memcpy(ee + eeo, tp, tpo); eeo += tpo; }
    memcpy(hs_buf + hlen, ee, eeo); hlen += eeo;
    sc_hash_update(&tr, ee, eeo);

    const struct leaf *l = &g_leaf[LEAF_OK];
    size_t cmn = cert_msg(l, 0, 0, hs_buf + hlen, sizeof(hs_buf) - hlen);
    sc_hash_update(&tr, hs_buf + hlen, cmn);
    hlen += cmn;
    unsigned char cert_th[32];
    tr_snapshot(&tr, cert_th);
    struct plan dummy_pl = {0};
    size_t cvn = cv_msg(l, cert_th, &dummy_pl, hs_buf + hlen, sizeof(hs_buf) - hlen);
    sc_hash_update(&tr, hs_buf + hlen, cvn);
    hlen += cvn;

    unsigned char fin_th[32], fk[32], vd[32];
    tr_snapshot(&tr, fin_th);
    xlabel(s_hs, "finished", NULL, 0, fk, 32);
    sc_hmac(SC_SHA256, fk, 32, fin_th, 32, vd);
    hs_buf[hlen++] = 20; hs_buf[hlen++] = 0; hs_buf[hlen++] = 0; hs_buf[hlen++] = 32;
    memcpy(hs_buf + hlen, vd, 32);
    sc_hash_update(&tr, hs_buf + hlen - 4, 36);
    hlen += 32;

    unsigned char sf_th[32], d_sec[32], master[32];
    tr_snapshot(&tr, sf_th);
    sc_hash_free(&tr);
    xlabel(hs_sec, "derived", empty, 32, d_sec, 32);
    sc_hkdf_extract(SC_SHA256, d_sec, 32, zeros, 32, master);
    xlabel(master, "c ap traffic", sf_th, 32, c_ap, 32);
    xlabel(master, "s ap traffic", sf_th, 32, s_ap, 32);

    unsigned char f_all[2048];
    size_t o_all = 0;
    f_all[o_all++] = 0x06;
    o_all += hy2_put_varint(f_all + o_all, 0);
    o_all += hy2_put_varint(f_all + o_all, hlen);
    memcpy(f_all + o_all, hs_buf, hlen);
    o_all += hlen;
    if (hy2_seal_long(fd, 2, cli_scid, srv_scid, s_hs, 0, f_all, o_all) != 0) return -1;

    /* Receive client Handshake Finished + 1-RTT /auth */
    int got_auth = 0;
    for (int i = 0; i < 6; i++) {
        if (poll(&pfd, 1, 300) <= 0) break;
        ssize_t nr = recv(fd, dgram, sizeof(dgram), 0);
        if (nr <= 0) break;
        if ((dgram[0] & 0x80) == 0) {
            uint64_t ap_pn = 0;
            const unsigned char *afp = NULL;
            size_t aflen = 0;
            if (hy2_open_1rtt(dgram, (size_t)nr, c_ap, &ap_pn, &afp, &aflen) == 0) {
                /* ACK client's 1-RTT auth packet */
                unsigned char ackf[16];
                size_t ao = 0;
                ackf[ao++] = 0x02;
                ao += hy2_put_varint(ackf + ao, ap_pn);
                ackf[ao++] = 0x00;
                ackf[ao++] = 0x00;
                ackf[ao++] = 0x00;
                hy2_seal_1rtt(fd, cli_scid, s_ap, (*srv_1rtt_pn)++, ackf, ao);
                got_auth = 1;
                break;
            }
        }
    }
    if (!got_auth) return -1;

    /* Send Stream 0 HTTP/3 :status = 233 + Stream 4 TCP response status OK (0x00, msg_len=0, pad_len=0) */
    static const unsigned char h3_ok[10] = {
        0x01, 0x08, 0x00, 0x00, 0x5F, 0x09, 0x03, '2', '3', '3'
    };
    unsigned char sf[32];
    size_t sfo = 0;
    sf[sfo++] = 0x0B; /* STREAM(sid=0, off=0, len, fin=1) */
    sf[sfo++] = 0x00;
    sf[sfo++] = (unsigned char)sizeof(h3_ok);
    memcpy(sf + sfo, h3_ok, sizeof(h3_ok));
    sfo += sizeof(h3_ok);
    if (hy2_seal_1rtt(fd, cli_scid, s_ap, (*srv_1rtt_pn)++, sf, sfo) != 0) return -1;
    return 0;
}

/* Parse STREAM frames for sid=4 inside a decrypted 1-RTT payload, and inspect ACK/control frames */
struct hy2_rx_inspect {
    int saw_ack;
    uint64_t max_ack_range_cnt;
    int saw_stream_data_blocked;
    int saw_data_blocked;
    uint64_t max_stream_data_val;
    uint64_t max_data_val;
    int pkt_has_msd;
    int pkt_has_md;
    uint64_t pkt_msd_val;
    uint64_t pkt_md_val;
    int saw_ping;
    int saw_dgram;
    unsigned char dgram_buf[2048];
    size_t dgram_len;
};

static int hy2_parse_1rtt_frames(const unsigned char *fp, size_t flen,
                                 unsigned char *s4_buf, size_t s4_cap, size_t *s4_max_end,
                                 uint8_t *s4_bitmap, struct hy2_rx_inspect *ins) {
    size_t pos = 0;
    int s4_chunks = 0;
    if (ins) {
        ins->pkt_has_msd = 0;
        ins->pkt_has_md  = 0;
        ins->pkt_msd_val = 0;
        ins->pkt_md_val  = 0;
    }
    while (pos < flen) {
        uint64_t ftype = 0; size_t c = 0;
        if (hy2_get_varint(fp + pos, flen - pos, &ftype, &c) != 0) return -1;
        pos += c;
        if (ftype == 0x00) continue;
        if (ftype == 0x01) { if (ins) ins->saw_ping = 1; continue; }
        if (ftype == 0x02 || ftype == 0x03) {
            uint64_t largest = 0, delay = 0, rcnt = 0, first_r = 0;
            size_t c1 = 0, c2 = 0, c3 = 0, c4 = 0;
            if (hy2_get_varint(fp + pos, flen - pos, &largest, &c1) != 0) return -1;
            pos += c1;
            if (hy2_get_varint(fp + pos, flen - pos, &delay, &c2) != 0) return -1;
            pos += c2;
            if (hy2_get_varint(fp + pos, flen - pos, &rcnt, &c3) != 0) return -1;
            pos += c3;
            if (hy2_get_varint(fp + pos, flen - pos, &first_r, &c4) != 0) return -1;
            pos += c4;
            if (ins) {
                ins->saw_ack = 1;
                if (rcnt > ins->max_ack_range_cnt) ins->max_ack_range_cnt = rcnt;
            }
            for (uint64_t i = 0; i < rcnt; i++) {
                uint64_t gap = 0, rlen = 0; size_t cg = 0, cr = 0;
                if (hy2_get_varint(fp + pos, flen - pos, &gap, &cg) != 0) return -1;
                pos += cg;
                if (hy2_get_varint(fp + pos, flen - pos, &rlen, &cr) != 0) return -1;
                pos += cr;
            }
            if (ftype == 0x03) {
                for (int i = 0; i < 3; i++) {
                    uint64_t v = 0; size_t cv = 0;
                    if (hy2_get_varint(fp + pos, flen - pos, &v, &cv) != 0) return -1;
                    pos += cv;
                }
            }
            continue;
        }
        if (ftype >= 0x08 && ftype <= 0x0f) {
            int has_off = (ftype & 0x04) != 0;
            int has_len = (ftype & 0x02) != 0;
            uint64_t sid = 0, off = 0, slen = 0; size_t cs = 0, co = 0, cl = 0;
            if (hy2_get_varint(fp + pos, flen - pos, &sid, &cs) != 0) return -1;
            pos += cs;
            if (has_off) {
                if (hy2_get_varint(fp + pos, flen - pos, &off, &co) != 0) return -1;
                pos += co;
            }
            if (has_len) {
                if (hy2_get_varint(fp + pos, flen - pos, &slen, &cl) != 0) return -1;
                pos += cl;
            } else {
                slen = flen - pos;
            }
            if (pos + slen > flen) return -1;
            if (sid == 4 && s4_buf) {
                if (off + slen <= s4_cap) {
                    memcpy(s4_buf + off, fp + pos, (size_t)slen);
                    if (s4_bitmap) {
                        for (size_t k = 0; k < (size_t)slen; k++) s4_bitmap[off + k] = 1;
                    }
                    if (off + slen > *s4_max_end) *s4_max_end = (size_t)(off + slen);
                    s4_chunks++;
                }
            }
            pos += (size_t)slen;
            continue;
        }
        if (ftype == 0x10) {
            uint64_t md = 0; size_t cm = 0;
            if (hy2_get_varint(fp + pos, flen - pos, &md, &cm) != 0) return -1;
            pos += cm;
            if (ins) {
                ins->pkt_has_md = 1;
                ins->pkt_md_val = md;
                if (md > ins->max_data_val) ins->max_data_val = md;
            }
            continue;
        }
        if (ftype == 0x11) {
            uint64_t sid = 0, msd = 0; size_t cs = 0, cm = 0;
            if (hy2_get_varint(fp + pos, flen - pos, &sid, &cs) != 0) return -1;
            pos += cs;
            if (hy2_get_varint(fp + pos, flen - pos, &msd, &cm) != 0) return -1;
            pos += cm;
            if (ins && sid == 4) {
                ins->pkt_has_msd = 1;
                ins->pkt_msd_val = msd;
                if (msd > ins->max_stream_data_val) ins->max_stream_data_val = msd;
            }
            continue;
        }
        if (ftype == 0x14) {
            uint64_t lim = 0; size_t cl = 0;
            if (hy2_get_varint(fp + pos, flen - pos, &lim, &cl) != 0) return -1;
            pos += cl;
            if (ins) ins->saw_data_blocked = 1;
            continue;
        }
        if (ftype == 0x15) {
            uint64_t sid = 0, lim = 0; size_t cs = 0, cl = 0;
            if (hy2_get_varint(fp + pos, flen - pos, &sid, &cs) != 0) return -1;
            pos += cs;
            if (hy2_get_varint(fp + pos, flen - pos, &lim, &cl) != 0) return -1;
            pos += cl;
            if (ins && sid == 4) ins->saw_stream_data_blocked = 1;
            continue;
        }
        if (ftype == 0x30 || ftype == 0x31) {
            uint64_t dlen = 0; size_t cd = 0;
            if (ftype == 0x31) {
                if (hy2_get_varint(fp + pos, flen - pos, &dlen, &cd) != 0) return -1;
                pos += cd;
            } else {
                dlen = flen - pos;
            }
            if (pos + dlen > flen) return -1;
            if (ins && dlen <= sizeof(ins->dgram_buf)) {
                ins->saw_dgram++;
                memcpy(ins->dgram_buf, fp + pos, (size_t)dlen);
                ins->dgram_len = (size_t)dlen;
            }
            pos += (size_t)dlen;
            continue;
        }
        break;
    }
    return s4_chunks;
}

/* Scenario 1: Loss Recovery (Packet Threshold + PTO Tail Loss), Multi-Range SACK, Duplicate Suppression */
struct hy2_loss_srv_ctx {
    int fd;
    int ok;
    int saw_multi_sack;
    int saw_monotonic_retx_pn;
    int dropped_pkt_threshold;
    int dropped_tail_pto;
    size_t rx_total;
    unsigned char rx_stream[65536];
    uint8_t rx_bitmap[65536];
};

static size_t hy2_build_srv_ack(const uint8_t *rx_pn, uint64_t max_pn, unsigned char *out) {
    struct { uint64_t low, high; } rng[32];
    size_t nr = 0;
    int64_t p = (int64_t)max_pn;
    while (p >= 0 && nr < 32) {
        while (p >= 0 && !rx_pn[p]) p--;
        if (p < 0) break;
        uint64_t hi = (uint64_t)p;
        while (p >= 0 && rx_pn[p]) p--;
        uint64_t lo = (uint64_t)(p + 1);
        rng[nr].low = lo;
        rng[nr].high = hi;
        nr++;
    }
    if (nr == 0) return 0;
    size_t o = 0;
    out[o++] = 0x02;
    o += hy2_put_varint(out + o, rng[0].high);
    out[o++] = 0x00; /* delay = 0 */
    o += hy2_put_varint(out + o, nr - 1);
    o += hy2_put_varint(out + o, rng[0].high - rng[0].low);
    uint64_t prev_low = rng[0].low;
    for (size_t i = 1; i < nr; i++) {
        uint64_t gap = prev_low - rng[i].high - 2;
        uint64_t rlen = rng[i].high - rng[i].low;
        o += hy2_put_varint(out + o, gap);
        o += hy2_put_varint(out + o, rlen);
        prev_low = rng[i].low;
    }
    return o;
}

static void *hy2_loss_srv_thread(void *arg) {
    struct hy2_loss_srv_ctx *ctx = arg;
    unsigned char cli_scid[8], c_ap[32], s_ap[32];
    uint64_t srv_pn = 0;
    if (hy2_handshake_srv(ctx->fd, 0, 0, cli_scid, c_ap, s_ap, &srv_pn) != 0) return NULL;

    struct pollfd pfd = { .fd = ctx->fd, .events = POLLIN, .revents = 0 };
    unsigned char dgram[2048];
    struct hy2_rx_inspect ins;
    memset(&ins, 0, sizeof(ins));
    uint8_t srv_rx_pn[512];
    memset(srv_rx_pn, 0, sizeof(srv_rx_pn));
    srv_rx_pn[0] = 1; /* auth packet pn=0 */
    uint64_t max_rx_pn = 0;

    /* Step A: Wait for client's HY2 TCP framing header on Stream 4 ([0x40,0x01][addr][pad]) */
    size_t s4_max_end = 0;
    size_t hdr_len = 0;
    uint64_t last_cli_pn = 0;
    int have_last_pn = 0;
    int monotonic_ok = 1;

    while (s4_max_end < 14) {
        if (poll(&pfd, 1, 1000) <= 0) return NULL;
        ssize_t nr = recv(ctx->fd, dgram, sizeof(dgram), 0);
        if (nr <= 0) return NULL;
        uint64_t pn = 0; const unsigned char *fp = NULL; size_t flen = 0;
        if (hy2_open_1rtt(dgram, (size_t)nr, c_ap, &pn, &fp, &flen) != 0) continue;
        if (have_last_pn && pn <= last_cli_pn) monotonic_ok = 0;
        last_cli_pn = pn; have_last_pn = 1;
        if (pn < sizeof(srv_rx_pn)) srv_rx_pn[pn] = 1;
        if (pn > max_rx_pn) max_rx_pn = pn;
        hy2_parse_1rtt_frames(fp, flen, ctx->rx_stream, sizeof(ctx->rx_stream), &s4_max_end, ctx->rx_bitmap, &ins);
        if (s4_max_end < 14) continue;
        /* ACK the TCP request header and send HY2 TCP response [0x00 (OK), 0x00 (msg_len=0), 0x00 (pad_len=0)] */
        unsigned char resp[64];
        size_t ro = hy2_build_srv_ack(srv_rx_pn, max_rx_pn, resp);
        resp[ro++] = 0x0A; /* STREAM(sid=4, off=0, len=3) */
        resp[ro++] = 0x04;
        resp[ro++] = 0x03;
        resp[ro++] = 0x00; resp[ro++] = 0x00; resp[ro++] = 0x00;
        hy2_seal_1rtt(ctx->fd, cli_scid, s_ap, srv_pn++, resp, ro);
        hdr_len = s4_max_end;
        break;
    }

    /* Step B: Send 8 server Stream 4 chunks (8 * 1000 = 8000 bytes) OUT OF ORDER and with DUPLICATE PN
     * AND with a deliberate PN gap so client emits a multi-range SACK (rcnt >= 1):
     * First wave: chunk 2 (pn = base_pn), chunk 4 (pn = base_pn + 2, skipping base_pn + 1!), duplicate chunk 2 (pn = base_pn). */
    size_t srv_off_base = 3; /* after 3-byte HY2 TCP status header */
    uint64_t base_pn = srv_pn;
    srv_pn += 8;
    int wave1_ch[3] = { 2, 4, 2 };
    uint64_t wave1_pn[3] = { base_pn, base_pn + 2, base_pn };
    for (int idx = 0; idx < 3; idx++) {
        int ch_i = wave1_ch[idx];
        size_t off = srv_off_base + (size_t)ch_i * 1000;
        unsigned char sf[1100];
        size_t so = 0;
        sf[so++] = 0x0E;
        sf[so++] = 0x04;
        so += hy2_put_varint(sf + so, off);
        so += hy2_put_varint(sf + so, 1000);
        for (size_t k = 0; k < 1000; k++) sf[so + k] = (unsigned char)((ch_i * 37 + k) & 0xFF);
        so += 1000;
        hy2_seal_1rtt(ctx->fd, cli_scid, s_ap, wave1_pn[idx], sf, so);
    }

    /* Wait briefly for client to process wave 1 and emit its multi-range SACK (rcnt >= 1) */
    for (int w = 0; w < 6 && ins.max_ack_range_cnt < 1; w++) {
        if (poll(&pfd, 1, 30) <= 0) continue;
        ssize_t nr = recv(ctx->fd, dgram, sizeof(dgram), 0);
        if (nr <= 0) break;
        uint64_t pn = 0; const unsigned char *fp = NULL; size_t flen = 0;
        if (hy2_open_1rtt(dgram, (size_t)nr, c_ap, &pn, &fp, &flen) == 0) {
            if (pn <= last_cli_pn) monotonic_ok = 0;
            last_cli_pn = pn;
            if (pn < sizeof(srv_rx_pn)) srv_rx_pn[pn] = 1;
            if (pn > max_rx_pn) max_rx_pn = pn;
            hy2_parse_1rtt_frames(fp, flen, ctx->rx_stream, sizeof(ctx->rx_stream), &s4_max_end, ctx->rx_bitmap, &ins);
        }
    }

    /* Second wave: fill the PN gap (base_pn + 1) and send remaining chunks 0, 1, 3, 5, 6, 7 */
    int wave2_ch[6] = { 0, 1, 3, 5, 6, 7 };
    uint64_t wave2_pn[6] = { base_pn + 1, base_pn + 3, base_pn + 4, base_pn + 5, base_pn + 6, base_pn + 7 };
    for (int idx = 0; idx < 6; idx++) {
        int ch_i = wave2_ch[idx];
        size_t off = srv_off_base + (size_t)ch_i * 1000;
        unsigned char sf[1100];
        size_t so = 0;
        sf[so++] = 0x0E;
        sf[so++] = 0x04;
        so += hy2_put_varint(sf + so, off);
        so += hy2_put_varint(sf + so, 1000);
        for (size_t k = 0; k < 1000; k++) sf[so + k] = (unsigned char)((ch_i * 37 + k) & 0xFF);
        so += 1000;
        hy2_seal_1rtt(ctx->fd, cli_scid, s_ap, wave2_pn[idx], sf, so);
    }

    /* Step C: Receive 16000 bytes of client payload (after hdr_len) on Stream 4.
     * Deliberately DROP the 2nd data packet (to trigger 3-packet-threshold loss detection via SACK)
     * AND deliberately DROP the last packet in the flight (to trigger PTO tail recovery!). */
    size_t target_end = hdr_len + 16000;
    int data_pkt_idx = 0;
    int dropped_1 = 0, dropped_tail = 0;

    for (int iter = 0; iter < 250; iter++) {
        int all_done = 1;
        for (size_t k = hdr_len; k < target_end; k++) {
            if (!ctx->rx_bitmap[k]) { all_done = 0; break; }
        }
        if (all_done && ins.max_ack_range_cnt >= 1) break;

        if (poll(&pfd, 1, 200) <= 0) continue;
        ssize_t nr = recv(ctx->fd, dgram, sizeof(dgram), 0);
        if (nr <= 0) break;
        uint64_t pn = 0; const unsigned char *fp = NULL; size_t flen = 0;
        if (hy2_open_1rtt(dgram, (size_t)nr, c_ap, &pn, &fp, &flen) != 0) continue;
        if (pn <= last_cli_pn) monotonic_ok = 0;
        last_cli_pn = pn;

        /* Peek if packet has Stream 4 data before committing */
        unsigned char tmp_buf[65536];
        uint8_t tmp_bm[65536];
        size_t tmp_end = s4_max_end;
        memcpy(tmp_bm, ctx->rx_bitmap, sizeof(tmp_bm));
        int s4c = hy2_parse_1rtt_frames(fp, flen, tmp_buf, sizeof(tmp_buf), &tmp_end, tmp_bm, &ins);
        if (s4c > 0) {
            data_pkt_idx++;
            if (!dropped_1 && data_pkt_idx == 2) {
                /* Drop packet #2: do NOT record in srv_rx_pn and do NOT copy into rx_stream */
                dropped_1 = 1;
                ctx->dropped_pkt_threshold = 1;
                continue;
            }
            if (!dropped_tail && tmp_end >= target_end) {
                /* Drop the final packet of the flight: do NOT record in srv_rx_pn and do NOT ACK it, forcing PTO! */
                dropped_tail = 1;
                ctx->dropped_tail_pto = 1;
                continue;
            }
        }
        /* Accept packet */
        if (pn < sizeof(srv_rx_pn)) srv_rx_pn[pn] = 1;
        if (pn > max_rx_pn) max_rx_pn = pn;
        hy2_parse_1rtt_frames(fp, flen, ctx->rx_stream, sizeof(ctx->rx_stream), &s4_max_end, ctx->rx_bitmap, &ins);

        unsigned char ackf[128];
        size_t ao = hy2_build_srv_ack(srv_rx_pn, max_rx_pn, ackf);
        if (ao > 0)
            hy2_seal_1rtt(ctx->fd, cli_scid, s_ap, srv_pn++, ackf, ao);
    }

    ctx->saw_multi_sack = (ins.max_ack_range_cnt >= 1) ? 1 : 0;
    ctx->saw_monotonic_retx_pn = monotonic_ok;
    ctx->rx_total = (s4_max_end >= hdr_len) ? (s4_max_end - hdr_len) : 0;
    if (ctx->rx_total == 16000) {
        memmove(ctx->rx_stream, ctx->rx_stream + hdr_len, 16000);
        ctx->ok = 1;
    }
    return NULL;
}

/* Scenario 2: Send & Receive Flow Control (EncryptedExtensions TP, STREAM_DATA_BLOCKED, MAX_STREAM_DATA, MAX_DATA) */
struct hy2_fc_srv_ctx {
    int fd;
    int saw_stream_data_blocked;
    int capped_at_initial_window;
    int resumed_after_max_stream_data;
    int saw_client_max_stream_data;
    int saw_client_max_data;
    size_t rx_total;
};

static void *hy2_fc_srv_thread(void *arg) {
    struct hy2_fc_srv_ctx *ctx = arg;
    unsigned char cli_scid[8], c_ap[32], s_ap[32];
    uint64_t srv_pn = 0;
    /* Advertise initial_max_data = 4096, initial_max_stream_data_bidi_remote = 1500 */
    if (hy2_handshake_srv(ctx->fd, 4096, 1500, cli_scid, c_ap, s_ap, &srv_pn) != 0) return NULL;

    struct pollfd pfd = { .fd = ctx->fd, .events = POLLIN, .revents = 0 };
    unsigned char dgram[2048];
    unsigned char rx_buf[16384];
    uint8_t rx_bm[16384];
    memset(rx_bm, 0, sizeof(rx_bm));
    size_t s4_max_end = 0;
    struct hy2_rx_inspect ins;
    memset(&ins, 0, sizeof(ins));

    /* Collect client's initial burst until it blocks at 1500 bytes and sends STREAM_DATA_BLOCKED (0x15) */
    for (int i = 0; i < 15; i++) {
        if (poll(&pfd, 1, 80) <= 0) break;
        ssize_t nr = recv(ctx->fd, dgram, sizeof(dgram), 0);
        if (nr <= 0) break;
        uint64_t pn = 0; const unsigned char *fp = NULL; size_t flen = 0;
        if (hy2_open_1rtt(dgram, (size_t)nr, c_ap, &pn, &fp, &flen) != 0) continue;
        hy2_parse_1rtt_frames(fp, flen, rx_buf, sizeof(rx_buf), &s4_max_end, rx_bm, &ins);
        unsigned char ackf[32]; size_t ao = 0;
        ackf[ao++] = 0x02; ao += hy2_put_varint(ackf + ao, pn);
        ackf[ao++] = 0; ackf[ao++] = 0; ao += hy2_put_varint(ackf + ao, pn);
        hy2_seal_1rtt(ctx->fd, cli_scid, s_ap, srv_pn++, ackf, ao);
        if (ins.saw_stream_data_blocked && s4_max_end == 1500) break;
    }

    if (s4_max_end == 1500) ctx->capped_at_initial_window = 1;
    if (ins.saw_stream_data_blocked) ctx->saw_stream_data_blocked = 1;

    /* Now grant MAX_STREAM_DATA(sid=4, 16384) and MAX_DATA(32768) + HY2 TCP OK response on Stream 4 */
    unsigned char grant[64];
    size_t go = 0;
    grant[go++] = 0x11; /* MAX_STREAM_DATA */
    grant[go++] = 0x04; /* sid = 4 */
    go += hy2_put_varint(grant + go, 16384);
    grant[go++] = 0x10; /* MAX_DATA */
    go += hy2_put_varint(grant + go, 32768);
    grant[go++] = 0x0A; /* STREAM(sid=4, off=0, len=3) */
    grant[go++] = 0x04;
    grant[go++] = 0x03;
    grant[go++] = 0x00; grant[go++] = 0x00; grant[go++] = 0x00;
    hy2_seal_1rtt(ctx->fd, cli_scid, s_ap, srv_pn++, grant, go);

    /* Also send 20000 bytes of server Stream 4 data so client consumes > 16 KiB and emits MAX_STREAM_DATA */
    size_t srv_off = 3;
    for (int chunk = 0; chunk < 20; chunk++) {
        unsigned char sf[1100];
        size_t so = 0;
        sf[so++] = 0x0E;
        sf[so++] = 0x04;
        so += hy2_put_varint(sf + so, srv_off);
        so += hy2_put_varint(sf + so, 1000);
        memset(sf + so, 0x5A, 1000);
        so += 1000;
        srv_off += 1000;
        hy2_seal_1rtt(ctx->fd, cli_scid, s_ap, srv_pn++, sf, so);
    }

    /* Receive remaining client Stream 4 data and client's MAX_STREAM_DATA update */
    for (int i = 0; i < 40; i++) {
        if (s4_max_end > 4000) ctx->resumed_after_max_stream_data = 1;
        if (ins.max_stream_data_val > 0) ctx->saw_client_max_stream_data = 1;
        if (ins.max_data_val > 0) ctx->saw_client_max_data = 1;
        if (s4_max_end > 4000 && ins.max_stream_data_val > 0) break;
        if (poll(&pfd, 1, 100) <= 0) continue;
        ssize_t nr = recv(ctx->fd, dgram, sizeof(dgram), 0);
        if (nr <= 0) break;
        uint64_t pn = 0; const unsigned char *fp = NULL; size_t flen = 0;
        if (hy2_open_1rtt(dgram, (size_t)nr, c_ap, &pn, &fp, &flen) != 0) continue;
        hy2_parse_1rtt_frames(fp, flen, rx_buf, sizeof(rx_buf), &s4_max_end, rx_bm, &ins);
        unsigned char ackf[32]; size_t ao = 0;
        ackf[ao++] = 0x02; ao += hy2_put_varint(ackf + ao, pn);
        ackf[ao++] = 0; ackf[ao++] = 0; ao += hy2_put_varint(ackf + ao, pn);
        hy2_seal_1rtt(ctx->fd, cli_scid, s_ap, srv_pn++, ackf, ao);
    }

    if (s4_max_end > 4000) ctx->resumed_after_max_stream_data = 1;
    if (ins.max_stream_data_val > 0) ctx->saw_client_max_stream_data = 1;
    if (ins.max_data_val > 0) ctx->saw_client_max_data = 1;
    ctx->rx_total = s4_max_end;
    return NULL;
}

/* Scenario 2B: Reliable Flow-Control Grant Recovery Under Loss
 * - Server sends up to client's initial window limit (4096B) and stops WITHOUT sending BLOCKED
 * - Drops client's standalone MAX_STREAM_DATA/MAX_DATA grant #1, drops retransmitted grant #2
 *   (repeated grant loss), drops ACK for grant #3 (ACK loss), then accepts grant #4 and resumes
 * - Drops a grant piggybacked onto a STREAM packet, then recovers both STREAM and grant via PTO
 * - Drops an older grant (V3=10240), accepts and ACKs a newer grant (V4=12288) + 3 subsequent
 *   packets so V3 crosses the 3-packet loss threshold, and verifies V3 loss never regresses or
 *   re-sends the stale window value */
struct hy2_grant_loss_srv_ctx {
    int fd;
    int paused_at_initial_limit;
    int dropped_standalone_grant;
    int dropped_grant_repeat;
    int dropped_grant_ack;
    int standalone_grant_recovered;
    int primed_piggyback;
    int dropped_piggybacked_grant;
    int piggybacked_grant_recovered;
    int dropped_stale_v3;
    int saw_v4_grant;
    int saw_stale_grant_regression;
    uint64_t max_msd_seen;
    uint64_t max_md_seen;
    size_t rx_total;
    unsigned char rx_stream[16384];
    uint8_t rx_bitmap[16384];
};

static void hy2_send_srv_s4_To_limit(int fd, const unsigned char cli_scid[8],
                                     const unsigned char s_ap[32], uint64_t *srv_pn,
                                     size_t *srv_s4_sent, size_t limit) {
    while (*srv_s4_sent < limit) {
        size_t rem = limit - *srv_s4_sent;
        size_t chunk = rem > 1024 ? 1024 : rem;
        unsigned char sf[1100];
        size_t so = 0;
        size_t off = *srv_s4_sent;
        sf[so++] = off ? 0x0E : 0x0A;
        sf[so++] = 0x04;
        if (off) so += hy2_put_varint(sf + so, off);
        so += hy2_put_varint(sf + so, chunk);
        for (size_t k = 0; k < chunk; k++) {
            size_t pos = off + k;
            if (pos < 3) {
                sf[so + k] = 0x00; /* 3-byte HY2 TCP status header [0x00, 0x00, 0x00] */
            } else {
                size_t pay_idx = pos - 3;
                sf[so + k] = (unsigned char)((pay_idx * 29 + 11) & 0xFF);
            }
        }
        so += chunk;
        *srv_s4_sent += chunk;
        hy2_seal_1rtt(fd, cli_scid, s_ap, (*srv_pn)++, sf, so);
    }
}

static void *hy2_grant_loss_srv_thread(void *arg) {
    struct hy2_grant_loss_srv_ctx *ctx = arg;
    unsigned char cli_scid[8], c_ap[32], s_ap[32];
    uint64_t srv_pn = 0;
    if (hy2_handshake_srv(ctx->fd, 65536, 65536, cli_scid, c_ap, s_ap, &srv_pn) != 0) return NULL;

    struct pollfd pfd = { .fd = ctx->fd, .events = POLLIN, .revents = 0 };
    unsigned char dgram[2048];
    struct hy2_rx_inspect ins;
    memset(&ins, 0, sizeof(ins));
    uint8_t srv_rx_pn[512];
    memset(srv_rx_pn, 0, sizeof(srv_rx_pn));
    srv_rx_pn[0] = 1; /* auth packet pn=0 */
    uint64_t max_rx_pn = 0;

    size_t s4_max_end = 0;
    size_t hdr_len = 0;
    size_t srv_s4_sent = 0;
    size_t srv_peer_limit = 4096; /* client's initial local_s4_max_data (TUNVLESS_HY2_RX_WIN=4096) */

    /* Wait for client's 14B HY2 TCP address header on Stream 4 */
    while (s4_max_end < 14) {
        if (poll(&pfd, 1, 1000) <= 0) return NULL;
        ssize_t nr = recv(ctx->fd, dgram, sizeof(dgram), 0);
        if (nr <= 0) return NULL;
        uint64_t pn = 0; const unsigned char *fp = NULL; size_t flen = 0;
        if (hy2_open_1rtt(dgram, (size_t)nr, c_ap, &pn, &fp, &flen) != 0) continue;
        if (pn < sizeof(srv_rx_pn)) srv_rx_pn[pn] = 1;
        if (pn > max_rx_pn) max_rx_pn = pn;
        hy2_parse_1rtt_frames(fp, flen, ctx->rx_stream, sizeof(ctx->rx_stream), &s4_max_end, ctx->rx_bitmap, &ins);
        if (s4_max_end < 14) continue;
        hdr_len = s4_max_end;
        unsigned char ackf[64];
        size_t ao = hy2_build_srv_ack(srv_rx_pn, max_rx_pn, ackf);
        if (ao > 0) hy2_seal_1rtt(ctx->fd, cli_scid, s_ap, srv_pn++, ackf, ao);
        break;
    }

    /* Send up to initial window limit (4096B on Stream 4 = 3B header + 4093B payload) and STOP without BLOCKED */
    hy2_send_srv_s4_To_limit(ctx->fd, cli_scid, s_ap, &srv_pn, &srv_s4_sent, srv_peer_limit);
    if (srv_s4_sent == 4096) ctx->paused_at_initial_limit = 1;

    int v1_attempts = 0;
    size_t target_cli_end = hdr_len + 3000;

    for (int iter = 0; iter < 250; iter++) {
        int cli_done = (s4_max_end >= target_cli_end);
        if (cli_done) {
            for (size_t k = hdr_len; k < target_cli_end; k++) {
                if (!ctx->rx_bitmap[k]) { cli_done = 0; break; }
            }
        }
        if (cli_done && srv_s4_sent == 8192 && ctx->saw_v4_grant) break;

        if (poll(&pfd, 1, 150) <= 0) continue;
        ssize_t nr = recv(ctx->fd, dgram, sizeof(dgram), 0);
        if (nr <= 0) break;
        uint64_t pn = 0; const unsigned char *fp = NULL; size_t flen = 0;
        if (hy2_open_1rtt(dgram, (size_t)nr, c_ap, &pn, &fp, &flen) != 0) continue;

        /* Inspect packet frames into temporary buffers before deciding whether to drop or accept */
        unsigned char tmp_buf[16384];
        uint8_t tmp_bm[16384];
        size_t tmp_end = s4_max_end;
        memcpy(tmp_bm, ctx->rx_bitmap, sizeof(tmp_bm));
        int s4c = hy2_parse_1rtt_frames(fp, flen, tmp_buf, sizeof(tmp_buf), &tmp_end, tmp_bm, &ins);

        /* Monotonic grant check: no received packet may ever carry a grant smaller than an already-seen grant */
        if (ins.pkt_has_msd && ins.pkt_msd_val < ctx->max_msd_seen)
            ctx->saw_stale_grant_regression = 1;
        if (ins.pkt_has_md && ins.pkt_md_val < ctx->max_md_seen)
            ctx->saw_stale_grant_regression = 1;

        /* Phase A: Grant V1 (msd == 6144, standalone):
         * Attempt 1: drop standalone grant
         * Attempt 2: drop retransmitted grant (repeated grant loss)
         * Attempt 3: drop server ACK (ACK loss)
         * Attempt 4: accept, ACK, and resume server Stream 4 up to 6144 */
        if (ins.pkt_has_msd && ins.pkt_msd_val == 6144) {
            v1_attempts++;
            if (v1_attempts == 1 && s4c == 0) {
                ctx->dropped_standalone_grant = 1;
                continue;
            }
            if (v1_attempts == 2) {
                ctx->dropped_grant_repeat = 1;
                continue;
            }
            if (v1_attempts == 3) {
                ctx->dropped_grant_ack = 1;
                continue;
            }
            ctx->standalone_grant_recovered = 1;
        }

        /* Phase B: Grant V2 (msd == 8192):
         * First standalone arrival: drop so next client STREAM write piggybacks MAX_STREAM_DATA(8192)
         * First piggybacked arrival (s4c > 0 && msd == 8192): drop entire piggybacked packet
         * Second arrival (PTO retransmission of STREAM + MAX_STREAM_DATA(8192)): accept & resume to 8192 */
        if (ins.pkt_has_msd && ins.pkt_msd_val == 8192) {
            if (s4c == 0 && !ctx->primed_piggyback) {
                ctx->primed_piggyback = 1;
                continue;
            }
            if (s4c > 0 && !ctx->dropped_piggybacked_grant) {
                ctx->dropped_piggybacked_grant = 1;
                continue;
            }
            if (s4c > 0 && ctx->dropped_piggybacked_grant) {
                ctx->piggybacked_grant_recovered = 1;
            }
        }

        /* Phase C: Stale Grant V3 (msd == 10240) vs Newer Grant V4 (msd == 12288):
         * Drop V3 (10240) so it stays in client sent_pkts while V4 (12288) is accepted and ACKed */
        if (ins.pkt_has_msd && ins.pkt_msd_val == 10240 && !ctx->dropped_stale_v3) {
            ctx->dropped_stale_v3 = 1;
            continue;
        }
        if (ins.pkt_has_msd && ins.pkt_msd_val == 12288) {
            ctx->saw_v4_grant = 1;
        }

        /* Accept packet */
        if (pn < sizeof(srv_rx_pn)) srv_rx_pn[pn] = 1;
        if (pn > max_rx_pn) max_rx_pn = pn;
        hy2_parse_1rtt_frames(fp, flen, ctx->rx_stream, sizeof(ctx->rx_stream), &s4_max_end, ctx->rx_bitmap, &ins);

        if (ins.pkt_has_msd && ins.pkt_msd_val > ctx->max_msd_seen)
            ctx->max_msd_seen = ins.pkt_msd_val;
        if (ins.pkt_has_md && ins.pkt_md_val > ctx->max_md_seen)
            ctx->max_md_seen = ins.pkt_md_val;
        if (ctx->max_msd_seen > srv_peer_limit) {
            srv_peer_limit = (size_t)ctx->max_msd_seen;
            if (srv_peer_limit > 8192) srv_peer_limit = 8192;
        }

        unsigned char ackf[128];
        size_t ao = hy2_build_srv_ack(srv_rx_pn, max_rx_pn, ackf);
        if (ao > 0)
            hy2_seal_1rtt(ctx->fd, cli_scid, s_ap, srv_pn++, ackf, ao);

        /* Resume sending server Stream 4 data up to the newly granted peer limit (without ever sending BLOCKED) */
        hy2_send_srv_s4_To_limit(ctx->fd, cli_scid, s_ap, &srv_pn, &srv_s4_sent, srv_peer_limit);
    }

    ctx->rx_total = (s4_max_end >= hdr_len) ? (s4_max_end - hdr_len) : 0;
    if (ctx->rx_total == 3000)
        memmove(ctx->rx_stream, ctx->rx_stream + hdr_len, 3000);
    return NULL;
}

/* Scenario 3: Multi-Fragment Hysteria2 UDP Datagram Send & Out-of-Order Reassembly */
struct hy2_udp_srv_ctx {
    int fd;
    int got_all_3_frags;
    size_t reassembled_len;
    unsigned char reassembled[4096];
};

static void *hy2_udp_srv_thread(void *arg) {
    struct hy2_udp_srv_ctx *ctx = arg;
    unsigned char cli_scid[8], c_ap[32], s_ap[32];
    uint64_t srv_pn = 0;
    if (hy2_handshake_srv(ctx->fd, 0, 0, cli_scid, c_ap, s_ap, &srv_pn) != 0) return NULL;

    struct pollfd pfd = { .fd = ctx->fd, .events = POLLIN, .revents = 0 };
    unsigned char dgram[2048];
    struct hy2_rx_inspect ins;
    uint8_t seen_frag[3] = {0, 0, 0};
    uint16_t seen_pkt_id = 0;
    uint32_t cli_sid = 0;

    for (int i = 0; i < 20; i++) {
        if (seen_frag[0] && seen_frag[1] && seen_frag[2]) break;
        if (poll(&pfd, 1, 200) <= 0) continue;
        ssize_t nr = recv(ctx->fd, dgram, sizeof(dgram), 0);
        if (nr <= 0) break;
        uint64_t pn = 0; const unsigned char *fp = NULL; size_t flen = 0;
        if (hy2_open_1rtt(dgram, (size_t)nr, c_ap, &pn, &fp, &flen) != 0) continue;
        memset(&ins, 0, sizeof(ins));
        size_t dummy_end = 0;
        hy2_parse_1rtt_frames(fp, flen, NULL, 0, &dummy_end, NULL, &ins);
        if (ins.saw_dgram && ins.dgram_len > 8) {
            const unsigned char *dp = ins.dgram_buf;
            cli_sid = ((uint32_t)dp[0] << 24) | ((uint32_t)dp[1] << 16) | ((uint32_t)dp[2] << 8) | dp[3];
            uint16_t pid = (uint16_t)(((uint16_t)dp[4] << 8) | dp[5]);
            uint8_t fid = dp[6], fcnt = dp[7];
            uint64_t alen = 0; size_t ac = 0;
            if (fcnt == 3 && fid < 3 && hy2_get_varint(dp + 8, ins.dgram_len - 8, &alen, &ac) == 0) {
                size_t pay_off = 8 + ac + (size_t)alen;
                size_t pay_len = ins.dgram_len - pay_off;
                if (seen_pkt_id == 0) seen_pkt_id = pid;
                if (pid == seen_pkt_id) {
                    seen_frag[fid] = 1;
                    memcpy(ctx->reassembled + (size_t)fid * 1100, dp + pay_off, pay_len);
                    ctx->reassembled_len += pay_len;
                }
            }
        }
    }

    if (seen_frag[0] && seen_frag[1] && seen_frag[2]) {
        ctx->got_all_3_frags = 1;
        /* Send a 2400-byte UDP datagram back in 3 OUT-OF-ORDER fragments (frag_id = 2, 0, 1) */
        int send_order[3] = { 2, 0, 1 };
        for (int idx = 0; idx < 3; idx++) {
            int fid = send_order[idx];
            unsigned char df[1000];
            size_t doff = 0;
            df[doff++] = 0x31; /* DATAGRAM with length */
            const char *addr_s = "1.1.1.1:53";
            size_t alen = strlen(addr_s);
            size_t body_len = 4 + 2 + 1 + 1 + 1 + alen + 800;
            doff += hy2_put_varint(df + doff, body_len);
            df[doff++] = (unsigned char)(cli_sid >> 24);
            df[doff++] = (unsigned char)(cli_sid >> 16);
            df[doff++] = (unsigned char)(cli_sid >> 8);
            df[doff++] = (unsigned char)cli_sid;
            df[doff++] = 0x77; df[doff++] = 0x88; /* pkt_id = 0x7788 */
            df[doff++] = (unsigned char)fid;
            df[doff++] = 3; /* frag_count = 3 */
            df[doff++] = (unsigned char)alen;
            memcpy(df + doff, addr_s, alen); doff += alen;
            for (size_t k = 0; k < 800; k++) {
                df[doff + k] = (unsigned char)(((size_t)fid * 800 + k) & 0xFF);
            }
            doff += 800;
            hy2_seal_1rtt(ctx->fd, cli_scid, s_ap, srv_pn++, df, doff);
        }
    }
    return NULL;
}
#endif /* STEER_HAVE_X509WRITE */

/* One run: make a socket pair, give one end to the client and the other to the server half.
 *
 * ctx_left, if given, receives the number of cipher contexts left EXPANDED in the connection
 * after return. This is the observable form of "there was nothing to free": a failed handshake
 * closes with a plain close(fd), which is safe only while tls13.c expands the traffic contexts
 * as its last step, after all its failure exits. Nothing else guards this link between the two
 * files; the check fails the day the order in tls13.c changes. */
static int run_case(const struct plan *pl, struct vless_node *n, char *reason, size_t rn,
                    int *ctx_left) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return -100;

    struct srv s;
    memset(&s, 0, sizeof(s));
    s.fd = sv[1];
    s.plan = pl;

    pthread_t th;
    if (pthread_create(&th, NULL, server_half, &s) != 0) {
        close(sv[0]); close(sv[1]);
        return -101;
    }

    g_give_fd = sv[0];
    g_tcp_dial = fake_dial;
    struct transport c;
    int rc = vless_connect(n, &c, 3);
    if (rc == 0) transport_close(&c);
    g_tcp_dial = NULL;

    if (reason && rn) snprintf(reason, rn, "%s", tls13_verify_reason());
    if (ctx_left) *ctx_left = (c.link.tls.rd.ctx_ready ? 1 : 0) + (c.link.tls.wr.ctx_ready ? 1 : 0);

    pthread_join(th, NULL);
    /* What the client sent after the server Finished. vless_connect has returned, so a Finished
     * it sent is already in the socket: read without waiting. */
    g_cfin = 0;
    unsigned char b;
    if (s.fd >= 0 && fcntl(s.fd, F_SETFL, O_NONBLOCK) == 0 && recv(s.fd, &b, 1, MSG_PEEK) > 0) {
        struct dir *d = calloc(1, sizeof(*d));
        g_cfin = d && s.fin_sent ? client_finished(&s, d) : -1;
        if (d && d->ready) sc_aead_free(&d->g);
        free(d);
    }
    if (s.fd >= 0) close(s.fd);
    /* The client's end of the pair is closed by vless_connect itself (or by transport_close on
     * success). If it is not, that is the finding, and the caller's descriptor count shows it. */
    return rc;
}

/* A ws or httpupgrade run through to data: setup, the first data after the 101 answer (it came
 * in ONE TLS record with the answer), the client's reply. 0 if all of it worked; *s holds what
 * the server saw. */
#if defined(STEER_HAVE_X509WRITE)
_Static_assert(sizeof(struct cc_ent) == 64, "a cache entry is 64 bytes");

#define CC_M 1000000ull

static void cc_reset(void) {
    pthread_mutex_lock(&g_cc_mu);
    memset(g_cc, 0, sizeof g_cc);
    g_cc_checked = 0;
    pthread_mutex_unlock(&g_cc_mu);
    g_cc_wall_s = 0;
    g_cc_mono_ms = 0;
}

static int cc_hs(const struct plan *pl, const char *vcn, const char *pcs, char *why, size_t wn) {
    struct vless_node tn;
    node_tls(&tn, "tcp");
    tn.vcn = vcn;
    tn.pcs = pcs;
    return run_case(pl, &tn, why, wn, NULL);
}

static void cc_hex(const unsigned char *d, size_t n, char out[65]) {
    static const char HEX[] = "0123456789abcdef";
    unsigned char h[32];
    sc_hash(SC_SHA256, d, n, h);
    for (int k = 0; k < 32; k++) { out[2 * k] = HEX[h[k] >> 4]; out[2 * k + 1] = HEX[h[k] & 15]; }
    out[64] = '\0';
}

static void t_cc_hit_skips_chain(void) {
    /* catches: no cache (2 checks), or a cache that never hits */
    cc_reset();
    struct plan ok = { .name = "cc ok", .chain = LEAF_OK };
    check("cache: first handshake verifies", 0, cc_hs(&ok, NULL, NULL, NULL, 0));
    check("cache: first handshake checks the chain", 1, (long)g_cc_checked);
    check("cache: second handshake verifies", 0, cc_hs(&ok, NULL, NULL, NULL, 0));
    check("cache: second handshake checks no chain", 1, (long)g_cc_checked);
}

static void t_cc_hit_still_checks_signature(void) {
    /* catches: a hit that returns before check_signature, or a cached CertificateVerify verdict */
    cc_reset();
    struct plan ok = { .name = "cc ok", .chain = LEAF_OK };
    struct plan sig = { .name = "cc sig", .chain = LEAF_OK, .cv_bad_sig = 1 };
    struct plan alg = { .name = "cc alg", .chain = LEAF_OK, .cv_bad_alg = 1 };
    char why[256] = "";
    check("cache hit: good chain verifies", 0, cc_hs(&ok, NULL, NULL, NULL, 0));
    check("cache hit: chain checked once", 1, (long)g_cc_checked);
    check("cache hit: bad signature refused", TLS13_ECERT, cc_hs(&sig, NULL, NULL, why, sizeof why));
    check("cache hit: bad signature was a hit", 1, (long)g_cc_checked);
    check_str("cache hit: bad signature reason", "bad server signature", why);
    check("cache hit: scheme not offered refused", TLS13_ECERT, cc_hs(&alg, NULL, NULL, NULL, 0));
}

static void t_cc_failure_not_cached(void) {
    /* catches: a failed chain remembered */
    cc_reset();
    struct plan name = { .name = "cc name", .chain = LEAF_NAME };
    struct plan self = { .name = "cc self", .chain = LEAF_SELF };
    check("cache: wrong name refused", TLS13_ECERT, cc_hs(&name, NULL, NULL, NULL, 0));
    check("cache: wrong name refused again", TLS13_ECERT, cc_hs(&name, NULL, NULL, NULL, 0));
    check("cache: wrong name checked both times", 2, (long)g_cc_checked);
    check("cache: self-signed refused", TLS13_ECERT, cc_hs(&self, NULL, NULL, NULL, 0));
    check("cache: self-signed refused again", TLS13_ECERT, cc_hs(&self, NULL, NULL, NULL, 0));
    check("cache: self-signed checked both times", 4, (long)g_cc_checked);
}

static void t_cc_name_change_misses(void) {
    /* catches: names left out of the key */
    cc_reset();
    struct plan ok = { .name = "cc ok", .chain = LEAF_OK };
    check("cache names: sni verifies", 0, cc_hs(&ok, NULL, NULL, NULL, 0));
    check("cache names: sni checked", 1, (long)g_cc_checked);
    check("cache names: another vcn refused", TLS13_ECERT, cc_hs(&ok, "other.invalid", NULL, NULL, 0));
    check("cache names: another vcn checked", 2, (long)g_cc_checked);
    check("cache names: a vcn list verifies", 0, cc_hs(&ok, "other.invalid," TLS_SNI, NULL, NULL, 0));
    check("cache names: a vcn list checked", 3, (long)g_cc_checked);
    check("cache names: the same list verifies", 0, cc_hs(&ok, "other.invalid," TLS_SNI, NULL, NULL, 0));
    check("cache names: the same list is a hit", 3, (long)g_cc_checked);
}

static void t_cc_pin_change_misses(void) {
    /* catches: pcs or the anchor kind left out of the key, or the cache consulted before the pin decision */
    char h_root[65], h_name[65], both[140], why[256] = "";
    cc_hex(g_root_der, g_root_n, h_root);
    cc_hex(g_leaf[LEAF_NAME].der, g_leaf[LEAF_NAME].der_n, h_name);
    snprintf(both, sizeof both, "%s,%s", h_root, h_name);
    struct plan rt = { .name = "cc root", .chain = LEAF_OK, .send_root = 1 };
    cc_reset();
    check("cache pin: a chain carrying the trusted root verifies", 0, cc_hs(&rt, NULL, NULL, NULL, 0));
    cc_reset();
    check("cache pin: pinned CA verifies", 0, cc_hs(&rt, NULL, h_root, NULL, 0));
    check("cache pin: pinned CA checked", 1, (long)g_cc_checked);
    check("cache pin: same chain on the process store verifies", 0, cc_hs(&rt, NULL, NULL, NULL, 0));
    check("cache pin: process store is another entry", 2, (long)g_cc_checked);
    check("cache pin: pinned CA again verifies", 0, cc_hs(&rt, NULL, h_root, NULL, 0));
    check("cache pin: pinned CA again is a hit", 2, (long)g_cc_checked);
    check("cache pin: two fingerprints verify", 0, cc_hs(&rt, NULL, both, NULL, 0));
    check("cache pin: another pcs is another entry", 3, (long)g_cc_checked);
    check("cache pin: an unrelated fingerprint refused", TLS13_ECERT, cc_hs(&rt, NULL, h_name, why, sizeof why));
    check_str("cache pin: unrelated fingerprint reason", "matches no pinned fingerprint", why);
    check("cache pin: refused before the cache", 3, (long)g_cc_checked);
}

static void t_cc_key_binds_inputs(void) {
    /* catches: an unordered or unframed key (pieces or strings concatenated without lengths), or a field not hashed */
    const struct leaf *a = &g_leaf[LEAF_OK];
    static unsigned char b[2048], ab[4096];
    memcpy(b, g_root_der, g_root_n);
    struct cert_policy none = { 0 }, pks = { .pks = "ab" }, pc = { .pcs = "c" }, pbc = { .pcs = "bc" };
    unsigned char k0[32], k1[32];
    const unsigned char *d[2] = { a->der, b };
    size_t dn[2] = { a->der_n, g_root_n };
    int rc = cc_key(0, "n", &none, d, dn, 2, k0);
    rc |= cc_key(0, "n", &none, d, dn, 2, k1);
    check("cache key: equal inputs, equal keys", 1, !rc && !memcmp(k0, k1, 32));
    const unsigned char *ds[2] = { b, a->der };
    size_t dns[2] = { g_root_n, a->der_n };
    rc = cc_key(0, "n", &none, ds, dns, 2, k1);
    check("cache key: swapped pieces differ", 1, !rc && memcmp(k0, k1, 32));
    b[g_root_n / 2] ^= 1;
    rc = cc_key(0, "n", &none, d, dn, 2, k1);
    b[g_root_n / 2] ^= 1;
    check("cache key: one flipped byte differs", 1, !rc && memcmp(k0, k1, 32));
    memcpy(ab, a->der, a->der_n);
    ab[a->der_n] = b[0];
    const unsigned char *dm[2] = { ab, b + 1 };
    size_t dnm[2] = { a->der_n + 1, g_root_n - 1 };
    rc = cc_key(0, "n", &none, dm, dnm, 2, k1);
    check("cache key: a moved boundary differs", 1, !rc && memcmp(k0, k1, 32));
    rc = cc_key(0, "n", &pks, d, dn, 2, k1);
    check("cache key: pks differs", 1, !rc && memcmp(k0, k1, 32));
    rc = cc_key(1, "n", &none, d, dn, 2, k1);
    check("cache key: anchor kind differs", 1, !rc && memcmp(k0, k1, 32));
    rc = cc_key(0, "ab", &pc, d, dn, 2, k0);
    rc |= cc_key(0, "a", &pbc, d, dn, 2, k1);
    check("cache key: names and pcs framed apart", 1, !rc && memcmp(k0, k1, 32));
}

static void t_cc_key_too_long_falls_back(void) {
    /* catches: a key built over a truncated length (65,536 hashed as 0), or a key failure that refuses the chain or stores an entry */
    static char big[65537], list[65537];
    memset(big, 'a', 65536);
    big[65536] = '\0';
    const struct leaf *a = &g_leaf[LEAF_OK];
    const unsigned char *d[1] = { a->der };
    size_t dn[1] = { a->der_n };
    unsigned char k[32];
    struct cert_policy pcs = { .pcs = big }, pks = { .pks = big }, none = { 0 };
    check("cache key: 65,536-byte pcs refused", 1, cc_key(0, "n", &pcs, d, dn, 1, k) != 0);
    check("cache key: 65,536-byte pks refused", 1, cc_key(0, "n", &pks, d, dn, 1, k) != 0);
    check("cache key: 65,536-byte names refused", 1, cc_key(0, big, &none, d, dn, 1, k) != 0);
    check("cache key: 65,535-byte names keyed", 0, cc_key(0, big + 1, &none, d, dn, 1, k));
    size_t sn = strlen(TLS_SNI);
    memset(list, ',', 65536 - sn);
    memcpy(list + 65536 - sn, TLS_SNI, sn + 1);
    struct cert_policy vcn = { .vcn = list };
    cc_reset();
    check("cache key failure: chain still verifies", 0, cc_chain(g_roots, NULL, 0, d, dn, 1, list, &vcn, g_cert_roots));
    check("cache key failure: chain checked", 1, (long)g_cc_checked);
    check("cache key failure: chain verifies again", 0, cc_chain(g_roots, NULL, 0, d, dn, 1, list, &vcn, g_cert_roots));
    check("cache key failure: nothing stored", 2, (long)g_cc_checked);
    int used = 0;
    for (int i = 0; i < CC_SLOTS; i++) used += g_cc[i].born != 0;
    check("cache key failure: table empty", 0, used);
}

static void t_cc_window_bounds(void) {
    /* catches: an open/closed bound swapped, notBefore not checked, no TTL, or a TTL counted from the last use */
    cc_reset();
    unsigned char k[32] = { 0 };
    g_cc_mono_ms = CC_M;
    cc_put(k, 1000, 2000);
    g_cc_wall_s = 999;
    check("cache window: before notBefore misses", 0, cc_get(k));
    g_cc_wall_s = 1000;
    check("cache window: at notBefore hits", 1, cc_get(k));
    g_cc_wall_s = 1999;
    check("cache window: a second before notAfter hits", 1, cc_get(k));
    g_cc_wall_s = 2000;
    check("cache window: at notAfter misses", 0, cc_get(k));
    g_cc_mono_ms = CC_M;
    cc_put(k, 1000, 2000);
    g_cc_wall_s = 1500;
    g_cc_mono_ms = CC_M + 3599999;
    check("cache ttl: last millisecond hits", 1, cc_get(k));
    g_cc_mono_ms = CC_M + 3600000;
    check("cache ttl: one hour after the insert misses", 0, cc_get(k));
    cc_reset();
}

static void t_cc_ttl_jitter(void) {
    /* catches: no jitter (all entries of a burst expire together), jitter with the wrong sign, or a fixed TTL */
    cc_reset();
    unsigned char k[32] = { 255 };
    g_cc_wall_s = 1500;
    g_cc_mono_ms = CC_M;
    cc_put(k, 1000, 2000);
    g_cc_mono_ms = CC_M + 3089999;
    check("cache jitter 255: last millisecond hits", 1, cc_get(k));
    g_cc_mono_ms = CC_M + 3090000;
    check("cache jitter 255: expired", 0, cc_get(k));
    k[0] = 1;
    g_cc_mono_ms = CC_M;
    cc_put(k, 1000, 2000);
    g_cc_mono_ms = CC_M + 3597999;
    check("cache jitter 1: last millisecond hits", 1, cc_get(k));
    g_cc_mono_ms = CC_M + 3598000;
    check("cache jitter 1: expired", 0, cc_get(k));
    cc_reset();
}

static void t_cc_expired_entry_reverifies(int64_t w) {
    /* catches: a hit that ignores the wall clock, so an expired chain keeps passing */
    cc_reset();
    struct plan ok = { .name = "cc ok", .chain = LEAF_OK };
    check("cache dates: first handshake verifies", 0, cc_hs(&ok, NULL, NULL, NULL, 0));
    check("cache dates: chain checked", 1, (long)g_cc_checked);
    g_cc_wall_s = w + 6 * 365 * 86400LL;
    check("cache dates: past notAfter verifies on the real clock", 0, cc_hs(&ok, NULL, NULL, NULL, 0));
    check("cache dates: past notAfter is a miss", 2, (long)g_cc_checked);
    g_cc_wall_s = w - 3 * 86400LL;
    check("cache dates: before notBefore verifies on the real clock", 0, cc_hs(&ok, NULL, NULL, NULL, 0));
    check("cache dates: before notBefore is a miss", 3, (long)g_cc_checked);
    cc_reset();
}

static void t_cc_lru(void) {
    /* catches: FIFO instead of LRU, an off-by-one table, or a full table that refuses inserts */
    cc_reset();
    unsigned char k[65][32];
    memset(k, 0, sizeof k);
    for (int i = 0; i < 65; i++) k[i][1] = (unsigned char)i;
    g_cc_wall_s = 1500;
    for (int i = 0; i < 64; i++) { g_cc_mono_ms = CC_M + (uint64_t)i; cc_put(k[i], 1000, 2000); }
    g_cc_mono_ms = CC_M + 64;
    cc_get(k[0]);
    g_cc_mono_ms = CC_M + 65;
    cc_put(k[64], 1000, 2000);
    check("cache lru: the entry used last stays", 1, cc_get(k[0]));
    check("cache lru: the entry used least is gone", 0, cc_get(k[1]));
    check("cache lru: the new entry is in", 1, cc_get(k[64]));
    int kept = 0;
    for (int i = 2; i < 64; i++) kept += cc_get(k[i]);
    check("cache lru: the other 62 stay", 62, kept);
    cc_reset();
    unsigned char a[32] = { 0 }, b[32] = { 0 };
    b[31] = 1;
    g_cc_wall_s = 1500;
    g_cc_mono_ms = CC_M;
    cc_put(a, 1000, 2000);
    check("cache key: the last byte tells keys apart", 0, cc_get(b));
    check("cache key: the stored key still hits", 1, cc_get(a));
    cc_reset();
}

static pthread_barrier_t g_cc_bar;

static void *cc_burst(void *arg) {
    const struct leaf *a = &g_leaf[LEAF_OK];
    const unsigned char *d[1] = { a->der };
    size_t dn[1] = { a->der_n };
    pthread_barrier_wait(&g_cc_bar);
    *(int *)arg = cc_chain(g_roots, NULL, 0, d, dn, 1, TLS_SNI, NULL, g_cert_roots);
    return NULL;
}

static void t_cc_cold_burst_verifies_once(void) {
    /* catches: no re-lookup under the miss lock (8 serial checks), or a missing lock (TSan) */
    cc_reset();
    pthread_t th[8];
    int rc[8], made = 0, bad = 0;
    pthread_barrier_init(&g_cc_bar, NULL, 8);
    for (int i = 0; i < 8; i++) if (pthread_create(&th[i], NULL, cc_burst, &rc[i]) == 0) made++;
    for (int i = 0; i < made; i++) { pthread_join(th[i], NULL); bad += rc[i] != 0; }
    pthread_barrier_destroy(&g_cc_bar);
    check("cache burst: 8 threads started", 8, made);
    check("cache burst: all verified", 0, bad);
    check("cache burst: one chain check", 1, (long)g_cc_checked);
}

static void t_cc_pinned_ca_expires(void) {
    /* catches: a hit that outlives the pinned CA's notAfter, which a full check refuses */
    char h_root[65], why[256] = "";
    cc_hex(g_root_der, g_root_n, h_root);
    struct plan late = { .name = "cc late", .chain = LEAF_LATE, .send_root = 1 };
    cc_reset();
    check("cache pinned CA: verifies", 0, cc_hs(&late, NULL, h_root, NULL, 0));
    check("cache pinned CA: chain checked", 1, (long)g_cc_checked);
    check("cache pinned CA: verifies again", 0, cc_hs(&late, NULL, h_root, NULL, 0));
    check("cache pinned CA: again is a hit", 1, (long)g_cc_checked);
    g_time_shift = 1825 * 86400LL + 43200;
    check("cache pinned CA: refused once the CA expired", TLS13_ECERT, cc_hs(&late, NULL, h_root, why, sizeof why));
    check_str("cache pinned CA: refused as main refuses", "matches no pinned fingerprint", why);
    check("cache pinned CA: the leaf still verifies on the process store", 0, cc_hs(&late, NULL, NULL, NULL, 0));
    g_time_shift = 0;
    cc_reset();
    struct plan early = { .name = "cc early", .chain = LEAF_EARLY, .send_root = 1 };
    char why2[256] = "";
    check("cache pinned CA: early leaf verifies", 0, cc_hs(&early, NULL, h_root, NULL, 0));
    check("cache pinned CA: early leaf again is a hit", 0, cc_hs(&early, NULL, h_root, NULL, 0));
    check("cache pinned CA: early leaf checked once", 1, (long)g_cc_checked);
    g_time_shift = -172800;
    check("cache pinned CA: refused before the CA is valid", TLS13_ECERT, cc_hs(&early, NULL, h_root, why2, sizeof why2));
    check_str("cache pinned CA: refused before validity as main refuses", "matches no pinned fingerprint", why2);
    check("cache pinned CA: the early leaf still verifies on the process store", 0, cc_hs(&early, NULL, NULL, NULL, 0));
    g_time_shift = 0;
    cc_reset();
}

static void t_cc_compressed_same_entry(void) {
    /* catches: a key over the raw message instead of the decompressed pieces */
    cc_reset();
    struct plan ok = { .name = "cc ok", .chain = LEAF_OK };
    struct plan br = { .name = "cc brotli", .chain = LEAF_OK, .compress = 2 };
    check("cache: plain certificate verifies", 0, cc_hs(&ok, NULL, NULL, NULL, 0));
    check("cache: plain certificate checked", 1, (long)g_cc_checked);
    check("cache: brotli certificate verifies", 0, cc_hs(&br, NULL, NULL, NULL, 0));
    check("cache: brotli certificate is a hit", 1, (long)g_cc_checked);
}

static void cc_tests(void) {
    int64_t w = (int64_t)time(NULL);
    t_cc_hit_skips_chain();
    t_cc_hit_still_checks_signature();
    t_cc_failure_not_cached();
    t_cc_name_change_misses();
    t_cc_pin_change_misses();
    t_cc_key_binds_inputs();
    t_cc_key_too_long_falls_back();
    t_cc_window_bounds();
    t_cc_ttl_jitter();
    t_cc_expired_entry_reverifies(w);
    t_cc_lru();
    t_cc_cold_burst_verifies_once();
    t_cc_compressed_same_entry();
    t_cc_pinned_ca_expires();
    cc_reset();
}
#endif

static int run_upg(const struct plan *pl, struct vless_node *n, struct srv *s) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return -100;
    memset(s, 0, sizeof(*s));
    s->fd = sv[1];
    s->plan = pl;
    pthread_t th;
    if (pthread_create(&th, NULL, server_half, s) != 0) { close(sv[0]); close(sv[1]); return -101; }

    g_give_fd = sv[0];
    g_tcp_dial = fake_dial;
    struct transport c;
    int rc = vless_connect(n, &c, 3);
    g_tcp_dial = NULL;
    if (rc == 0 && pl->ed_first) rc = transport_write(&c, (const unsigned char *)"hello", 5);
    if (rc == 0) {
        static unsigned char buf[VLESS_MIN_RECV_CAP];
        size_t got = 0;
        for (int i = 0; i < 50 && !rc && !got; i++) {
            if (!transport_has_data(&c)) {
                struct pollfd p = { .fd = transport_fd(&c), .events = POLLIN, .revents = 0 };
                if (poll(&p, 1, 3000) <= 0) break;
            }
            rc = transport_read(&c, buf, sizeof(buf), &got);
        }
        if (!rc && (got != 5 || memcmp(buf, "FIRST", 5))) rc = -102;
        if (!rc && !pl->ed_first) rc = transport_write(&c, (const unsigned char *)"hello", 5);
        transport_close(&c);
    }
    pthread_join(th, NULL);
    if (s->fd >= 0) close(s->fd);
    return rc;
}

static int run_two(const struct plan *pa, const struct plan *pb, const struct vless_node *n,
                   long *ms, int over[2]) {
    int sp[2][2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp[0]) != 0) return -100;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp[1]) != 0) { close(sp[0][0]); close(sp[0][1]); return -100; }
    static struct srv s[2];
    pthread_t th[2];
    const struct plan *pl[2] = { pa, pb };
    g_meet = 0;
    g_peer_fin = 0;
    int made = 0;
    for (int i = 0; i < 2; i++) {
        memset(&s[i], 0, sizeof s[i]);
        s[i].fd = sp[i][1];
        s[i].plan = pl[i];
        if (pthread_create(&th[i], NULL, server_half, &s[i]) == 0) made++;
    }
    int rc = -101;
    if (made == 2) {
        g_give2[0] = sp[0][0];
        g_give2[1] = sp[1][0];
        g_dial_n = 0;
        g_tcp_dial = fake_dial2;
        int64_t t0 = now_ms();
        struct transport c;
        rc = vless_connect(n, &c, 8);
        *ms = (long)(now_ms() - t0);
        if (rc == 0) transport_close(&c);
        g_tcp_dial = NULL;
    }
    for (int i = 0; i < 2; i++) {
        if (g_give2[i] >= 0) { close(g_give2[i]); g_give2[i] = -1; }
        if (i < made) pthread_join(th[i], NULL);
        if (s[i].fd >= 0) close(s[i].fd);
        over[i] = s[i].overlap;
    }
    return rc;
}

/* base64url without padding: the form of pbk in a node link. */
static void b64url(const unsigned char *in, size_t n, char *out) {
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        unsigned v = (unsigned)in[i] << 16;
        if (i + 1 < n) v |= (unsigned)in[i + 1] << 8;
        if (i + 2 < n) v |= in[i + 2];
        out[o++] = T[(v >> 18) & 63];
        out[o++] = T[(v >> 12) & 63];
        if (i + 1 < n) out[o++] = T[(v >> 6) & 63];
        if (i + 2 < n) out[o++] = T[v & 63];
    }
    out[o] = '\0';
}

/* Does the heap check itself work?
 *
 * A test built WITH the sanitizer but run with ASAN_OPTIONS=detect_leaks=0 would report
 * "nothing left on the heap" on EVERY path: a green test that no longer checks what it was
 * written for. A safeguard that can be turned off by accident must report its own state.
 *
 * The leak is made ON PURPOSE and cleaned up right away. The pointer is hidden by XOR because
 * LeakSanitizer scans the stack and the registers too and would not count a live pointer as a
 * leak. The sanitizer report printed below is part of the check, not a failure. */
static volatile uintptr_t g_hidden;
#define HIDE_MASK ((uintptr_t)0x5a5a5a5a5a5a5a5aULL)

static void heap_check_selftest(void) {
#if defined(__SANITIZE_ADDRESS__)
    void *p = malloc(64);
    if (!p) return;
    memset(p, 0x11, 64);
    g_hidden = (uintptr_t)p ^ HIDE_MASK;
    p = NULL;
    printf("-- an EXPECTED leak report follows: it proves the heap check is on --\n");
    fflush(stdout);
    int seen = LEAK_CHECK();
    printf("-- end of the expected report --\n");
    check("heap check is on (the deliberate leak was seen)", 1, seen);
    free((void *)(g_hidden ^ HIDE_MASK));
    g_hidden = 0;
#endif
}

static int fm_inq(int fd) {
    int v = -1;
    ioctl(fd, FIONREAD, &v);
    return v;
}

static void fm_use(const struct fm_ops *o, int relay) {
    g_fmt_ops = o;
    g_fm_new = o ? fmt_new : NULL;
    g_fm_relay = relay;
}

static int fm_app_keys(struct srv *s, struct dir *cd, struct dir *sd) {
    unsigned char zeros[HLEN] = { 0 }, empty[HLEN], derived[HLEN], master[HLEN], th[HLEN];
    unsigned char c_ap[HLEN], s_ap[HLEN];
    if (sc_hash(SC_SHA256, zeros, 0, empty)) return -1;
    if (xlabel(s->hs, "derived", empty, HLEN, derived, HLEN)) return -1;
    if (sc_hkdf_extract(SC_SHA256, derived, HLEN, zeros, HLEN, master)) return -1;
    tr_snapshot(&s->tr, th);
    if (xlabel(master, "c ap traffic", th, HLEN, c_ap, HLEN)) return -1;
    if (xlabel(master, "s ap traffic", th, HLEN, s_ap, HLEN)) return -1;
    if (client_finished(s, cd) != 1) return -1;
    return dir_set(cd, c_ap) || dir_set(sd, s_ap) ? -1 : 0;
}

static void fm_dirs_free(struct dir *cd, struct dir *sd) {
    if (cd && cd->ready) sc_aead_free(&cd->g);
    if (sd && sd->ready) sc_aead_free(&sd->g);
    free(cd);
    free(sd);
}

static unsigned char g_fmx_up[3000], g_fmx_down[1000], g_fmx_in[4096];

static int fm_read_n(struct transport *c, unsigned char *out, size_t want) {
    static unsigned char buf[VLESS_MIN_RECV_CAP];
    size_t have = 0;
    uint64_t dl = fmr_ms() + 10000;
    while (have < want && fmr_ms() < dl) {
        if (!transport_has_data(c)) {
            struct pollfd p = { .fd = transport_fd(c), .events = POLLIN, .revents = 0 };
            if (poll(&p, 1, 3000) <= 0) return -110;
        }
        size_t got = 0;
        int rc = transport_read(c, buf, sizeof buf, &got);
        if (rc) return rc;
        if (have + got > want) return -111;
        memcpy(out + have, buf, got);
        have += got;
    }
    return have == want ? 0 : -112;
}

enum { FM_RECORDS, FM_DIRECT_RAW, FM_DIRECT_MASKED, FM_TX_DIRECT, FM_DIRECT_REC };

static unsigned char g_fmx_raw[3000];
static unsigned char g_fmx_wire[5 + 100 + 17 + sizeof g_fmx_down];

static int fm_rec_raw(struct transport *c, struct dir *sd, int fd) {
    size_t n = rec_wrap(sd, g_fmx_up, 100, g_fmx_wire);
    if (!n) return -130;
    memcpy(g_fmx_wire + n, g_fmx_down, sizeof g_fmx_down);
    n += sizeof g_fmx_down;
    if (wr_all(fd, g_fmx_wire, n)) return -131;
    for (int i = 0; i < 3000 && fm_inq(transport_fd(c)) < (int)(n * 8 / 6); i++) usleep(1000);
    unsigned char got[100];
    int rc = fm_read_n(c, got, sizeof got);
    if (!rc && memcmp(got, g_fmx_up, sizeof got)) rc = -132;
    if (!rc && !tls13_buffered(&c->link.tls)) rc = -133;
    if (!rc) transport_direct(c);
    return rc;
}

static int fm_data(const struct plan *pl, struct vless_node *n, int how) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) return -100;
    struct timeval tv = { .tv_sec = 3 };
    setsockopt(sv[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    static struct srv s;
    memset(&s, 0, sizeof s);
    s.fd = sv[1];
    s.plan = pl;
    const int tls = strcmp(n->security, "none") != 0;
    pthread_t th;
    if (tls && pthread_create(&th, NULL, server_half, &s)) {
        close(sv[0]);
        close(sv[1]);
        return -101;
    }
    g_give_fd = sv[0];
    g_tcp_dial = fake_dial;
    struct transport c;
    int rc = vless_connect(n, &c, 3);
    g_tcp_dial = NULL;
    if (tls) pthread_join(th, NULL);
    struct dir *cd = calloc(1, sizeof *cd), *sd = calloc(1, sizeof *sd);
    const int up = rc == 0;
    if (!rc && (!cd || !sd || s.rc)) rc = -102;
    if (!rc && tls && fm_app_keys(&s, cd, sd)) rc = -103;
    for (size_t i = 0; i < sizeof g_fmx_up; i++) g_fmx_up[i] = (unsigned char)(i * 13 + 7);
    for (size_t i = 0; i < sizeof g_fmx_down; i++) g_fmx_down[i] = (unsigned char)(i * 29 + 3);
    if (!rc) rc = transport_write(&c, g_fmx_up, sizeof g_fmx_up);
    size_t have = 0;
    int recs = 0;
    while (!rc && have < sizeof g_fmx_up) {
        size_t k = 0;
        unsigned char inner = 0;
        if (tls) {
            if (rec_open(cd, s.fd, g_fmx_in + have, sizeof g_fmx_in - have, &k, &inner) || inner != 0x17) rc = -104;
            recs++;
        } else {
            ssize_t r = read(s.fd, g_fmx_in + have, sizeof g_fmx_up - have);
            if (r <= 0) rc = -104;
            else k = (size_t)r;
        }
        have += k;
    }
    if (!rc && memcmp(g_fmx_in, g_fmx_up, sizeof g_fmx_up)) rc = -105;
    if (!rc && how == FM_TX_DIRECT) {
        if (recs != 2) rc = -120;
        for (size_t i = 0; i < sizeof g_fmx_raw; i++) g_fmx_raw[i] = (unsigned char)(i * 7 + 1);
        if (!rc && g_relay.on) fmrelay_off(&g_relay, 0);
        if (!rc) transport_tx_direct(&c);
        if (!rc) rc = transport_write(&c, g_fmx_raw, sizeof g_fmx_raw);
        size_t got = 0;
        while (!rc && got < sizeof g_fmx_raw) {
            ssize_t r = read(s.fd, g_fmx_in + got, sizeof g_fmx_raw - got);
            if (r <= 0) rc = -121;
            else got += (size_t)r;
        }
        if (!rc && memcmp(g_fmx_in, g_fmx_raw, sizeof g_fmx_raw)) rc = -122;
        struct pollfd pf = { .fd = s.fd, .events = POLLIN, .revents = 0 };
        if (!rc && poll(&pf, 1, 200) != 0) rc = -123;
    }
    if (!rc && how == FM_DIRECT_REC) {
        rc = fm_rec_raw(&c, sd, s.fd);
    } else if (!rc && how != FM_RECORDS && how != FM_TX_DIRECT) {
        if (how == FM_DIRECT_RAW) fmrelay_off(&g_relay, 1);
        transport_direct(&c);
        if (wr_all(s.fd, g_fmx_down, sizeof g_fmx_down)) rc = -106;
    } else if (!rc) {
        if (tls ? rec_seal(sd, s.fd, g_fmx_down, sizeof g_fmx_down) : wr_all(s.fd, g_fmx_down, sizeof g_fmx_down))
            rc = -106;
    }
    if (!rc) rc = fm_read_n(&c, g_fmx_in, sizeof g_fmx_down);
    if (!rc && memcmp(g_fmx_in, g_fmx_down, sizeof g_fmx_down)) rc = -107;
    if (up) transport_close(&c);
    fm_dirs_free(cd, sd);
    close(s.fd);
    fmrelay_join(&g_relay);
    return rc;
}

static int upg_answer(const struct srv *s, char *resp, size_t cap) {
    int k;
    if (s->plan->upg == 1) {
        char key[32] = "", acc[29];
        const char *kp = strstr(s->req, "\r\nSec-WebSocket-Key: ");
        if (!kp) return -1;
        sscanf(kp + 21, "%31[^\r]", key);
        if (ws_accept(key, acc)) return -1;
        k = snprintf(resp, cap, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                     "Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", acc);
        resp[k++] = (char)0x82;
        resp[k++] = 5;
        memcpy(resp + k, "FIRST", 5);
        k += 5;
    } else {
        k = snprintf(resp, cap, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n"
                     "Upgrade: websocket\r\n\r\nFIRST");
    }
    return k;
}

static void *plain_upg(void *arg) {
    struct srv *s = arg;
    s->rc = -1;
    size_t rn = 0;
    while (!strstr(s->req, "\r\n\r\n")) {
        ssize_t r = read(s->fd, s->req + rn, sizeof s->req - 1 - rn);
        if (r <= 0) return NULL;
        rn += (size_t)r;
        s->req[rn] = '\0';
    }
    char resp[512];
    int k = upg_answer(s, resp, sizeof resp);
    if (k < 0 || wr_all(s->fd, (const unsigned char *)resp, (size_t)k)) return NULL;
    unsigned char b[11];
    if (s->plan->upg == 1) {
        if (rd_all(s->fd, b, 11) || b[0] != 0x82 || b[1] != (0x80 | 5)) return NULL;
        for (int i = 0; i < 5; i++) b[6 + i] ^= b[2 + (i & 3)];
        s->got_hello = !memcmp(b + 6, "hello", 5);
        if (s->plan->ed_first) s->got_hello &= strstr(s->req, "\r\nSec-WebSocket-Protocol: aGVsbG8\r\n") != NULL;
        if (wr_all(s->fd, (const unsigned char *)"\x82\x05" "AGAIN", 7)) return NULL;
    } else {
        if (rd_all(s->fd, b, 5)) return NULL;
        s->got_hello = !memcmp(b, "hello", 5);
        if (wr_all(s->fd, (const unsigned char *)"AGAIN", 5)) return NULL;
    }
    s->rc = 0;
    return NULL;
}

static int fm_upg(const struct plan *pl, struct vless_node *n, struct srv *s) {
    if (strcmp(n->security, "none")) {
        int rc = run_upg(pl, n, s);
        fmrelay_join(&g_relay);
        return rc;
    }
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return -100;
    struct timeval tv = { .tv_sec = 3 };
    setsockopt(sv[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    memset(s, 0, sizeof(*s));
    s->fd = sv[1];
    s->plan = pl;
    pthread_t th;
    if (pthread_create(&th, NULL, plain_upg, s) != 0) { close(sv[0]); close(sv[1]); return -101; }
    g_give_fd = sv[0];
    g_tcp_dial = fake_dial;
    struct transport c;
    int rc = vless_connect(n, &c, 3);
    g_tcp_dial = NULL;
    if (rc == 0) {
        unsigned char got[5];
        if (pl->ed_first) rc = transport_write(&c, (const unsigned char *)"hello", 5);
        if (!rc) rc = fm_read_n(&c, got, 5);
        if (!rc && memcmp(got, "FIRST", 5)) rc = -102;
        if (!rc) rc = transport_write(&c, (const unsigned char *)"hello", 5);
        if (!rc) rc = fm_read_n(&c, got, 5);
        if (!rc && memcmp(got, "AGAIN", 5)) rc = -104;
        transport_close(&c);
    }
    pthread_join(th, NULL);
    if (!rc && s->rc) rc = -103;
    close(s->fd);
    fmrelay_join(&g_relay);
    return rc;
}

static void upg_node(struct vless_node *n, const char *sec, const char *type, const char *path) {
    node_reality(n, type);
    snprintf(n->security, sizeof n->security, "%s", sec);
    b64url(g_rs_pub, 32, n->pbk);
    snprintf(n->path, sizeof n->path, "%s", path);
    snprintf(n->http_host, sizeof n->http_host, "%s", "cdn.example");
}

/* catches: one of trsec.c:155, tls13.c:104/147/759/774/887, transport.c:30/56, trupgrade.c:628/726, trws.c:312/343 left on the bare fd */
static void t_fm_x55(void) {
    struct plan ok = { .name = "x55", .reality_ok = 1 };
    struct vless_node rn;
    upg_node(&rn, "reality", "tcp", "");
    int fd0 = fd_count();
    fm_use(NULL, 1);
    check("x55: the relay alone breaks a reality link", 1, fm_data(&ok, &rn, FM_RECORDS) != 0);
    fm_use(&FMT_X55, 1);
    check("x55 reality tcp: data both ways", 0, fm_data(&ok, &rn, FM_RECORDS));
    check("x55 reality tcp: the relay carried it", 1, g_relay.n[0] > 3000 && g_relay.n[1] > 1000);
    struct vless_node pn;
    upg_node(&pn, "none", "tcp", "");
    check("x55 none tcp: data both ways", 0, fm_data(&ok, &pn, FM_RECORDS));
    check("x55 none tcp: the relay carried it", 3000 + 1000, g_relay.n[0] + g_relay.n[1]);
    static const char *ty[] = { "ws", "httpupgrade", "ws" };
    static const char *pa[] = { "/w?ed=0", "/w?ed=2048", "/w?ed=2048" };
    static const char *nm[] = { "ws", "httpupgrade", "ws ed" };
    for (int sec = 0; sec < 2; sec++)
        for (int u = 0; u < 3; u++) {
            struct plan up = { .name = "x55 upg", .reality_ok = 1, .upg = u == 1 ? 2 : 1, .ed_first = u == 2 };
            struct vless_node n;
            upg_node(&n, sec ? "none" : "reality", ty[u], pa[u]);
            static struct srv s;
            char what[96];
            int rc = fm_upg(&up, &n, &s);
            snprintf(what, sizeof what, "x55 %s %s: FIRST read, hello sent", sec ? "none" : "reality", nm[u]);
            check(what, 0, rc);
            snprintf(what, sizeof what, "x55 %s %s: the server read hello", sec ? "none" : "reality", nm[u]);
            check(what, 1, s.got_hello);
            snprintf(what, sizeof what, "x55 %s %s: the relay carried it", sec ? "none" : "reality", nm[u]);
            check(what, 1, g_relay.n[0] > 0 && g_relay.n[1] > 0);
        }
    fm_use(NULL, 0);
    check("x55: descriptor count restored", fd0, fd_count());
    check("x55: nothing left on the heap", 0, LEAK_CHECK());
}

/* catches: a socket EPROTO on an unmasked link reported as the mask's error */
static void t_lk_err_unmasked(void) {
    struct tr_link l;
    memset(&l, 0, sizeof l);
    errno = EPROTO;
    check("unmasked link, EPROTO: a plain I/O error", TR_EIO, tr_lk_err(&l, -1));
    check("unmasked link, EOF: closed", TR_ECLOSED, tr_lk_err(&l, 0));
}

/* catches: tr_link_read passing direct=0, or bypassing a non-splice layer */
static void t_fm_direct(void) {
    struct plan ok = { .name = "direct", .reality_ok = 1 };
    struct vless_node rn;
    upg_node(&rn, "reality", "tcp", "");
    int fd0 = fd_count();
    fm_use(&FMT_X55, 1);
    check("direct, splice layer: raw bytes read past it", 0, fm_data(&ok, &rn, FM_DIRECT_RAW));
    fm_use(&FMT_X55_NOSPLICE, 1);
    check("direct, non-splice layer: bytes still read through it", 0, fm_data(&ok, &rn, FM_DIRECT_MASKED));
    fm_use(NULL, 0);
    check("direct: descriptor count restored", fd0, fd_count());
    check("direct: nothing left on the heap", 0, LEAK_CHECK());
}

static int can_tx(const struct plan *pl, struct vless_node *n, int enc) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) return -100;
    struct timeval tv = { .tv_sec = 3 };
    setsockopt(sv[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    static struct srv s;
    memset(&s, 0, sizeof s);
    s.fd = sv[1];
    s.plan = pl;
    pthread_t th;
    if (pthread_create(&th, NULL, server_half, &s)) {
        close(sv[0]);
        close(sv[1]);
        return -101;
    }
    g_give_fd = sv[0];
    g_tcp_dial = fake_dial;
    struct transport c;
    int rc = vless_connect(n, &c, 3);
    g_tcp_dial = NULL;
    pthread_join(th, NULL);
    if (!rc) {
        struct venc *e = c.enc;
        if (enc) c.enc = (struct venc *)&s;
        rc = transport_can_tx_direct(&c);
        c.enc = e;
        transport_close(&c);
    } else {
        rc = -102;
    }
    close(s.fd);
    fmrelay_join(&g_relay);
    return rc;
}

/* catches: tr_link_write sealing after the switch, the raw write going through a splice layer, or the gate ignoring enc */
static void t_tx_direct(void) {
    struct plan ok = { .name = "tx direct", .reality_ok = 1 };
    struct vless_node rn;
    upg_node(&rn, "reality", "tcp", "");
    int fd0 = fd_count();
    fm_use(NULL, 0);
    check("tx direct, unmasked: raw bytes after the switch", 0, fm_data(&ok, &rn, FM_TX_DIRECT));
    check("tx direct, unmasked: may switch", 1, can_tx(&ok, &rn, 0));
    check("tx direct, under encryption: may not switch", 0, can_tx(&ok, &rn, 1));
    fm_use(&FMT_X55, 1);
    check("tx direct, splice layer: raw bytes past it", 0, fm_data(&ok, &rn, FM_TX_DIRECT));
    check("tx direct, splice layer: may switch", 1, can_tx(&ok, &rn, 0));
    fm_use(&FMT_X55_NOSPLICE, 1);
    check("tx direct, non-splice layer: may switch", 1, can_tx(&ok, &rn, 0));
    fm_use(NULL, 0);
    static const struct { const char *what; const struct transport_ops *fr; int plain; int want; } k[] = {
        { "tx direct, raw tcp: may switch", &tr_tcp, 0, 1 },
        { "tx direct, security none: may not switch", &tr_tcp, 1, 0 },
        { "tx direct, ws: may not switch", &tr_ws, 0, 0 },
        { "tx direct, grpc: may not switch", &tr_grpc, 0, 0 },
        { "tx direct, httpupgrade: may not switch", &tr_httpupgrade, 0, 0 },
        { "tx direct, xhttp: may not switch", &tr_xhttp, 0, 0 },
    };
    for (size_t i = 0; i < sizeof k / sizeof k[0]; i++) {
        static struct transport t;
        memset(&t, 0, sizeof t);
        t.fr = k[i].fr;
        if (t.fr != &tr_xhttp) t.link.plain = k[i].plain;
        check(k[i].what, k[i].want, transport_can_tx_direct(&t));
    }
    check("tx direct: descriptor count restored", fd0, fd_count());
    check("tx direct: nothing left on the heap", 0, LEAK_CHECK());
}

static void *silent_half(void *arg) {
    struct srv *s = arg;
    unsigned char b[4096];
    while (read(s->fd, b, sizeof b) > 0) {}
    return NULL;
}

/* catches: the chain leaked on link_drop or the retry */
static void t_fm_free_paths(void) {
    struct vless_node node;
    node_reality(&node, "tcp");
    static const struct plan pl[] = {
        { .name = "hangup", .hangup = 1 },
        { .name = "bad finished", .bad_finished = 1 },
        { .name = "no key share", .no_keyshare = 1 },
    };
    static const int want[] = { TLS13_ECLOSED, TLS13_EFINISHED, TLS13_ENOKEYSHARE };
    fm_use(&FMT_X55, 1);
    for (size_t i = 0; i < sizeof pl / sizeof *pl; i++) {
        char what[96];
        int fd0 = fd_count();
        int rc = run_case(&pl[i], &node, NULL, 0, NULL);
        fmrelay_join(&g_relay);
        snprintf(what, sizeof what, "free paths, %s: the masked handshake fails there", pl[i].name);
        check(what, want[i], rc);
        snprintf(what, sizeof what, "free paths, %s: descriptor count restored", pl[i].name);
        check(what, fd0, fd_count());
        snprintf(what, sizeof what, "free paths, %s: nothing left on the heap", pl[i].name);
        check(what, 0, LEAK_CHECK());
    }
    struct vless_node bad;
    node_reality(&bad, "tcp");
    snprintf(bad.pbk, sizeof bad.pbk, "%s", "!!");
    for (int k = 0; k < 2; k++) {
        int fd0 = fd_count(), sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) break;
        fm_use(k ? &FMT_HSFAIL : &FMT_X55, 0);
        g_give_fd = sv[0];
        g_tcp_dial = fake_dial;
        struct transport c;
        int rc = vless_connect(k ? &node : &bad, &c, 1);
        g_tcp_dial = NULL;
        close(sv[1]);
        check(k ? "free paths, the layer's handshake fails: TR_EMASK" : "free paths, the hello cannot be built",
              k ? TR_EMASK : REALITY_EBADKEY, rc);
        check(k ? "free paths, the layer's handshake fails: descriptor count restored"
                : "free paths, the hello cannot be built: descriptor count restored", fd0, fd_count());
        check(k ? "free paths, the layer's handshake fails: nothing left on the heap"
                : "free paths, the hello cannot be built: nothing left on the heap", 0, LEAK_CHECK());
    }
    fm_use(&FMT_X55, 1);
    struct vless_node rn;
    node_reality(&rn, "tcp");
    snprintf(rn.host, sizeof rn.host, "%s", "retry.invalid");
    int sv[2];
    int fd0 = fd_count();
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
        struct timeval tv = { .tv_sec = 5 };
        setsockopt(sv[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        static struct srv s;
        memset(&s, 0, sizeof s);
        s.fd = sv[1];
        pthread_t th;
        pthread_create(&th, NULL, silent_half, &s);
        g_give_fd = sv[0];
        g_tcp_dial = fake_dial;
        struct transport c;
        int rc = vless_connect(&rn, &c, 1);
        g_tcp_dial = NULL;
        check("free paths, nopq retry: the silent node times out", TLS13_ETIMEOUT, rc);
        pthread_join(th, NULL);
        close(sv[1]);
        fmrelay_join(&g_relay);
    }
    fm_use(NULL, 0);
    check("free paths, nopq retry: descriptor count restored", fd0, fd_count());
    check("free paths, nopq retry: nothing left on the heap", 0, LEAK_CHECK());
}

/* catches: transport_has_data not asking the chain */
static void t_fm_pending_ready(void) {
    struct plan ok = { .name = "hold", .reality_ok = 1 };
    struct vless_node rn;
    upg_node(&rn, "reality", "tcp", "");
    int fd0 = fd_count();
    fm_use(&FMT_HOLD, 0);
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) return;
    struct timeval tv = { .tv_sec = 3 };
    setsockopt(sv[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    static struct srv s;
    memset(&s, 0, sizeof s);
    s.fd = sv[1];
    s.plan = &ok;
    pthread_t th;
    pthread_create(&th, NULL, server_half, &s);
    g_give_fd = sv[0];
    g_tcp_dial = fake_dial;
    struct transport c;
    int rc = vless_connect(&rn, &c, 3);
    g_tcp_dial = NULL;
    pthread_join(th, NULL);
    check("pending: connected through a holding layer", 0, rc);
    struct dir *cd = calloc(1, sizeof *cd), *sd = calloc(1, sizeof *sd);
    check("pending: server keys", 0, !rc && cd && sd ? fm_app_keys(&s, cd, sd) : -1);
    if (!rc) {
        check("pending: two records written", 0,
              rec_seal(sd, s.fd, (const unsigned char *)"abc", 3) || rec_seal(sd, s.fd, (const unsigned char *)"def", 3));
        int fd = transport_fd(&c);
        for (int i = 0; i < 300 && fm_inq(fd) < 50; i++) usleep(1000);
        check("pending: both records in the socket", 50, fm_inq(fd));
        unsigned char got[3] = { 0 };
        check("pending: the first record read", 0, fm_read_n(&c, got, 3));
        check("pending: abc", 0, memcmp(got, "abc", 3));
        check("pending: the socket is empty", 0, fm_inq(fd));
        check("pending: one byte held by the chain", 1, fm_pending(c.link.tls.fm));
        check("pending: transport_has_data asks the chain", 1, transport_has_data(&c));
        size_t n = 0;
        static unsigned char buf[VLESS_MIN_RECV_CAP];
        check("pending: the second record read without the socket", 0, transport_read(&c, buf, sizeof buf, &n));
        check("pending: def", 1, n == 3 && !memcmp(buf, "def", 3));
        transport_close(&c);
    }
    fm_dirs_free(cd, sd);
    close(s.fd);
    fm_use(NULL, 0);
    check("pending: descriptor count restored", fd0, fd_count());
    check("pending: nothing left on the heap", 0, LEAK_CHECK());
}

/* catches: a layer's read error reported as an I/O error, or a node whose mask cannot be built dialled unmasked */
static void t_fm_mask_error(void) {
    struct vless_node rn;
    upg_node(&rn, "reality", "tcp", "");
    int fd0 = fd_count();
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) return;
    struct timeval tv = { .tv_sec = 3 };
    setsockopt(sv[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    static struct srv s;
    struct plan ok = { .name = "bad read", .reality_ok = 1 };
    memset(&s, 0, sizeof s);
    s.fd = sv[1];
    s.plan = &ok;
    pthread_t th;
    pthread_create(&th, NULL, server_half, &s);
    fm_use(&FMT_BAD, 0);
    g_give_fd = sv[0];
    g_tcp_dial = fake_dial;
    struct transport c;
    int rc = vless_connect(&rn, &c, 3);
    g_tcp_dial = NULL;
    fm_use(NULL, 0);
    check("mask error: a layer's read error fails the handshake as TR_EMASK", TR_EMASK, rc);
    check_str("mask error: the text names the layer's reason", "finalmask: test: bad read", transport_strerror(rc));
    shutdown(sv[1], SHUT_RDWR);
    pthread_join(th, NULL);
    close(sv[1]);
    rn.fm = "{\"tcp\":[{\"type\":";
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
        g_give_fd = sv[0];
        g_tcp_dial = fake_dial;
        rc = vless_connect(&rn, &c, 3);
        g_tcp_dial = NULL;
        check("mask refused: TR_EMASK", TR_EMASK, rc);
        check("mask refused: never dialled", sv[0], g_give_fd);
        check_str("mask refused: the text says why", "finalmask: the node's mask does not parse", transport_strerror(rc));
        g_give_fd = -1;
        close(sv[0]);
        close(sv[1]);
    }
    check("mask error: descriptor count restored", fd0, fd_count());
    check("mask error: nothing left on the heap", 0, LEAK_CHECK());
}

#define SD_NODE "{\"tcp\":[{\"type\":\"sudoku\",\"settings\":{\"password\":\"p\",\"paddingMin\":0,\"paddingMax\":0}}]}"

enum { SDK_TCP, SDK_VISION, SDK_WS, SDK_WS_ED, SDK_HU, SDK_N };

static const char *const g_sdk_name[SDK_N] = { "none tcp", "vision direct", "plain ws", "plain ws ed", "plain httpupgrade" };

struct sdup { struct srv *s; int go, rc; const unsigned char *d; size_t n; };

static void *sd_upg_half(void *a) {
    struct sdup *u = a;
    struct srv *s = u->s;
    u->rc = -1;
    size_t rn = 0;
    while (!strstr(s->req, "\r\n\r\n")) {
        ssize_t r = read(s->fd, s->req + rn, sizeof s->req - 1 - rn);
        if (r <= 0) return NULL;
        rn += (size_t)r;
        s->req[rn] = '\0';
    }
    char resp[512];
    int k = upg_answer(s, resp, sizeof resp);
    if (k < 0 || wr_all(s->fd, (const unsigned char *)resp, (size_t)k)) return NULL;
    uint64_t dl = fmr_ms() + 10000;
    while (!__atomic_load_n(&u->go, __ATOMIC_SEQ_CST) && fmr_ms() < dl) poll(NULL, 0, 1);
    if (!__atomic_load_n(&u->go, __ATOMIC_SEQ_CST) || !u->d) return NULL;
    unsigned char h[4] = { 0x82, (unsigned char)u->n, 0, 0 };
    size_t hn = 2;
    if (u->n >= 126) {
        h[1] = 126;
        h[2] = (unsigned char)(u->n >> 8);
        h[3] = (unsigned char)u->n;
        hn = 4;
    }
    if (s->plan->upg == 1 && wr_all(s->fd, h, hn)) return NULL;
    if (wr_all(s->fd, u->d, u->n)) return NULL;
    u->rc = 0;
    return NULL;
}

static int sd_read(struct transport *c, unsigned char *out, size_t want) {
    static unsigned char buf[VLESS_MIN_RECV_CAP];
    size_t have = 0;
    uint64_t dl = fmr_ms() + 15000;
    while (have < want && fmr_ms() < dl) {
        if (!transport_has_data(c)) {
            struct pollfd p = { .fd = transport_fd(c), .events = POLLIN, .revents = 0 };
            if (poll(&p, 1, 100) <= 0) continue;
        }
        size_t got = 0;
        int rc = transport_read(c, buf, sizeof buf, &got);
        if (rc) return rc;
        if (have + got > want) return -111;
        memcpy(out + have, buf, got);
        have += got;
    }
    return have == want ? 0 : -112;
}

struct sdres { int rc, zrc; size_t zgot; uint64_t zms; long zinq; };

static void sd_zero(struct transport *c, struct sdres *o) {
    static unsigned char buf[VLESS_MIN_RECV_CAP];
    uint64_t dl = fmr_ms() + 3000;
    while (!__atomic_load_n(&g_relay.sd_padded, __ATOMIC_SEQ_CST) && fmr_ms() < dl) poll(NULL, 0, 1);
    if (!__atomic_load_n(&g_relay.sd_padded, __ATOMIC_SEQ_CST)) {
        o->rc = -130;
        return;
    }
    uint64_t t0 = fmr_ms();
    o->zgot = 99;
    o->zrc = transport_read(c, buf, sizeof buf, &o->zgot);
    o->zms = fmr_ms() - t0;
    int q = -1;
    o->zinq = ioctl(transport_fd(c), FIONREAD, &q) ? -1 : q;
}

static unsigned char g_sd_down[2048];

static void sd_case(int kind, int mode, struct sdres *o) {
    memset(o, 0, sizeof *o);
    o->zrc = -1;
    static const char *const ty[SDK_N] = { "tcp", "tcp", "ws", "ws", "httpupgrade" };
    static const char *const pa[SDK_N] = { "", "", "/w?ed=0", "/w?ed=2048", "/w" };
    const int upg = kind >= SDK_WS;
    const int first_pad = mode == FMR_SD_PAD && kind == SDK_WS_ED;
    struct plan pl = { .name = "sd", .reality_ok = 1, .upg = kind == SDK_HU ? 2 : upg, .ed_first = kind == SDK_WS_ED };
    struct vless_node n;
    upg_node(&n, kind == SDK_VISION ? "reality" : "none", ty[kind], pa[kind]);
    n.fm = SD_NODE;
    const struct fm_cfg *cf = fm_cfg_get(SD_NODE);
    g_fmr_sd = cf && cf->n == 1 ? sd_tables(&cf->m[0].u.sd) : NULL;
    g_fmr_mode = first_pad ? FMR_SD_PAD : FMR_SD_PLAIN;
    if (!g_fmr_sd) {
        o->rc = -99;
        return;
    }
    for (size_t i = 0; i < sizeof g_sd_down; i++) g_sd_down[i] = (unsigned char)(i * 37 + (i >> 8) + 5);
    const size_t dn = mode == FMR_SD_DRIP ? sizeof g_sd_down : 5;
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
        o->rc = -100;
        return;
    }
    struct timeval tv = { .tv_sec = 3 };
    setsockopt(sv[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    static struct srv s;
    memset(&s, 0, sizeof s);
    s.fd = sv[1];
    s.plan = &pl;
    struct sdup u = { &s, 0, 0, g_sd_down, dn };
    pthread_t th;
    int th_on = 0;
    if (kind == SDK_VISION) th_on = !pthread_create(&th, NULL, server_half, &s);
    else if (upg) th_on = !pthread_create(&th, NULL, sd_upg_half, &u);
    fm_use(NULL, 1);
    g_give_fd = sv[0];
    g_tcp_dial = fake_dial;
    struct transport c;
    int rc = vless_connect(&n, &c, 3);
    g_tcp_dial = NULL;
    const int up = rc == 0;
    if (kind == SDK_VISION && th_on) {
        pthread_join(th, NULL);
        th_on = 0;
        if (!rc && s.rc) rc = -101;
    }
    unsigned char got[5];
    if (!rc && kind == SDK_WS_ED) rc = transport_write(&c, (const unsigned char *)"hello", 5);
    if (!rc && first_pad) {
        sd_zero(&c, o);
        rc = o->rc;
    }
    if (g_relay.on) fmrelay_go(&g_relay);
    if (!rc && upg) rc = sd_read(&c, got, 5);
    if (!rc && upg && memcmp(got, "FIRST", 5)) rc = -102;
    if (!rc && kind == SDK_VISION) transport_direct(&c);
    if (!rc && mode != FMR_SD_PLAIN && !first_pad) fmrelay_sd(&g_relay, mode);
    if (!rc && upg) __atomic_store_n(&u.go, 1, __ATOMIC_SEQ_CST);
    else if (!rc && wr_all(s.fd, g_sd_down, dn)) rc = -103;
    if (!rc && mode == FMR_SD_PAD && !first_pad) {
        sd_zero(&c, o);
        rc = o->rc;
    }
    if (g_relay.on) fmrelay_go(&g_relay);
    static unsigned char in[sizeof g_sd_down];
    if (!rc) rc = sd_read(&c, in, dn);
    if (!rc && memcmp(in, g_sd_down, dn)) rc = -104;
    if (up) transport_close(&c);
    __atomic_store_n(&u.go, 1, __ATOMIC_SEQ_CST);
    if (th_on) pthread_join(th, NULL);
    if (!rc && upg && u.rc) rc = -105;
    close(s.fd);
    fmrelay_join(&g_relay);
    fm_use(NULL, 0);
    g_fmr_sd = NULL;
    g_fmr_mode = FMR_SD_PLAIN;
    o->rc = rc;
}

static void t_fm_sd_pad_silent(void) {
    /* catches: a data-phase read site mapping a zero-yield EINTR to TR_EIO */
    int fd0 = fd_count();
    for (int k = 0; k < SDK_N; k++) {
        struct sdres o;
        char what[128];
        sd_case(k, FMR_SD_PAD, &o);
        snprintf(what, sizeof what, "sd pad silent %s: the read after the pad, rc 0", g_sdk_name[k]);
        check(what, 0, o.zrc);
        snprintf(what, sizeof what, "sd pad silent %s: got 0", g_sdk_name[k]);
        check(what, 0, (long)o.zgot);
        snprintf(what, sizeof what, "sd pad silent %s: within 100 ms", g_sdk_name[k]);
        check(what, 1, o.zms < 100);
        snprintf(what, sizeof what, "sd pad silent %s: the pad was read", g_sdk_name[k]);
        check(what, 0, o.zinq);
        snprintf(what, sizeof what, "sd pad silent %s: the next bytes decode", g_sdk_name[k]);
        check(what, 0, o.rc);
    }
    check("sd pad silent: descriptor count restored", fd0, fd_count());
    check("sd pad silent: nothing left on the heap", 0, LEAK_CHECK());
}

static void t_fm_sd_drip(void) {
    /* catches: a zero-yield read in the data phase cutting the flow or losing a byte */
    int fd0 = fd_count();
    for (int k = 0; k < SDK_N; k++) {
        struct sdres o;
        char what[128];
        sd_case(k, FMR_SD_DRIP, &o);
        snprintf(what, sizeof what, "sd drip %s: 2 KiB down intact", g_sdk_name[k]);
        check(what, 0, o.rc);
    }
    check("sd drip: descriptor count restored", fd0, fd_count());
    check("sd drip: nothing left on the heap", 0, LEAK_CHECK());
}

#if defined(STEER_HAVE_X509WRITE)
static void t_fm_sd(void) {
    /* catches: a handshake, record, raw, upgrade or ws read or write bypassing the mask */
    struct plan ok = { .name = "sd", .reality_ok = 1 };
    struct plan tok = { .name = "sd tls", .chain = LEAF_OK };
    int fd0 = fd_count();
    g_fmr_sd = fmr_sd_of(SD_NODE);
    check("sd: the relay's tables", 1, g_fmr_sd != NULL);
    fm_use(NULL, 1);
    struct vless_node rn;
    upg_node(&rn, "reality", "tcp", "");
    check("sd: the relay alone breaks a reality link", 1, fm_data(&ok, &rn, FM_RECORDS) != 0);
    rn.fm = SD_NODE;
    check("sd reality tcp: data both ways", 0, fm_data(&ok, &rn, FM_RECORDS));
    check("sd reality tcp: the relay carried it", 1, g_relay.n[0] > 4 * 3000 && g_relay.n[1] > 1000);
    struct vless_node tn;
    node_tls(&tn, "tcp");
    tn.fm = SD_NODE;
    check("sd tls tcp: data both ways", 0, fm_data(&tok, &tn, FM_RECORDS));
    check("sd tls tcp: the relay carried it", 1, g_relay.n[0] > 4 * 3000 && g_relay.n[1] > 1000);
    struct vless_node pn;
    upg_node(&pn, "none", "tcp", "");
    pn.fm = SD_NODE;
    check("sd none tcp: data both ways", 0, fm_data(&ok, &pn, FM_RECORDS));
    check("sd none tcp: four hints a byte up, the bytes down", 1, g_relay.n[0] == 4 * 3000 && g_relay.n[1] == 1000);
    static const char *ty[] = { "ws", "httpupgrade", "ws" };
    static const char *pa[] = { "/w?ed=0", "/w?ed=2048", "/w?ed=2048" };
    static const char *nm[] = { "ws", "httpupgrade", "ws ed" };
    for (int sec = 0; sec < 2; sec++)
        for (int u = 0; u < 3; u++) {
            struct plan up = { .name = "sd upg", .reality_ok = 1, .upg = u == 1 ? 2 : 1, .ed_first = u == 2 };
            struct vless_node n;
            upg_node(&n, sec ? "none" : "reality", ty[u], pa[u]);
            n.fm = SD_NODE;
            static struct srv s;
            char what[96];
            int rc = fm_upg(&up, &n, &s);
            snprintf(what, sizeof what, "sd %s %s: FIRST read, hello sent", sec ? "none" : "reality", nm[u]);
            check(what, 0, rc);
            snprintf(what, sizeof what, "sd %s %s: the server read hello", sec ? "none" : "reality", nm[u]);
            check(what, 1, s.got_hello);
            size_t rq = strnlen(s.req, sizeof s.req);
            snprintf(what, sizeof what, "sd %s %s: the request is at least its bare lines", sec ? "none" : "reality", nm[u]);
            check(what, 1, rq >= 38);
            snprintf(what, sizeof what, "sd %s %s: the relay carried it, four hints a byte", sec ? "none" : "reality", nm[u]);
            check(what, 1, g_relay.n[0] >= 4 * (long)(rq + 5) && g_relay.n[1] > 0);
        }
    g_fmr_mode = FMR_SD_DRIP;
    check("sd reality tcp, drip through the handshake: data both ways", 0, fm_data(&ok, &rn, FM_RECORDS));
    check("sd reality tcp, drip: the relay carried it", 1, g_relay.n[0] > 4 * 3000 && g_relay.n[1] > 1000);
    g_fmr_mode = FMR_SD_PLAIN;
    g_fmr_sd = NULL;
    fm_use(NULL, 0);
    check("sd: descriptor count restored", fd0, fd_count());
    check("sd: nothing left on the heap", 0, LEAK_CHECK());
}
#endif

static void t_fm_sd_direct_rx(void) {
    /* catches: direct reads skipping a non-splice layer, or the record buffer's raw start dropped */
    struct plan ok = { .name = "sd direct", .reality_ok = 1 };
    struct vless_node rn;
    upg_node(&rn, "reality", "tcp", "");
    rn.fm = SD_NODE;
    int fd0 = fd_count();
    g_fmr_sd = fmr_sd_of(SD_NODE);
    check("sd direct: the relay's tables", 1, g_fmr_sd != NULL);
    fm_use(NULL, 1);
    check("sd direct: the raw downlink decoded", 0, fm_data(&ok, &rn, FM_DIRECT_MASKED));
    check("sd direct: the relay carried it", 1, g_relay.n[0] > 4 * 3000 && g_relay.n[1] > 1000);
    check("sd direct: the buffered raw start decoded first", 0, fm_data(&ok, &rn, FM_DIRECT_REC));
    check("sd direct, buffered: the relay carried it", 1, g_relay.n[0] > 4 * 3000 && g_relay.n[1] > 1000 + 100);
    g_fmr_sd = NULL;
    fm_use(NULL, 0);
    check("sd direct: descriptor count restored", fd0, fd_count());
    check("sd direct: nothing left on the heap", 0, LEAK_CHECK());
}

static void t_sd_can_tx(void) {
    /* catches: a mask condition left on the switch */
    static const char frsd[] = "{\"tcp\":[{\"type\":\"fragment\",\"settings\":{\"packets\":\"1-100\",\"length\":10}},"
                               "{\"type\":\"sudoku\",\"settings\":{\"password\":\"p\"}}]}";
    static const char sdhc[] = "{\"tcp\":[{\"type\":\"sudoku\",\"settings\":{\"password\":\"p\"}},"
                               "{\"type\":\"header-custom\",\"settings\":{\"clients\":[[{\"packet\":[1]}]]}}]}";
    static const struct { const char *what; const char *fm; const struct transport_ops *fr; int enc; int want; } k[] = {
        { "sd can tx, sudoku: may switch", SD_NODE, &tr_tcp, 0, 1 },
        { "sd can tx, fragment and sudoku: may switch", frsd, &tr_tcp, 0, 1 },
        { "sd can tx, sudoku and header-custom: may switch", sdhc, &tr_tcp, 0, 1 },
        { "sd can tx, sudoku under encryption: may not switch", SD_NODE, &tr_tcp, 1, 0 },
        { "sd can tx, sudoku on ws: may not switch", SD_NODE, &tr_ws, 0, 0 },
    };
    for (size_t i = 0; i < sizeof k / sizeof k[0]; i++) {
        static struct transport t;
        memset(&t, 0, sizeof t);
        t.fr = k[i].fr;
        if (k[i].enc) t.enc = (struct venc *)&t;
        int rc = fm_link_open(k[i].fm, &t.link.tls.fm);
        check(k[i].what, k[i].want, rc ? -1 : transport_can_tx_direct(&t));
        fm_link_free(t.link.tls.fm);
    }
    check("sd can tx: nothing left on the heap", 0, LEAK_CHECK());
}

#define SD_FRAG "{\"tcp\":[{\"type\":\"fragment\",\"settings\":{\"packets\":\"1-100\",\"lengths\":[2000,500],\"delays\":[0,1000]}}," \
                "{\"type\":\"sudoku\",\"settings\":{\"password\":\"p\",\"paddingMin\":0,\"paddingMax\":0}}]}"

static const unsigned char g_sdt_uuid[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

struct sdt { int cmd[2], frames, sw, raw, next; long wire; };

static size_t sdt_sh(unsigned char *o) {
    size_t i = 0;
    static const unsigned char h[11] = { 0x16, 0x03, 0x03, 0x00, 0x7a, 0x02, 0x00, 0x00, 0x76, 0x03, 0x03 };
    memcpy(o, h, sizeof h);
    i += sizeof h;
    memset(o + i, 0x11, 32);
    i += 32;
    o[i++] = 0x20;
    memset(o + i, 0x22, 32);
    i += 32;
    static const unsigned char t[19] = { 0x13, 0x01, 0x00, 0x00, 0x2e, 0x00, 0x2b, 0x00, 0x02, 0x03,
                                         0x04, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20 };
    memcpy(o + i, t, sizeof t);
    i += sizeof t;
    memset(o + i, 0x33, 32);
    return i + 32;
}

static int sdt_frames(struct dir *cd, int fd, struct sdt *o) {
    static unsigned char b[1 << 14];
    size_t have = 0, at = 16;
    while (o->frames < 2) {
        size_t k = 0;
        unsigned char inner = 0;
        if (rec_open(cd, fd, b + have, sizeof b - have, &k, &inner) || inner != 0x17) return -140;
        have += k;
        while (o->frames < 2 && at + 5 <= have) {
            size_t len = (size_t)b[at + 1] << 8 | b[at + 2], pad = (size_t)b[at + 3] << 8 | b[at + 4];
            if (at + 5 + len + pad > have) break;
            o->cmd[o->frames++] = b[at];
            at += 5 + len + pad;
        }
    }
    return have == at && !memcmp(b, g_sdt_uuid, 16) ? 0 : -141;
}

static int sdt_send(struct transport *c, struct vision *v, const unsigned char *d, size_t n) {
    static unsigned char out[4096];
    size_t on = 0;
    if (vision_wrap(v, d, n, transport_can_tx_direct(c), out, sizeof out, &on)) return -150;
    return transport_write(c, out, on);
}

static void sdt_run(const char *fm, int loop, struct sdt *o) {
    struct plan ok = { .name = "sd tx", .reality_ok = 1 };
    struct vless_node rn;
    upg_node(&rn, "reality", "tcp", "");
    rn.fm = fm;
    memset(o, 0, sizeof *o);
    o->cmd[0] = o->cmd[1] = -1;
    o->raw = -1;
    o->next = -2;
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) return;
    struct timeval tv = { .tv_sec = 3 };
    setsockopt(sv[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    static struct srv s;
    memset(&s, 0, sizeof s);
    s.fd = sv[1];
    s.plan = &ok;
    pthread_t th;
    if (pthread_create(&th, NULL, server_half, &s)) {
        close(sv[0]);
        close(sv[1]);
        return;
    }
    fm_use(NULL, 1);
    g_give_fd = sv[0];
    g_tcp_dial = fake_dial;
    struct transport c;
    int rc = vless_connect(&rn, &c, 3);
    g_tcp_dial = NULL;
    pthread_join(th, NULL);
    const int up = rc == 0;
    struct dir *cd = calloc(1, sizeof *cd), *sd = calloc(1, sizeof *sd);
    if (!rc && (!cd || !sd || s.rc || fm_app_keys(&s, cd, sd))) rc = -102;
    struct vision v;
    vision_init(&v, g_sdt_uuid);
    static const unsigned char ch[10] = { 0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00 };
    unsigned char sh[160], app[37] = { 0x17, 0x03, 0x03, 0x00, 0x20 };
    memset(app + 5, 0x44, 32);
    if (!rc) rc = sdt_send(&c, &v, ch, sizeof ch);
    vision_filter(&v, sh, sdt_sh(sh));
    if (!rc) rc = sdt_send(&c, &v, app, sizeof app);
    if (!rc) rc = sdt_frames(cd, s.fd, o);
    o->sw = v.tx_switch;
    if (!rc && v.tx_switch) transport_tx_direct(&c);
    if (!rc && loop) {
        transport_set_loop(&c);
        if (tr_link_nonblock(&c.link)) rc = -103;
    }
    for (size_t i = 0; i < sizeof g_fmx_raw; i++) g_fmx_raw[i] = (unsigned char)(i * 7 + 1);
    long before = __atomic_load_n(&g_relay.n[0], __ATOMIC_SEQ_CST);
    if (!rc) rc = transport_write(&c, g_fmx_raw, sizeof g_fmx_raw);
    for (int i = 0, nx = 0; !rc && loop && nx >= 0 && nx < 500 && i < 1000; i++) {
        if (i) poll(NULL, 0, 1);
        if (transport_due(&c, tr_mono_ms(), &nx)) rc = -104;
        if (nx > o->next) o->next = nx;
    }
    size_t got = 0;
    while (!rc && got < sizeof g_fmx_raw) {
        ssize_t r = read(s.fd, g_fmx_in + got, sizeof g_fmx_raw - got);
        if (r <= 0) break;
        got += (size_t)r;
    }
    struct pollfd pf = { .fd = s.fd, .events = POLLIN, .revents = 0 };
    if (!rc) o->raw = got == sizeof g_fmx_raw && !memcmp(g_fmx_in, g_fmx_raw, got) && poll(&pf, 1, 200) == 0;
    o->wire = __atomic_load_n(&g_relay.n[0], __ATOMIC_SEQ_CST) - before;
    if (up) transport_close(&c);
    fm_dirs_free(cd, sd);
    close(s.fd);
    fmrelay_join(&g_relay);
    fm_use(NULL, 0);
}

static void t_fm_sd_direct_tx(void) {
    /* catches: raw writes entering through TLS or past sudoku */
    int fd0 = fd_count();
    g_fmr_sd = fmr_sd_of(SD_NODE);
    check("sd direct tx: the relay's tables", 1, g_fmr_sd != NULL);
    struct sdt o;
    sdt_run(SD_NODE, 0, &o);
    check("sd direct tx: the handshake frame continues", VISION_CMD_CONTINUE, o.cmd[0]);
    check("sd direct tx: the frame after the inner handshake says direct", VISION_CMD_DIRECT, o.cmd[1]);
    check("sd direct tx: the writer switches", 1, o.sw);
    check("sd direct tx: the raw uplink decodes to the inner stream", 1, o.raw);
    check("sd direct tx: four hints a raw byte", 4L * (long)sizeof g_fmx_raw, o.wire);
    sdt_run(SD_FRAG, 1, &o);
    check("sd direct tx, fragment above: direct", VISION_CMD_DIRECT, o.cmd[1]);
    check("sd direct tx, fragment above: the raw uplink decodes", 1, o.raw);
    check("sd direct tx, fragment above: four hints a raw byte", 4L * (long)sizeof g_fmx_raw, o.wire);
    check("sd direct tx, fragment above: no gap after a raw write", 1, o.next >= -1 && o.next <= 1);
    g_fmr_sd = NULL;
    check("sd direct tx: descriptor count restored", fd0, fd_count());
    check("sd direct tx: nothing left on the heap", 0, LEAK_CHECK());
}

#define SD_NODE100 "{\"tcp\":[{\"type\":\"sudoku\",\"settings\":{\"password\":\"p\",\"paddingMin\":100,\"paddingMax\":100}}]}"

static unsigned char g_sdv_up[1 << 18];

struct sdv { struct dir *cd; int fd; size_t got; int same; };

static void *sdv_read(void *a) {
    struct sdv *v = a;
    static unsigned char rec[1 << 15];
    v->same = 1;
    while (v->got < sizeof g_sdv_up) {
        size_t k = 0;
        unsigned char inner = 0;
        if (rec_open(v->cd, v->fd, rec, sizeof rec, &k, &inner) || inner != 0x17) break;
        if (v->got + k > sizeof g_sdv_up || memcmp(rec, g_sdv_up + v->got, k)) v->same = 0;
        v->got += k;
    }
    return NULL;
}

static int sdv_wait(struct transport *c, int next) {
    struct pollfd p = { .fd = transport_fd(c), .events = POLLOUT, .revents = 0 };
    return poll(&p, 1, next >= 0 && next < 10 ? next : 10);
}

static void t_fm_sd_vision_full(void) {
    /* catches: a mask room that never reopens past Vision's reserve */
    struct plan ok = { .name = "sd vision", .reality_ok = 1 };
    struct vless_node rn;
    upg_node(&rn, "reality", "tcp", "");
    rn.fm = SD_NODE100;
    int fd0 = fd_count();
    g_fmr_sd = fmr_sd_of(SD_NODE100);
    check("sd vision: the relay's tables", 1, g_fmr_sd != NULL);
    g_fmr_slow = 1;
    fm_use(NULL, 1);
    for (size_t i = 0; i < sizeof g_sdv_up; i++) g_sdv_up[i] = (unsigned char)(i * 131 + (i >> 10));
    int sv[2];
    int rc = !g_fmr_sd ? -99 : socketpair(AF_UNIX, SOCK_STREAM, 0, sv) ? -100 : 0;
    struct timeval tv = { .tv_sec = 3 };
    static struct srv s;
    memset(&s, 0, sizeof s);
    s.fd = rc ? -1 : sv[1];
    s.plan = &ok;
    pthread_t th;
    if (!rc) setsockopt(sv[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    if (!rc && pthread_create(&th, NULL, server_half, &s)) rc = -101;
    struct transport c;
    int up = 0;
    if (!rc) {
        g_give_fd = sv[0];
        g_tcp_dial = fake_dial;
        rc = vless_connect(&rn, &c, 3);
        g_tcp_dial = NULL;
        pthread_join(th, NULL);
        up = rc == 0;
    }
    struct dir *cd = calloc(1, sizeof *cd), *sd = calloc(1, sizeof *sd);
    if (!rc && (!cd || !sd || s.rc || fm_app_keys(&s, cd, sd))) rc = -102;
    if (!rc) {
        transport_set_loop(&c);
        if (tr_link_nonblock(&c.link)) rc = -103;
    }
    struct sdv v = { cd, s.fd, 0, 0 };
    pthread_t rt;
    int rt_on = !rc && !pthread_create(&rt, NULL, sdv_read, &v);
    if (!rc && !rt_on) rc = -104;
    size_t off = 0;
    long stalls = 0;
    int next = 0;
    uint64_t dl = fmr_ms() + 60000;
    while (!rc && off < sizeof g_sdv_up && fmr_ms() < dl) {
        if (transport_due(&c, fmr_ms(), &next)) {
            rc = -105;
            break;
        }
        long room = transport_mask_room(&c) - 2048;
        if (room <= 0) {
            stalls++;
            sdv_wait(&c, next);
            continue;
        }
        size_t k = sizeof g_sdv_up - off;
        if (k > (size_t)room) k = (size_t)room;
        rc = transport_write(&c, g_sdv_up + off, k);
        off += k;
    }
    if (!rc && off < sizeof g_sdv_up) rc = -107;
    while (!rc && fmr_ms() < dl) {
        if (transport_due(&c, fmr_ms(), &next)) rc = -106;
        else if (next < 0) break;
        else sdv_wait(&c, next);
    }
    if (rt_on) pthread_join(rt, NULL);
    check("sd vision: 256 KiB up written", 0, rc);
    check("sd vision: the room closed and reopened", 1, stalls > 0 && off == sizeof g_sdv_up);
    check("sd vision: the server got 256 KiB, the bytes sent", 1, v.got == sizeof g_sdv_up && v.same);
    if (up) transport_close(&c);
    fm_dirs_free(cd, sd);
    if (s.fd >= 0) close(s.fd);
    fmrelay_join(&g_relay);
    check("sd vision: the relay carried it padded", 1, g_relay.n[0] >= 9L * (long)sizeof g_sdv_up);
    g_fmr_slow = 0;
    g_fmr_sd = NULL;
    fm_use(NULL, 0);
    check("sd vision: descriptor count restored", fd0, fd_count());
    check("sd vision: nothing left on the heap", 0, LEAK_CHECK());
}

int main(void) {
    /* The server half writes to a socket the client has already closed: on a failed check the
     * client closes without reading to the end. Without this the test would die of SIGPIPE
     * instead of reporting the result. */
    signal(SIGPIPE, SIG_IGN);
    /* Line by line: a leak still there at exit makes LeakSanitizer end the process before stdio
     * flushes, and a buffered report would lose its last checks. */
    setvbuf(stdout, NULL, _IOLBF, 0);

    /* Without /proc every descriptor check would compare -1 with -1 and pass. */
    check("descriptors can be counted (/proc/self/fd)", 1, fd_count() > 0);

    heap_check_selftest();

    struct vless_node node;
    node_reality(&node, "tcp");

    /* Warm-up. The first handshake brings one-time allocations of the crypto library and the
     * thread start, and without it the first heap check would report them as a leak. The return
     * code shows that the warm-up worked: it must equal that of the first measured case below. */
    {
        struct plan warm = { .name = "warm-up", .cert = 0 };
        char why[256];
        int rc = run_case(&warm, &node, why, sizeof(why), NULL);
        check("warm-up: the handshake reached the certificate check", TLS13_ECERT, rc);
    }

    static const struct plan plans[] = {
        { .name = "server sent no certificate", .cert = 0 },
        { .name = "server certificate does not parse", .cert = 1 },
        { .name = "certificate arrived compressed", .cert = 2 },
        { .name = "ServerHello without key_share", .no_keyshare = 1 },
        { .name = "server Finished does not match", .bad_finished = 1 },
        { .name = "server closed after ClientHello", .hangup = 1 },
        /* Catches a ServerHello on P-256 taken for a missing key_share instead of a group we cannot finish. */
        { .name = "server chose P-256", .keyshare_group = 0x0017 },
        /* Catches a HelloRetryRequest parsed as a ServerHello instead of told by its random. */
        { .name = "server asked for a HelloRetryRequest", .hrr = 1 },
    };
    static const int want[] = {
        TLS13_ECERT, TLS13_ECERT, TLS13_ECERT,
        TLS13_ENOKEYSHARE, TLS13_EFINISHED, TLS13_ECLOSED,
        TLS13_EGROUP, TLS13_EHRR,
    };
    static const char *text_want[] = {
        "", "", "", "", "", "",
        "the server chose key share group 0x0017, which this client offers but cannot complete",
        "the server asked for a HelloRetryRequest, which is not supported",
    };
    /* The failure reason must reach the caller: without it "the node is down" and "the node is
     * not ours" look the same. Checked for the three ECERT paths, the only ones with a reason. */
    static const char *why_want[] = {
        "sent no certificate",
        "cannot parse",
        /* A compressed certificate is reported as "did not accept the key", not as anything
         * about compression, on purpose: a Reality server that accepted the client answers
         * with its temporary certificate and does not compress it, so the camouflage site is
         * answering. The check is here because a literal text ("server compressed its
         * certificate") would send the user after compression, which has nothing to do with
         * it. */
        "did not accept the key",
        "", "", "", "", "",
    };

    for (size_t i = 0; i < sizeof(plans) / sizeof(*plans); i++) {
        /* The test's buffer is TWICE the engine's (g_verify_reason[96]): the test must measure
         * the engine, not itself. With equal sizes a cut by the test's own buffer would look
         * like a property of the engine, and the other way round. */
        char what[160], why[256] = "";
        int fd0 = fd_count(), ctx_left = -1;
        int rc = run_case(&plans[i], &node, why, sizeof(why), &ctx_left);

        snprintf(what, sizeof(what), "%s: return code", plans[i].name);
        check(what, want[i], rc);

        if (why_want[i][0]) {
            snprintf(what, sizeof(what), "%s: reason reported", plans[i].name);
            check_str(what, why_want[i], why);
        }

        /* catches: a group the client cannot finish or a HelloRetryRequest told as a bad share or record */
        if (text_want[i][0]) {
            snprintf(what, sizeof(what), "%s: error text", plans[i].name);
            check_str(what, text_want[i], transport_strerror(rc));
        }

        /* Our Finished goes only to a server that has proved itself (tls13.c). Not after a
         * hangup: the server's end is gone, and there is nothing to read. */
        if (!plans[i].hangup) {
            snprintf(what, sizeof(what), "%s: no client Finished sent", plans[i].name);
            check(what, 0, g_cfin);
        }

        /* Twenty attempts in a row, as on a router, where the spare pool refills on every SYN.
         * A per-attempt leak becomes visible here instead of staying a rounding error. */
        for (int k = 0; k < 20; k++) {
            int again = run_case(&plans[i], &node, NULL, 0, NULL);
            if (again != want[i]) { rc = again; break; }
        }
        snprintf(what, sizeof(what), "%s: twenty more attempts, same code", plans[i].name);
        check(what, want[i], rc);

        snprintf(what, sizeof(what), "%s: no cipher context left expanded", plans[i].name);
        check(what, 0, ctx_left);

        snprintf(what, sizeof(what), "%s: descriptor count restored", plans[i].name);
        check(what, fd0, fd_count());

        snprintf(what, sizeof(what), "%s: nothing left on the heap", plans[i].name);
        check(what, 0, LEAK_CHECK());
    }

    /* Catches a key share group from an earlier handshake left for a later one's error text. */
    {
        struct plan p256 = { .name = "P-256 again", .keyshare_group = 0x0017 };
        struct plan hrr = { .name = "HelloRetryRequest again", .hrr = 1 };
        run_case(&p256, &node, NULL, 0, NULL);
        unsigned seen = tls13_server_group();
        run_case(&hrr, &node, NULL, 0, NULL);
        check("server group: set by P-256, cleared by the next handshake", 1,
              seen == 0x0017 && tls13_server_group() == 0);
    }

    /* ---- a successful Reality, and ws/httpupgrade over it ------------------------------
     *
     * The server answers with a real Reality temporary certificate (an HMAC over the authkey
     * from its static key pair; the node's pbk is the public half), so the handshake SUCCEEDS
     * here and data follows. For tcp only the look is checked: the ALPN is not narrowed to
     * http/1.1. For ws and httpupgrade everything up to data: ALPN http/1.1 alone, the Upgrade
     * request with the path without ed, the 101 answer and the first data in ONE TLS record (the
     * remainder is not lost), and the client's reply arriving (for ws as a masked frame). */
    if (xc_x25519_keypair(g_rs_priv, g_rs_pub) != 0) {
        printf("%-64s %s\n", "Reality server key pair", "FAIL");
        fails++;
    } else {
        /* ws without early data (ed=0: stripped, Ed 0) and with it (ed=2048: the request goes
         * out with the first write, "hello" in Sec-WebSocket-Protocol); httpupgrade with
         * ed=2048: the 101 answer is read lazily, on the first read. */
        static const char *rtype[] = { "tcp", "ws", "httpupgrade", "ws ed" };
        static const char *rpath[] = { "/w?ed=0", "/w?ed=0", "/w?ed=2048", "/w?ed=2048" };
        for (int u = 0; u < 4; u++) {
            struct plan up = { .name = "reality", .reality_ok = 1, .upg = u == 2 ? 2 : u ? 1 : 0,
                               .ed_first = u == 3 };
            struct vless_node rn;
            node_reality(&rn, u == 3 ? "ws" : rtype[u]);
            b64url(g_rs_pub, 32, rn.pbk);
            snprintf(rn.path, sizeof(rn.path), "%s", rpath[u]);
            snprintf(rn.http_host, sizeof(rn.http_host), "%s", "cdn.example");
            char what[160];
            int fd0 = fd_count();
            static struct srv s;
            int rc;
            if (u == 0) {
                __atomic_store_n(&g_seen_h11, -1, __ATOMIC_SEQ_CST);
                rc = run_case(&up, &rn, NULL, 0, NULL);
                check("reality: temporary certificate accepted, connection established", 0, rc);
                check("reality: the server verified the client's Finished", 1, g_cfin);
                check("reality + tcp: ALPN is not http/1.1 alone", 0, __atomic_load_n(&g_seen_h11, __ATOMIC_SEQ_CST));
                check("reality + tcp: descriptor count restored", fd0, fd_count());
                continue;
            }
            rc = run_upg(&up, &rn, &s);
            snprintf(what, sizeof(what), "reality + %s: connected, first data read", rtype[u]);
            check(what, 0, rc);
            snprintf(what, sizeof(what), "reality + %s: ALPN is http/1.1 alone", rtype[u]);
            check(what, 1, s.alpn_h11);
            snprintf(what, sizeof(what), "reality + %s: path without ed, Host from host", rtype[u]);
            check(what, 1, !strncmp(s.req, "GET /w HTTP/1.1\r\nHost: cdn.example\r\n", 36));
            snprintf(what, sizeof(what), u == 3 ? "reality + %s: 'hello' in Sec-WebSocket-Protocol"
                                                : "reality + %s: reply after 101 arrived", rtype[u]);
            check(what, 1, s.got_hello);
            snprintf(what, sizeof(what), "reality + %s: descriptor count restored", rtype[u]);
            check(what, fd0, fd_count());
            snprintf(what, sizeof(what), "reality + %s: nothing left on the heap", rtype[u]);
            check(what, 0, LEAK_CHECK());
        }
    }

    t_fm_x55();
    t_lk_err_unmasked();
    t_fm_direct();
    t_tx_direct();
    t_fm_free_paths();
    t_fm_pending_ready();
    t_fm_mask_error();
    t_fm_sd_pad_silent();
    t_fm_sd_drip();
    t_fm_sd_direct_rx();
    t_sd_can_tx();
    t_fm_sd_direct_tx();
    t_fm_sd_vision_full();

    {
        struct plan ok = { .name = "two links", .reality_ok = 1, .hold = 1 };
        struct plan cut = { .name = "two links, hangup", .hangup = 1, .hold = 1 };
        struct vless_node xn, dn;
        node_reality(&xn, "xhttp");
        b64url(g_rs_pub, 32, xn.pbk);
        snprintf(xn.path, sizeof(xn.path), "%s", "/x");
        snprintf(xn.mode, sizeof(xn.mode), "%s", "packet-up");
        dn = xn;
        snprintf(dn.host, sizeof(dn.host), "%s", "down.invalid");
        xn.dl = &dn;
        long ms = 0;
        int over[2], fd0 = fd_count();
        int rc = run_two(&ok, &ok, &xn, &ms, over);
        check("xhttp packet-up: both links open", 0, rc);
        /* catches: the upload link dialled only after the download link's handshake */
        check("xhttp packet-up: both Hellos out before either answer", 1, over[0] && over[1]);
        /* catches: the second handshake waiting out the first one's answer */
        check("xhttp packet-up: open within one held answer", 1, ms < HOLD_MS);
        check("xhttp packet-up: GET to the download host, upload to the node", 1,
              g_dial_n == 2 && !strcmp(g_dialed[0], "down.invalid") && !strcmp(g_dialed[1], "node.invalid"));
        check("xhttp packet-up: descriptor count restored", fd0, fd_count());
        check("xhttp packet-up: nothing left on the heap", 0, LEAK_CHECK());

        struct plan late = { .name = "answers after the other link", .reality_ok = 1, .after_peer = 1 };
        struct plan early = { .name = "answers at once", .reality_ok = 1, .tell_peer = 1 };
        rc = run_two(&late, &early, &xn, &ms, over);
        check("xhttp, the upload link answers first: both links open", 0, rc);
        /* catches: the download link's answer awaited before the upload link that already answered */
        check("xhttp, the upload link answers first: finished first", 1, over[0] && over[1] && ms < HOLD_MS);
        check("xhttp, the upload link answers first: descriptor count restored", fd0, fd_count());

        xn.mode[0] = '\0';
        rc = run_two(&ok, &ok, &xn, &ms, over);
        check("xhttp downloadSettings: both links open", 0, rc);
        check("xhttp downloadSettings: both Hellos out before either answer", 1, over[0] && over[1]);
        /* catches: the download link sent to the main node or the upload to the download host */
        check("xhttp downloadSettings: GET to the download host, upload to the node", 1,
              g_dial_n == 2 && !strcmp(g_dialed[0], "down.invalid") && !strcmp(g_dialed[1], "node.invalid"));
        check("xhttp downloadSettings: descriptor count restored", fd0, fd_count());
        snprintf(xn.mode, sizeof(xn.mode), "%s", "packet-up");

        rc = run_two(&ok, &cut, &xn, &ms, over);
        check("xhttp, upload link cut: the second link's error", TLS13_ECLOSED, rc);
        /* catches: the download link left open when the upload link fails */
        check("xhttp, upload link cut: descriptor count restored", fd0, fd_count());
        check("xhttp, upload link cut: nothing left on the heap", 0, LEAK_CHECK());
        rc = run_two(&cut, &ok, &xn, &ms, over);
        check("xhttp, download link cut: the first link's error", TLS13_ECLOSED, rc);
        /* catches: the upload link left open when the download link fails */
        check("xhttp, download link cut: descriptor count restored", fd0, fd_count());
        check("xhttp, download link cut: nothing left on the heap", 0, LEAK_CHECK());

        xn.dl = NULL;
        struct plan one = { .name = "one link", .reality_ok = 1 };
        rc = run_two(&one, &one, &xn, &ms, over);
        check("xhttp packet-up without a block: the link opens", 0, rc);
        /* catches: packet-up dialling a second link for its POSTs */
        check("xhttp packet-up without a block: one link", 1, g_dial_n);
        check("xhttp packet-up without a block: descriptor count restored", fd0, fd_count());
        check("xhttp packet-up without a block: nothing left on the heap", 0, LEAK_CHECK());
        xn.mode[0] = '\0';
        rc = run_two(&one, &one, &xn, &ms, over);
        check("xhttp stream-one: the link opens", 0, rc);
        /* catches: stream-one dialling a second link */
        check("xhttp stream-one: one link", 1, g_dial_n);
        check("xhttp stream-one: descriptor count restored", fd0, fd_count());
    }

    /* ---- security=tls with our own roots -------------------------------------------
     *
     * Here the server check passes on a real X.509 chain, which makes full setup and the
     * TR_ENOH2 path reachable; TR_ENOH2 must close through transport_close, not close(fd). The
     * roots reach the engine through the g_cert_roots seam. There is one store for the whole
     * process: certverify.c loads it under pthread_once, and a second one would have no effect. */
#if defined(STEER_HAVE_X509WRITE)
    if (chain_build() != 0) {
        printf("%-64s %s\n", "issuing our own X.509 chain", "FAIL");
        fails++;
    } else {
        g_cert_roots = g_roots_file;

        /* Warm-up for this half: the first handshake with chain verification loads the root
         * store under pthread_once. It stays on the heap for good by design (see roots_load),
         * and without the warm-up the first heap check would report it as a leak. */
        {
            struct plan warm = { .name = "tls warm-up", .chain = LEAF_OK };
            struct vless_node w;
            node_tls(&w, "tcp");
            int rc = run_case(&warm, &w, NULL, 0, NULL);
            check("tls warm-up: chain verified, connection established", 0, rc);
        }

        static const struct plan tls_plans[] = {
            { .name = "tls: chain verifies",                .chain = LEAF_OK },
            { .name = "tls: server chose http/1.1, not h2", .chain = LEAF_OK, .alpn = "http/1.1" },
            { .name = "tls: leaf issued for another name",  .chain = LEAF_NAME },
            { .name = "tls: self-signed leaf",              .chain = LEAF_SELF },
            { .name = "tls: no CertificateVerify",          .chain = LEAF_OK, .no_cv = 1 },
            { .name = "tls: signature does not verify",     .chain = LEAF_OK, .cv_bad_sig = 1 },
            { .name = "tls: signature scheme not offered",  .chain = LEAF_OK, .cv_bad_alg = 1 },
            /* Catches a CompressedCertificate refused on plain TLS, or hashed decompressed instead of as received. */
            { .name = "tls: brotli certificate verifies",   .chain = LEAF_OK, .compress = 2 },
            /* Catches an algorithm the Hello did not offer decompressed anyway. */
            { .name = "tls: zlib certificate refused",      .chain = LEAF_OK, .compress = 1 },
            /* Catches the offered set read as "any known algorithm". */
            { .name = "tls: zstd certificate refused",      .chain = LEAF_OK, .compress = 3 },
            /* Catches a CompressedCertificate taken for a plain chain that does not verify. */
            { .name = "tls: brotli wrong-name leaf refused", .chain = LEAF_NAME, .compress = 2 },
            /* Catches a CompressedCertificate whose stream length disagrees with its message length. */
            { .name = "tls: brotli with a byte past the stream", .chain = LEAF_OK, .compress = 2, .compress_junk = 1 },
            /* Catches a Firefox Hello whose offer of zlib the client does not honour. */
            { .name = "tls: firefox zlib certificate verifies", .chain = LEAF_OK, .compress = 1, .firefox = 1 },
            /* Catches a Firefox Hello whose offer of zstd the client does not honour. */
            { .name = "tls: firefox zstd certificate verifies", .chain = LEAF_OK, .compress = 3, .firefox = 1 },
            /* Catches a delegated credential ignored, or refused as a bad signature instead of by name. */
            { .name = "tls: delegated credential refused",   .chain = LEAF_OK, .dc = 1, .firefox = 1 },
            /* Catches an empty CompressedCertificate taken, leaving room for a later plain chain. */
            { .name = "tls: empty compressed certificate refused", .chain = LEAF_OK, .compress_empty = 1, .firefox = 1 },
            /* Catches a CompressedCertificate too short for its algorithm reported as one not asked for. */
            { .name = "tls: one-byte compressed certificate refused", .chain = LEAF_OK, .compress_short = 1 },
            /* Catches a Certificate taken with bytes after its list, as a chain cut at the wrong length is. */
            { .name = "tls: a byte after the certificate list refused", .chain = LEAF_OK, .cert_trail = 1 },
            /* Catches a second Certificate skipped in silence. */
            { .name = "tls: the certificate sent twice refused", .chain = LEAF_OK, .cert_twice = 1 },
            /* Catches a second CompressedCertificate skipped in silence. */
            { .name = "tls: the compressed certificate sent twice refused", .chain = LEAF_OK, .compress = 2, .cert_twice = 1 },
            /* Catches a second CertificateVerify skipped in silence. */
            { .name = "tls: CertificateVerify sent twice refused", .chain = LEAF_OK, .cv_twice = 1 },
        };
        /* The ALPN case MUST NOT run on tcp. tcp asks for no ALPN at all (transport.c: tr_tcp
         * has alpn = NULL), so the "server did not choose h2" check is not made there, and on tcp
         * this case would silently pass as a success. */
        static const char *tls_type[] = { "tcp", "grpc", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp", "tcp" };
        static const int tls_want[] = {
            0, TR_ENOH2, TLS13_ECERT, TLS13_ECERT,
            TLS13_ECERT, TLS13_ECERT, TLS13_ECERT,
            0, TLS13_ECERT, TLS13_ECERT, TLS13_ECERT, TLS13_ECERT,
            0, 0, TLS13_ECERT,
            TLS13_ECERT, TLS13_ECERT, TLS13_ECERT, TLS13_ECERT, TLS13_ECERT, TLS13_ECERT,
        };
        /* Each needle is the END of its reason in certverify.c or tls13.c, so a reason cut short
         * (g_verify_reason in tls13.c is 96 bytes) fails the check. */
        static const char *tls_why[] = {
            "", "",
            "names another host",          /* CERTV_ECHAIN: the name is checked with the chain */
            "does not chain to a root or names another host", /* self-signed: same code */
            "sent no signature",           /* tls13.c tells "no certificate" from "no signature" */
            "bad server signature",        /* CERTV_ESIG */
            "algorithm we did not offer",  /* CERTV_EALG: its own reason, not "bad signature" */
            "",
            "compressed certificate without being asked",
            "compressed certificate without being asked",
            "names another host",
            "cannot decompress the server certificate",
            "", "",
            "the server sent a delegated credential, which is not supported",
            "cannot decompress the server certificate",
            "cannot decompress the server certificate",
            "cannot parse the server certificate",
            "the server sent its certificate twice",
            "the server sent its certificate twice",
            "the server sent CertificateVerify twice",
        };
        for (size_t i = 0; i < sizeof(tls_plans) / sizeof(*tls_plans); i++) {
            struct vless_node tn;
            node_tls(&tn, tls_type[i]);
            if (tls_plans[i].firefox) snprintf(tn.fp, sizeof(tn.fp), "%s", "firefox");
            char what[160], why[256] = "";
            int fd0 = fd_count(), ctx_left = -1;
            int rc = run_case(&tls_plans[i], &tn, why, sizeof(why), &ctx_left);

            snprintf(what, sizeof(what), "%s: return code", tls_plans[i].name);
            check(what, tls_want[i], rc);

            if (tls_why[i][0]) {
                snprintf(what, sizeof(what), "%s: reason reported", tls_plans[i].name);
                check_str(what, tls_why[i], why);
            }

            /* The handshake completes for success and TR_ENOH2 (the ALPN is checked after it):
             * then the server must have a Finished that verifies; otherwise none at all. */
            const int done = tls_want[i] == 0 || tls_want[i] == TR_ENOH2;
            snprintf(what, sizeof(what), done ? "%s: client Finished verifies"
                                              : "%s: no client Finished sent", tls_plans[i].name);
            check(what, done, g_cfin);

            for (int k = 0; k < 20; k++) {
                int again = run_case(&tls_plans[i], &tn, NULL, 0, NULL);
                if (again != tls_want[i]) { rc = again; break; }
            }
            snprintf(what, sizeof(what), "%s: twenty more attempts, same code", tls_plans[i].name);
            check(what, tls_want[i], rc);

            snprintf(what, sizeof(what), "%s: no cipher context left expanded", tls_plans[i].name);
            check(what, 0, ctx_left);

            snprintf(what, sizeof(what), "%s: descriptor count restored", tls_plans[i].name);
            check(what, fd0, fd_count());

            snprintf(what, sizeof(what), "%s: nothing left on the heap", tls_plans[i].name);
            check(what, 0, LEAK_CHECK());
        }
        /* Catches the key schedule (handshake secret, both handshake traffic secrets, the server's handshake key) left on the stack after a handshake, whole or failed. */
        {
            struct plan ok = { .name = "wipe ok", .chain = LEAF_OK };
            struct plan bad = { .name = "wipe bad", .chain = LEAF_OK, .cv_bad_sig = 1 };
            struct vless_node tn;
            node_tls(&tn, "tcp");
            g_sec_set = 0;
            g_sec_wipes = 0;
            check("key schedule: a verified handshake", 0, run_case(&ok, &tn, NULL, 0, NULL));
            check("key schedule: wiped once after success", 1, g_sec_wipes);
            g_sec_set = 0;
            g_sec_wipes = 0;
            check("key schedule: a bad signature", TLS13_ECERT, run_case(&bad, &tn, NULL, 0, NULL));
            check("key schedule: wiped once after the failure", 1, g_sec_wipes);
        }
        /* Catches traffic keys left in a freed connection, with and without a cipher context set up. */
        {
            struct tls13 t;
            memset(&t, 0, sizeof t);
            t.rd.aead = t.wr.aead = TLS13_AEAD_AES128;
            t.rd.key_n = t.wr.key_n = 16;
            memset(t.rd.key, 0xA5, sizeof t.rd.key); memset(t.rd.iv, 0xA5, sizeof t.rd.iv);
            memset(t.wr.key, 0x5A, sizeof t.wr.key); memset(t.wr.iv, 0x5A, sizeof t.wr.iv);
            check("tls13_free: read context set up", 0, tls13_keys_setup(&t.rd));
            tls13_free(&t);
            size_t left = 0;
            for (size_t i = 0; i < sizeof t.rd.key; i++) left += (t.rd.key[i] != 0) + (t.wr.key[i] != 0);
            for (size_t i = 0; i < sizeof t.rd.iv; i++) left += (t.rd.iv[i] != 0) + (t.wr.iv[i] != 0);
            check("tls13_free: keys and IVs of both directions zero", 0, (long)left);
        }
        /* Pins and an explicit opt-out of verification (Xray pinnedPeerCertSha256 /
         * verifyPeerCertByName). The expectations match what a test against an Xray-core 26.9.9
         * server showed: a pinned leaf is accepted WITHOUT chain or name (here a self-signed
         * one), another leaf's fingerprint fails, vcn replaces the name to check, and insecure
         * drops the chain check but not the CertificateVerify signature. */
        {
            static const char HEX[] = "0123456789abcdef";
            char h_ok[65], h_name[65], h_self[65];
            struct { int idx; char *out; } hh[] = { { LEAF_OK, h_ok }, { LEAF_NAME, h_name }, { LEAF_SELF, h_self } };
            for (size_t i = 0; i < 3; i++) {
                unsigned char d[32];
                sc_hash(SC_SHA256, g_leaf[hh[i].idx].der, g_leaf[hh[i].idx].der_n, d);
                for (int k = 0; k < 32; k++) { hh[i].out[2 * k] = HEX[d[k] >> 4]; hh[i].out[2 * k + 1] = HEX[d[k] & 15]; }
                hh[i].out[64] = '\0';
            }
            struct { const char *name; struct plan pl; const char *pcs, *vcn; int ins; int want; } pin[] = {
                { "pcs: pinned self-signed leaf accepted",      { .chain = LEAF_SELF }, h_self, NULL, 0, 0 },
                { "pcs: pinned leaf for another name accepted", { .chain = LEAF_NAME }, h_name, NULL, 0, 0 },
                { "pcs: another leaf's fingerprint is refused", { .chain = LEAF_OK },   h_name, NULL, 0, TLS13_ECERT },
                { "pcs: several fingerprints, match is second", { .chain = LEAF_OK },   NULL,   NULL, 0, 0 },
                { "vcn: the name to check replaces sni",        { .chain = LEAF_NAME }, NULL,   "other.invalid", 0, 0 },
                { "vcn: a wrong name is refused",               { .chain = LEAF_OK },   NULL,   "other.invalid", 0, TLS13_ECERT },
                { "insecure: self-signed leaf accepted",        { .chain = LEAF_SELF }, NULL,   NULL, 1, 0 },
                { "insecure: CertificateVerify signature still checked",
                                                                { .chain = LEAF_OK, .cv_bad_sig = 1 }, NULL, NULL, 1, TLS13_ECERT },
            };
            char two[140];
            snprintf(two, sizeof two, "%s,%s", h_self, h_ok);
            for (size_t i = 0; i < sizeof pin / sizeof *pin; i++) {
                struct vless_node tn;
                node_tls(&tn, "tcp");
                tn.pcs = i == 3 ? two : pin[i].pcs;
                tn.vcn = pin[i].vcn;
                tn.insecure = (uint8_t)pin[i].ins;
                pin[i].pl.name = pin[i].name;
                int fd0 = fd_count(), ctx_left = -1;
                int rc = run_case(&pin[i].pl, &tn, NULL, 0, &ctx_left);
                char what[160];
                snprintf(what, sizeof what, "%s: return code", pin[i].name);
                check(what, pin[i].want, rc);
                snprintf(what, sizeof what, "%s: no fd or cipher context leak", pin[i].name);
                check(what, 0, (fd_count() - fd0) + (ctx_left > 0 ? ctx_left : 0));
                snprintf(what, sizeof what, "%s: nothing left on the heap", pin[i].name);
                check(what, 0, LEAK_CHECK());
            }
        }
        /* ws and httpupgrade over plain TLS with our own chain: as for Reality above, plus a real
         * certificate check. This is the path of nodes behind a CDN. */
        static const char *ttype[] = { "ws", "httpupgrade", "ws ed" };
        for (int u = 1; u <= 3; u++) {
            struct plan up = { .name = "tls", .chain = LEAF_OK, .upg = u == 2 ? 2 : 1, .ed_first = u == 3 };
            struct vless_node tn;
            node_tls(&tn, u == 2 ? "httpupgrade" : "ws");
            snprintf(tn.path, sizeof(tn.path), "%s", u == 1 ? "/w?ed=0" : "/w?ed=2048");
            char what[160];
            int fd0 = fd_count();
            static struct srv s;
            int rc = run_upg(&up, &tn, &s);
            snprintf(what, sizeof(what), "tls + %s: connected, first data read", ttype[u - 1]);
            check(what, 0, rc);
            snprintf(what, sizeof(what), "tls + %s: ALPN is http/1.1 alone", ttype[u - 1]);
            check(what, 1, s.alpn_h11);
            snprintf(what, sizeof(what), "tls + %s: path without ed, Host from sni", ttype[u - 1]);
            check(what, 1, !strncmp(s.req, "GET /w HTTP/1.1\r\nHost: " TLS_SNI "\r\n",
                                    strlen("GET /w HTTP/1.1\r\nHost: " TLS_SNI "\r\n")));
            snprintf(what, sizeof(what), "tls + %s: client's 'hello' arrived", ttype[u - 1]);
            check(what, 1, s.got_hello);
            snprintf(what, sizeof(what), "tls + %s: descriptor count restored", ttype[u - 1]);
            check(what, fd0, fd_count());
            snprintf(what, sizeof(what), "tls + %s: nothing left on the heap", ttype[u - 1]);
            check(what, 0, LEAK_CHECK());
        }
        {
            struct plan ok = { .name = "x55 tls", .chain = LEAF_OK };
            struct vless_node tn;
            node_tls(&tn, "tcp");
            int fd0 = fd_count();
            fm_use(&FMT_X55, 1);
            /* catches: tls13.c:104/147/759/774/887 or trsec.c:155 on the bare fd under security=tls */
            check("x55 tls tcp: data both ways", 0, fm_data(&ok, &tn, FM_RECORDS));
            fm_use(NULL, 0);
            check("x55 tls tcp: descriptor count restored", fd0, fd_count());
            check("x55 tls tcp: nothing left on the heap", 0, LEAK_CHECK());
        }

        /* The server behind TLS chose h2, but the upgrade runs over HTTP/1.1: its own code, not
         * "did not agree to HTTP/2". */
        {
            struct plan up = { .name = "tls h2", .chain = LEAF_OK, .alpn = "h2" };
            struct vless_node tn;
            node_tls(&tn, "ws");
            int rc = run_case(&up, &tn, NULL, 0, NULL);
            check("tls + ws: server chose h2, refused with TR_ENOH1", TR_ENOH1, rc);
        }
        t_fm_sd();
        cc_tests();
        /* Hysteria2 audit & full QUIC v1 engine tests (B1, B2, B3):
         * - B2: Enabled by default with full QUIC v1 engine, and can be gated off with vless_set_enable_hy2(0)
         * - B1: Server Finished without Certificate or CertificateVerify is rejected with TLS13_ECERT
         *       and never sends 1-RTT auth credentials
         * - B1 + B3: Out-of-order CRYPTO frames + HTTP/3 Stream 0 QPACK :status=200 with "233" in x-pad
         *       is rejected, while split out-of-order :status=233 succeeds
         * - B2 Full QUIC:
         *     1) RFC 9002 packet-threshold loss detection + PTO tail recovery + multi-range SACK + duplicate PN suppression
         *     2) QUIC send & receive flow control (EncryptedExtensions TP, STREAM_DATA_BLOCKED, MAX_STREAM_DATA, MAX_DATA)
         *     3) Multi-fragment Hysteria2 UDP datagram fragmentation & out-of-order reassembly */
        {
            struct vless_node hyn;
            memset(&hyn, 0, sizeof(hyn));
            snprintf(hyn.proto, sizeof(hyn.proto), "%s", "hy2");
            snprintf(hyn.host, sizeof(hyn.host), "%s", "node.invalid");
            hyn.port = 8443;
            snprintf(hyn.uuid, sizeof(hyn.uuid), "%s", "hy2-secret");
            snprintf(hyn.type, sizeof(hyn.type), "%s", "quic");
            snprintf(hyn.security, sizeof(hyn.security), "%s", "tls");
            snprintf(hyn.sni, sizeof(hyn.sni), "%s", TLS_SNI);

            check("hy2 B2: disabled by default", 0, vless_enable_hy2());
            struct transport c;
            check("hy2 B2: refused when disabled by default in transport_open", TR_ENONODE,
                  vless_connect(&hyn, &c, 2));

            vless_set_enable_hy2(1);
            int fd0 = fd_count(), got_1rtt = -1;
            check("hy2 B1: Finished without Certificate refused with TLS13_ECERT",
                  TLS13_ECERT, run_hy2_mock(HY2_MOCK_NO_CERT, &got_1rtt));
            check("hy2 B1: no 1-RTT auth sent without Certificate", 0, got_1rtt);

            got_1rtt = -1;
            check("hy2 B1: Finished without CertificateVerify refused with TLS13_ECERT",
                  TLS13_ECERT, run_hy2_mock(HY2_MOCK_NO_CV, &got_1rtt));
            check("hy2 B1: no 1-RTT auth sent without CertificateVerify", 0, got_1rtt);

            got_1rtt = 0;
            check("hy2 B3: :status=200 with '233' in header value refused",
                  TR_ECLOSED, run_hy2_mock(HY2_MOCK_STATUS_200_FAKE_233, &got_1rtt));
            check("hy2 B3: handshake completed before auth check", 1, got_1rtt);

            got_1rtt = 0;
            check("hy2 B1+B3: out-of-order CRYPTO & split Stream 0 :status=233 succeeds",
                  0, run_hy2_mock(HY2_MOCK_OOO_SPLIT_233_OK, &got_1rtt));

            /* B2 Scenario 1: Loss Recovery (Packet Threshold + PTO Tail), Multi-Range SACK, Dup PN Suppression */
            {
                int sv[2];
                check("hy2 B2 loss: socketpair", 0, socketpair(AF_UNIX, SOCK_DGRAM, 0, sv));
                struct hy2_loss_srv_ctx *lctx = calloc(1, sizeof(*lctx));
                lctx->fd = sv[1];
                pthread_t th;
                pthread_create(&th, NULL, hy2_loss_srv_thread, lctx);

                g_give_fd = sv[0];
                g_tcp_dial = fake_dial;
                struct transport tc;
                int orc = vless_connect(&hyn, &tc, 2);
                g_tcp_dial = NULL;
                check("hy2 B2 loss: vless_connect", 0, orc);
                if (orc == 0) {
                    /* Send TCP address header: [ATYP=0x01][1.2.3.4][port=80] */
                    unsigned char ahdr[7] = { 0x01, 1, 2, 3, 4, 0, 80 };
                    check("hy2 B2 loss: write addr header", 0, transport_write(&tc, ahdr, 7));

                    /* Read 8000 bytes sent out-of-order and with duplicate PNs by server */
                    unsigned char rx_stream_cli[8000];
                    size_t rx_got = 0;
                    struct pollfd cpfd = { .fd = tc.link.fd, .events = POLLIN, .revents = 0 };
                    for (int tries = 0; tries < 60 && rx_got < 8000; tries++) {
                        if (!transport_has_data(&tc)) poll(&cpfd, 1, 50);
                        size_t step_got = 0;
                        if (transport_read(&tc, rx_stream_cli + rx_got, 8000 - rx_got, &step_got) == 0 && step_got > 0)
                            rx_got += step_got;
                    }
                    check("hy2 B2 loss: client received all 8000 OOO server bytes", 8000, (int)rx_got);
                    int rx_match = 1;
                    for (int ch_i = 0; ch_i < 8; ch_i++) {
                        for (size_t k = 0; k < 1000; k++) {
                            unsigned char exp = (unsigned char)((ch_i * 37 + k) & 0xFF);
                            if (rx_stream_cli[ch_i * 1000 + k] != exp) { rx_match = 0; break; }
                        }
                    }
                    check("hy2 B2 loss: OOO + duplicate-PN server stream reassembled exact", 1, rx_match);

                    /* Now write 16000 bytes in 8 chunks of 2000 bytes; server drops packet #2 (SACK threshold)
                     * and drops the final packet (PTO tail loss). Pump transport_room/read until server gets all! */
                    unsigned char tx_stream_cli[16000];
                    for (size_t i = 0; i < sizeof(tx_stream_cli); i++)
                        tx_stream_cli[i] = (unsigned char)((i * 13 + 7) & 0xFF);
                    size_t tx_sent = 0;
                    while (tx_sent < sizeof(tx_stream_cli)) {
                        size_t chunk = sizeof(tx_stream_cli) - tx_sent;
                        if (chunk > 2000) chunk = 2000;
                        if (transport_write(&tc, tx_stream_cli + tx_sent, chunk) != 0) break;
                        tx_sent += chunk;
                    }
                    check("hy2 B2 loss: client queued all 16000 bytes", 16000, (int)tx_sent);

                    /* Drive QUIC loss detection & PTO timer via transport_read / transport_room while waiting */
                    for (int pump = 0; pump < 80 && !lctx->ok; pump++) {
                        if (poll(&cpfd, 1, 25) > 0) {
                            unsigned char tmp[256];
                            size_t sg = 0;
                            (void)transport_read(&tc, tmp, sizeof(tmp), &sg);
                        } else {
                            (void)transport_room(&tc);
                        }
                    }
                    transport_close(&tc);
                }
                pthread_join(th, NULL);
                close(sv[1]);

                check("hy2 B2 loss: client emitted multi-range SACK (rcnt >= 1)", 1, lctx->saw_multi_sack);
                check("hy2 B2 loss: server dropped packet #2 (packet-threshold test)", 1, lctx->dropped_pkt_threshold);
                check("hy2 B2 loss: server dropped tail packet (PTO probe test)", 1, lctx->dropped_tail_pto);
                check("hy2 B2 loss: all client retransmissions used strictly increasing PNs", 1, lctx->saw_monotonic_retx_pn);
                check("hy2 B2 loss: server recovered all 16000 client bytes", 1, lctx->ok);
                int tx_match = 1;
                for (size_t i = 0; i < 16000; i++) {
                    if (lctx->rx_stream[i] != (unsigned char)((i * 13 + 7) & 0xFF)) { tx_match = 0; break; }
                }
                check("hy2 B2 loss: recovered client stream matches byte-for-byte", 1, tx_match);
                free(lctx);
            }

            /* B2 Scenario 2: QUIC Flow Control (Send & Receive Window Credit & STREAM_DATA_BLOCKED) */
            {
                int sv[2];
                check("hy2 B2 flowctl: socketpair", 0, socketpair(AF_UNIX, SOCK_DGRAM, 0, sv));
                struct hy2_fc_srv_ctx fctx;
                memset(&fctx, 0, sizeof(fctx));
                fctx.fd = sv[1];
                pthread_t th;
                pthread_create(&th, NULL, hy2_fc_srv_thread, &fctx);

                g_give_fd = sv[0];
                g_tcp_dial = fake_dial;
                struct transport tc;
                int orc = vless_connect(&hyn, &tc, 2);
                g_tcp_dial = NULL;
                check("hy2 B2 flowctl: vless_connect", 0, orc);
                if (orc == 0) {
                    unsigned char ahdr[7] = { 0x01, 1, 2, 3, 4, 0, 80 };
                    (void)transport_write(&tc, ahdr, 7);
                    unsigned char payload[6000];
                    memset(payload, 0x42, sizeof(payload));
                    int wrc = transport_write(&tc, payload, sizeof(payload));
                    check("hy2 B2 flowctl: buffered 6000-byte write", 0, wrc);

                    /* Read 20000 bytes from server so client replenishes receive flow-control window */
                    struct pollfd cpfd = { .fd = tc.link.fd, .events = POLLIN, .revents = 0 };
                    unsigned char rbuf[2048];
                    size_t rgot = 0;
                    for (int i = 0; i < 80 && rgot < 20000; i++) {
                        if (!transport_has_data(&tc)) poll(&cpfd, 1, 30);
                        size_t sg = 0;
                        if (transport_read(&tc, rbuf, sizeof(rbuf), &sg) == 0 && sg > 0) rgot += sg;
                        (void)transport_room(&tc);
                    }
                    check("hy2 B2 flowctl: client read all 20000 server bytes", 20000, (int)rgot);
                    for (int w = 0; w < 30 && (!fctx.resumed_after_max_stream_data || !fctx.saw_client_max_stream_data); w++) {
                        poll(&cpfd, 1, 10);
                        (void)transport_room(&tc);
                    }
                    transport_close(&tc);
                }
                pthread_join(th, NULL);
                close(sv[1]);

                check("hy2 B2 flowctl: initial burst capped at server TP initial_max_stream_data (1500)",
                      1, fctx.capped_at_initial_window);
                check("hy2 B2 flowctl: client emitted STREAM_DATA_BLOCKED (0x15)",
                      1, fctx.saw_stream_data_blocked);
                check("hy2 B2 flowctl: client resumed Stream 4 after MAX_STREAM_DATA grant",
                      1, fctx.resumed_after_max_stream_data);
                check("hy2 B2 flowctl: client emitted MAX_STREAM_DATA (0x11) on receive consumption",
                      1, fctx.saw_client_max_stream_data);
                check("hy2 B2 flowctl: client emitted MAX_DATA (0x10) on receive consumption",
                      1, fctx.saw_client_max_data);
            }

            /* B2 Scenario 2B: Flow-Control Grant Loss Recovery (Standalone, Piggybacked, Repeated Grant/ACK Loss, Stale Non-Regression) */
            {
                int sv[2];
                check("hy2 B2 grant-loss: socketpair", 0, socketpair(AF_UNIX, SOCK_DGRAM, 0, sv));
                struct hy2_grant_loss_srv_ctx *gctx = calloc(1, sizeof(*gctx));
                gctx->fd = sv[1];
                pthread_t th;
                pthread_create(&th, NULL, hy2_grant_loss_srv_thread, gctx);

                setenv("TUNVLESS_HY2_RX_WIN", "4096", 1);
                g_give_fd = sv[0];
                g_tcp_dial = fake_dial;
                struct transport tc;
                int64_t t_start_ms = now_ms();
                int orc = vless_connect(&hyn, &tc, 2);
                g_tcp_dial = NULL;
                unsetenv("TUNVLESS_HY2_RX_WIN");
                check("hy2 B2 grant-loss: vless_connect", 0, orc);

                unsigned char cli_rx_all[8189];
                size_t cli_rx_got = 0;
                unsigned char cli_tx_all[3000];
                for (size_t i = 0; i < sizeof(cli_tx_all); i++)
                    cli_tx_all[i] = (unsigned char)((i * 23 + 5) & 0xFF);

                if (orc == 0) {
                    struct pollfd cpfd = { .fd = tc.link.fd, .events = POLLIN, .revents = 0 };
                    unsigned char ahdr[7] = { 0x01, 1, 2, 3, 4, 0, 80 };
                    check("hy2 B2 grant-loss: write addr header", 0, transport_write(&tc, ahdr, 7));

                    /* 1. Wait until initial 4093B payload arrives, then read 2045B (3+2045=2048B consumed -> V1=6144) */
                    while (cli_rx_got < 2045) {
                        if (!transport_has_data(&tc)) poll(&cpfd, 1, 25);
                        size_t sg = 0;
                        if (transport_read(&tc, cli_rx_all + cli_rx_got, 2045 - cli_rx_got, &sg) == 0 && sg > 0)
                            cli_rx_got += sg;
                    }
                    check("hy2 B2 grant-loss: read first 2045B triggering standalone grant V1=6144", 2045, (int)cli_rx_got);

                    /* Pump PTO timer while server drops standalone grant #1, drops repeat #2, drops ACK #3, and accepts #4 */
                    for (int w = 0; w < 80 && !gctx->standalone_grant_recovered; w++) {
                        poll(NULL, 0, 15);
                        (void)transport_room(&tc);
                    }
                    /* Drain server ACK for attempt #4 and incoming 4096..6144 stream packets so pto_count resets to 0 */
                    for (int w = 0; w < 20; w++) {
                        if (poll(&cpfd, 1, 5) <= 0) break;
                        (void)transport_room(&tc);
                    }

                    /* 2. Read next 2048B (s4_rx_consumed=4096 -> V2=8192); server drops standalone V2 so next write piggybacks V2 */
                    while (cli_rx_got < 4093) {
                        if (!transport_has_data(&tc)) poll(&cpfd, 1, 25);
                        size_t sg = 0;
                        if (transport_read(&tc, cli_rx_all + cli_rx_got, 4093 - cli_rx_got, &sg) == 0 && sg > 0)
                            cli_rx_got += sg;
                    }
                    for (int w = 0; w < 30 && !gctx->primed_piggyback; w++)
                        poll(NULL, 0, 2);
                    /* Wait for PTO (>120ms) to expire on standalone V2, then write 1000B so hy2_queue_stream4 -> hy2_tick
                     * PTO detects standalone V2 loss and coalesces MAX_STREAM_DATA(8192) + MAX_DATA(12288) with STREAM */
                    poll(NULL, 0, 200);
                    check("hy2 B2 grant-loss: write 1000B with piggybacked grant V2=8192", 0,
                          transport_write(&tc, cli_tx_all, 1000));

                    /* Pump PTO while server drops the piggybacked STREAM+grant packet and recovers both on PTO */
                    for (int w = 0; w < 80 && !gctx->piggybacked_grant_recovered; w++) {
                        poll(NULL, 0, 25);
                        (void)transport_room(&tc);
                    }

                    /* 3. Wait for remaining server bytes (up to 8189B total payload):
                     * Read 2048B (s4_rx_consumed=6144 -> V3=10240, dropped by server)
                     * Then immediately read final 2048B (s4_rx_consumed=8192 -> V4=12288, accepted & ACKed by server) */
                    while (cli_rx_got < 6141) {
                        if (!transport_has_data(&tc)) poll(&cpfd, 1, 25);
                        size_t sg = 0;
                        if (transport_read(&tc, cli_rx_all + cli_rx_got, 6141 - cli_rx_got, &sg) == 0 && sg > 0)
                            cli_rx_got += sg;
                    }
                    while (cli_rx_got < 8189) {
                        if (!transport_has_data(&tc)) poll(&cpfd, 1, 25);
                        size_t sg = 0;
                        if (transport_read(&tc, cli_rx_all + cli_rx_got, 8189 - cli_rx_got, &sg) == 0 && sg > 0)
                            cli_rx_got += sg;
                    }
                    check("hy2 B2 grant-loss: client received all 8189 server payload bytes after grant recoveries",
                          8189, (int)cli_rx_got);

                    /* 4. Send 4 more 500B chunks (total 3000B client payload) so 3 ACKs after V3 mark stale V3 lost */
                    for (int c_i = 0; c_i < 4; c_i++) {
                        check("hy2 B2 grant-loss: write 500B chunk after V4", 0,
                              transport_write(&tc, cli_tx_all + 1000 + c_i * 500, 500));
                        poll(&cpfd, 1, 10);
                        (void)transport_room(&tc);
                    }
                    for (int w = 0; w < 40 && gctx->rx_total < 3000; w++) {
                        poll(&cpfd, 1, 15);
                        (void)transport_room(&tc);
                    }
                    transport_close(&tc);
                }
                pthread_join(th, NULL);
                int64_t elapsed_ms = now_ms() - t_start_ms;
                close(sv[1]);

                check("hy2 B2 grant-loss: server paused at initial 4096B window without sending BLOCKED",
                      1, gctx->paused_at_initial_limit);
                check("hy2 B2 grant-loss: standalone MAX_STREAM_DATA/MAX_DATA grant dropped",
                      1, gctx->dropped_standalone_grant);
                check("hy2 B2 grant-loss: repeated grant loss injected",
                      1, gctx->dropped_grant_repeat);
                check("hy2 B2 grant-loss: grant ACK loss injected",
                      1, gctx->dropped_grant_ack);
                check("hy2 B2 grant-loss: standalone grant recovered via PTO and unblocked server",
                      1, gctx->standalone_grant_recovered);
                check("hy2 B2 grant-loss: piggybacked STREAM + MAX_STREAM_DATA/MAX_DATA packet dropped",
                      1, gctx->dropped_piggybacked_grant);
                check("hy2 B2 grant-loss: piggybacked STREAM + grant recovered together",
                      1, gctx->piggybacked_grant_recovered);
                check("hy2 B2 grant-loss: older V3(10240) grant dropped before V4(12288) ACKed",
                      1, gctx->dropped_stale_v3 && gctx->saw_v4_grant);
                check("hy2 B2 grant-loss: losing older V3 grant never regressed or re-sent stale window",
                      0, gctx->saw_stale_grant_regression);
                check("hy2 B2 grant-loss: final server max_stream_data is V4 (12288)",
                      12288, (int)gctx->max_msd_seen);
                check("hy2 B2 grant-loss: final server max_data is 16384",
                      16384, (int)gctx->max_md_seen);
                int srv_rx_match = (cli_rx_got == 8189);
                for (size_t i = 0; i < 8189 && srv_rx_match; i++) {
                    if (cli_rx_all[i] != (unsigned char)((i * 29 + 11) & 0xFF)) srv_rx_match = 0;
                }
                check("hy2 B2 grant-loss: server->client 8189B stream matches byte-for-byte", 1, srv_rx_match);
                int cli_tx_match = (gctx->rx_total == 3000);
                for (size_t i = 0; i < 3000 && cli_tx_match; i++) {
                    if (gctx->rx_stream[i] != cli_tx_all[i]) cli_tx_match = 0;
                }
                check("hy2 B2 grant-loss: client->server 3000B stream matches byte-for-byte", 1, cli_tx_match);
                check("hy2 B2 grant-loss: bounded recovery completion time (< 2000 ms)",
                      1, elapsed_ms > 0 && elapsed_ms < 2000);
                free(gctx);
            }

            /* B2 Scenario 3: Multi-Fragment Hysteria2 UDP Datagram Send & Out-of-Order Reassembly */
            {
                int sv[2];
                check("hy2 B2 udp-frag: socketpair", 0, socketpair(AF_UNIX, SOCK_DGRAM, 0, sv));
                struct hy2_udp_srv_ctx uctx;
                memset(&uctx, 0, sizeof(uctx));
                uctx.fd = sv[1];
                pthread_t th;
                pthread_create(&th, NULL, hy2_udp_srv_thread, &uctx);

                g_give_fd = sv[0];
                g_tcp_dial = fake_dial;
                struct transport tc;
                int orc = vless_connect(&hyn, &tc, 2);
                g_tcp_dial = NULL;
                check("hy2 B2 udp-frag: vless_connect", 0, orc);
                if (orc == 0) {
                    /* Open UDP mode: [0x81 (UDP | IPv4)][1.1.1.1][port=53] */
                    unsigned char uhdr[7] = { 0x81, 1, 1, 1, 1, 0, 53 };
                    check("hy2 B2 udp-frag: write UDP addr header", 0, transport_write(&tc, uhdr, 7));

                    /* Send a 2500-byte UDP datagram payload (split into 3 QUIC DATAGRAM fragments of 1100, 1100, 300B) */
                    unsigned char udgram[2500];
                    for (size_t i = 0; i < 2500; i++) udgram[i] = (unsigned char)((i * 19 + 3) & 0xFF);
                    check("hy2 B2 udp-frag: write 2500B UDP datagram", 0,
                          transport_write(&tc, udgram, sizeof(udgram)));

                    /* Read 2400-byte UDP datagram sent back in 3 out-of-order fragments by server */
                    struct pollfd cpfd = { .fd = tc.link.fd, .events = POLLIN, .revents = 0 };
                    unsigned char urx[2 + 2400];
                    size_t ugot = 0;
                    for (int i = 0; i < 40 && ugot < sizeof(urx); i++) {
                        if (!transport_has_data(&tc)) poll(&cpfd, 1, 50);
                        size_t sg = 0;
                        if (transport_read(&tc, urx + ugot, sizeof(urx) - ugot, &sg) == 0 && sg > 0)
                            ugot += sg;
                    }
                    check("hy2 B2 udp-frag: received reassembled 2402B UDP frame", 2402, (int)ugot);
                    int ulen_hdr = ((int)urx[0] << 8) | urx[1];
                    check("hy2 B2 udp-frag: reassembled UDP length prefix is 2400", 2400, ulen_hdr);
                    int umatch = 1;
                    for (size_t i = 0; i < 2400; i++) {
                        if (urx[2 + i] != (unsigned char)(i & 0xFF)) { umatch = 0; break; }
                    }
                    check("hy2 B2 udp-frag: out-of-order UDP fragments reassembled byte-for-byte", 1, umatch);
                    transport_close(&tc);
                }
                pthread_join(th, NULL);
                close(sv[1]);

                check("hy2 B2 udp-frag: server received all 3 fragments from client", 1, uctx.got_all_3_frags);
                check("hy2 B2 udp-frag: server reassembled 2500B from client", 2500, (int)uctx.reassembled_len);
                int cmatch = 1;
                for (size_t i = 0; i < 2500; i++) {
                    if (uctx.reassembled[i] != (unsigned char)((i * 19 + 3) & 0xFF)) { cmatch = 0; break; }
                }
                check("hy2 B2 udp-frag: client fragmented UDP payload matches byte-for-byte", 1, cmatch);
            }

            vless_set_enable_hy2(0);
            check("hy2 B1+B2+B3: descriptor count restored", fd0, fd_count());
            check("hy2 B1+B2+B3: nothing left on the heap", 0, LEAK_CHECK());
        }
        g_cert_roots = NULL;
        chain_free();
    }
#else
    printf("\nWARNING: built WITHOUT certificate issuing (no STEER_HAVE_X509WRITE, tests/certgen.c):\n");
    printf("         the security=tls cases are SKIPPED: neither a passing server check\n");
    printf("         nor the TR_ENOH2 path with its transport_close is tested here.\n\n");
#endif

    /* security=none: no TLS at all. It checks the test rather than the client: if the seam
     * handed over a bad socket, success would fail too, and the failure checks above would pass
     * for the wrong reason. */
    {
        struct vless_node plain;
        memset(&plain, 0, sizeof(plain));
        snprintf(plain.host, sizeof(plain.host), "%s", "node.invalid");
        plain.port = 443;
        snprintf(plain.type, sizeof(plain.type), "%s", "tcp");
        snprintf(plain.security, sizeof(plain.security), "%s", "none");

        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return 2;
        g_give_fd = sv[0];
        g_tcp_dial = fake_dial;
        struct transport c;
        int rc = vless_connect(&plain, &c, 3);
        g_tcp_dial = NULL;
        check("security=none over tcp: connection established", 0, rc);
        check("security=none: no TLS set up", 1, c.link.plain);
        if (rc == 0) transport_close(&c);
        /* Closed, not only marked closed: the other end of the pair reads end of stream (the
         * client wrote nothing, and nothing else holds its end). */
        unsigned char b;
        check("security=none: transport_close closed the descriptor", 0,
              recv(sv[1], &b, 1, MSG_DONTWAIT));
        close(sv[1]);
        check("security=none: nothing left on the heap", 0, LEAK_CHECK());
    }

    /* Shadowsocks AEAD (SIP004) and SS-2022 (SIP022) stream encryption/decryption over tcp:
     * verifies that transport_open attaches tr_venc (ss_open), encrypts the SOCKS5 target
     * address + payload on write (no plaintext on the wire), and decrypts the server's
     * encrypted response chunks on read. */
    {
        struct vless_node ssn;
        memset(&ssn, 0, sizeof(ssn));
        snprintf(ssn.proto, sizeof(ssn.proto), "%s", "ss");
        snprintf(ssn.host, sizeof(ssn.host), "%s", "node.invalid");
        ssn.port = 8388;
        snprintf(ssn.uuid, sizeof(ssn.uuid), "%s", "aes-256-gcm:my-secret-password");
        snprintf(ssn.type, sizeof(ssn.type), "%s", "tcp");
        snprintf(ssn.security, sizeof(ssn.security), "%s", "none");

        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return 2;
        g_give_fd = sv[0];
        g_tcp_dial = fake_dial;
        struct transport c;
        int rc = vless_connect(&ssn, &c, 3);
        g_tcp_dial = NULL;
        check("ss aes-256-gcm: connection established with AEAD layer", 0, rc);
        check("ss aes-256-gcm: c.enc attached", 1, c.enc != NULL);

        unsigned char req_plain[64];
        size_t alen = ss_build_addr("example.com", NULL, 443, req_plain, sizeof(req_plain));
        const char *http_req = "GET / HTTP/1.1\r\n\r\n";
        size_t hlen = strlen(http_req);
        memcpy(req_plain + alen, http_req, hlen);
        size_t total_plain = alen + hlen;

        check("ss aes-256-gcm: transport_write succeeds", 0,
              transport_write(&c, req_plain, total_plain));

        unsigned char wire[256];
        ssize_t wn = recv(sv[1], wire, sizeof(wire), 0);
        /* 32B salt + (2B len + 16B tag) + (total_plain + 16B tag) */
        check("ss aes-256-gcm: wire length matches salt + AEAD chunk",
              (long)(32 + 18 + total_plain + 16), (long)wn);
        /* Wire must not contain plaintext "example.com" */
        int found_plain = 0;
        for (ssize_t i = 0; i + 11 <= wn; i++) {
            if (!memcmp(wire + i, "example.com", 11)) found_plain = 1;
        }
        check("ss aes-256-gcm: no plaintext target host on wire", 0, found_plain);

        /* Derive server key and decrypt client's chunk to verify wire format */
        unsigned char psk[32], prev[16];
        const char *pass = "my-secret-password";
        size_t plen = strlen(pass), gen = 0;
        while (gen < 32) {
            struct sc_hash_ctx hc;
            sc_hash_init(&hc, SC_MD5);
            if (gen > 0) sc_hash_update(&hc, prev, 16);
            sc_hash_update(&hc, pass, plen);
            sc_hash_final(&hc, prev);
            sc_hash_free(&hc);
            memcpy(psk + gen, prev, 16);
            gen += 16;
        }
        unsigned char c_subkey[32];
        sc_hkdf(SC_SHA1, wire, 32, psk, 32, "ss-subkey", 9, c_subkey, 32);
        struct sc_aead srv_rd;
        sc_aead_setkey(&srv_rd, SC_AES256_GCM, c_subkey);
        unsigned char n0[12] = {0}, n1[12] = {1, 0};
        check("ss aes-256-gcm: server opens length header", 0,
              sc_aead_open(&srv_rd, n0, NULL, 0, wire + 32, 2, wire + 34));
        size_t clen = ((size_t)wire[32] << 8) | wire[33];
        check("ss aes-256-gcm: decrypted chunk length matches", (long)total_plain, (long)clen);
        check("ss aes-256-gcm: server opens payload", 0,
              sc_aead_open(&srv_rd, n1, NULL, 0, wire + 50, clen, wire + 50 + clen));
        check("ss aes-256-gcm: decrypted payload matches request", 0,
              memcmp(wire + 50, req_plain, total_plain));
        sc_aead_free(&srv_rd);

        /* Server sends encrypted response back to client */
        unsigned char srv_wire[128];
        memset(srv_wire, 0x42, 32); /* 32B server salt */
        unsigned char s_subkey[32];
        sc_hkdf(SC_SHA1, srv_wire, 32, psk, 32, "ss-subkey", 9, s_subkey, 32);
        struct sc_aead srv_wr;
        sc_aead_setkey(&srv_wr, SC_AES256_GCM, s_subkey);
        const char *http_resp = "HTTP/1.1 200 OK\r\n\r\n";
        size_t rlen = strlen(http_resp);
        srv_wire[32] = (unsigned char)(rlen >> 8);
        srv_wire[33] = (unsigned char)rlen;
        sc_aead_seal(&srv_wr, n0, NULL, 0, srv_wire + 32, 2, srv_wire + 34);
        memcpy(srv_wire + 50, http_resp, rlen);
        sc_aead_seal(&srv_wr, n1, NULL, 0, srv_wire + 50, rlen, srv_wire + 50 + rlen);
        sc_aead_free(&srv_wr);
        check("ss aes-256-gcm: server writes encrypted response", 0,
              wr_all(sv[1], srv_wire, 50 + rlen + 16));

        unsigned char rx_buf[128];
        size_t got = 0;
        check("ss aes-256-gcm: transport_read decrypts response", 0,
              transport_read(&c, rx_buf, sizeof(rx_buf), &got));
        check("ss aes-256-gcm: decrypted response length", (long)rlen, (long)got);
        check("ss aes-256-gcm: decrypted response content", 0,
              memcmp(rx_buf, http_resp, rlen));

        transport_close(&c);
        close(sv[1]);
        check("ss aes-256-gcm: nothing left on the heap", 0, LEAK_CHECK());
    }
    {
        struct vless_node ss22;
        memset(&ss22, 0, sizeof(ss22));
        snprintf(ss22.proto, sizeof(ss22.proto), "%s", "ss");
        snprintf(ss22.host, sizeof(ss22.host), "%s", "node.invalid");
        ss22.port = 8388;
        /* 16 bytes of 0x11 in base64: EREQEBAQEBAQEBAQEBAQEA== (16 bytes of 0x10..0x11)
         * Let's use 16 zero bytes: AAAAAAAAAAAAAAAAAAAAAA== */
        snprintf(ss22.uuid, sizeof(ss22.uuid), "%s", "2022-blake3-aes-128-gcm:AAAAAAAAAAAAAAAAAAAAAA==");
        snprintf(ss22.type, sizeof(ss22.type), "%s", "tcp");
        snprintf(ss22.security, sizeof(ss22.security), "%s", "none");

        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return 2;
        g_give_fd = sv[0];
        g_tcp_dial = fake_dial;
        struct transport c;
        int rc = vless_connect(&ss22, &c, 3);
        g_tcp_dial = NULL;
        check("ss-2022 aes-128-gcm: connection established", 0, rc);

        unsigned char req_plain[64];
        size_t alen = ss_build_addr("example.com", NULL, 443, req_plain, sizeof(req_plain));
        const char *http_req = "PING";
        size_t hlen = strlen(http_req);
        memcpy(req_plain + alen, http_req, hlen);
        size_t total_plain = alen + hlen;

        check("ss-2022 aes-128-gcm: first transport_write succeeds", 0,
              transport_write(&c, req_plain, total_plain));

        unsigned char wire[256];
        ssize_t wn = recv(sv[1], wire, sizeof(wire), 0);
        /* 16B salt + (11B fixed hdr + 16B tag) + (total_plain + 2B pad_len + 16B tag) */
        check("ss-2022 aes-128-gcm: wire length matches SIP022 request stream",
              (long)(16 + 27 + total_plain + 2 + 16), (long)wn);

        /* Server sends SIP022 response header + payload */
        unsigned char srv_wire[128];
        memset(srv_wire, 0x77, 16); /* 16B server salt */
        unsigned char mat[32];
        memset(mat, 0, 16);         /* 16 zero bytes PSK */
        memcpy(mat + 16, srv_wire, 16);
        unsigned char s_subkey[16];
        sc_blake3_derive_key(s_subkey, 16, "shadowsocks 2022 session subkey", 31, mat, 32);
        struct sc_aead srv_wr;
        sc_aead_setkey(&srv_wr, SC_AES128_GCM, s_subkey);
        unsigned char n0[12] = {0}, n1[12] = {1, 0};
        /* SIP022 response fixed header: [0x01][8B ts][16B client_salt][u16 payload_len] = 27B */
        unsigned char *rh = srv_wire + 16;
        rh[0] = 0x01;
        memset(rh + 1, 0, 8);
        memcpy(rh + 9, wire, 16); /* echo client salt */
        const char *pong = "PONG";
        size_t rlen = strlen(pong);
        rh[25] = (unsigned char)(rlen >> 8);
        rh[26] = (unsigned char)rlen;
        sc_aead_seal(&srv_wr, n0, NULL, 0, rh, 27, rh + 27);
        unsigned char *rp = rh + 43;
        memcpy(rp, pong, rlen);
        sc_aead_seal(&srv_wr, n1, NULL, 0, rp, rlen, rp + rlen);
        sc_aead_free(&srv_wr);
        check("ss-2022 aes-128-gcm: server writes SIP022 response", 0,
              wr_all(sv[1], srv_wire, 16 + 43 + rlen + 16));

        unsigned char rx_buf[64];
        size_t got = 0;
        check("ss-2022 aes-128-gcm: transport_read decrypts SIP022 response", 0,
              transport_read(&c, rx_buf, sizeof(rx_buf), &got));
        check("ss-2022 aes-128-gcm: decrypted response length", (long)rlen, (long)got);
        check("ss-2022 aes-128-gcm: decrypted response content", 0,
              memcmp(rx_buf, pong, rlen));

        transport_close(&c);
        close(sv[1]);
        check("ss-2022 aes-128-gcm: nothing left on the heap", 0, LEAK_CHECK());
    }
    {
        struct vless_node any;
        memset(&any, 0, sizeof(any));
        snprintf(any.proto, sizeof(any.proto), "%s", "anytls");
        snprintf(any.host, sizeof(any.host), "%s", "node.invalid");
        any.port = 443;
        snprintf(any.uuid, sizeof(any.uuid), "%s", "anytls-secret");
        snprintf(any.type, sizeof(any.type), "%s", "tcp");
        snprintf(any.security, sizeof(any.security), "%s", "none");

        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return 2;
        g_give_fd = sv[0];
        g_tcp_dial = fake_dial;
        struct transport c;
        int rc = vless_connect(&any, &c, 3);
        g_tcp_dial = NULL;
        check("anytls: connection established with 0-RTT prewrite", 0, rc);

        unsigned char req_plain[64];
        size_t alen = ss_build_addr("example.com", NULL, 443, req_plain, sizeof(req_plain));
        const char *http_req = "PING";
        size_t hlen = strlen(http_req);
        memcpy(req_plain + alen, http_req, hlen);
        size_t total_plain = alen + hlen;

        check("anytls: first transport_write sends prewrite + PSH", 0,
              transport_write(&c, req_plain, total_plain));

        unsigned char wire[256];
        ssize_t wn = recv(sv[1], wire, sizeof(wire), 0);
        static const char settings[] = "v=2\nclient=tunvless\npadding-md5=04cfa2939c724322dc67282362a8f718";
        size_t slen = sizeof(settings) - 1;
        size_t pre_n = 34 + 7 + slen + 7;
        check("anytls: wire length matches 34B auth + cmdSettings + cmdSyn + cmdPush",
              (long)(pre_n + 7 + total_plain), (long)wn);
        unsigned char exp_sha[32];
        sc_hash(SC_SHA256, "anytls-secret", 13, exp_sha);
        check("anytls: wire starts with SHA-256(password)", 0, memcmp(wire, exp_sha, 32));
        check("anytls: frame 1 is cmd=4 (cmdSettings)", 4, (long)wire[34]);
        check("anytls: frame 2 is cmd=1 (cmdSyn) sid=1", 1,
              wire[34 + 7 + slen] == 1 && wire[34 + 7 + slen + 4] == 1);
        check("anytls: frame 3 is cmd=2 (cmdPsh) sid=1", 1,
              wire[pre_n] == 2 && wire[pre_n + 4] == 1 &&
              (((size_t)wire[pre_n + 5] << 8) | wire[pre_n + 6]) == total_plain);
        check("anytls: PSH payload matches SOCKS5 target + data", 0,
              memcmp(wire + pre_n + 7, req_plain, total_plain));

        /* Server sends cmdSynAck (cmd=7, len=0) followed by cmdPsh (cmd=2, len=4, "PONG") */
        unsigned char srv_wire[18] = {
            7, 0, 0, 0, 1, 0, 0,
            2, 0, 0, 0, 1, 0, 4, 'P', 'O', 'N', 'G'
        };
        check("anytls: server writes cmdSynAck + cmdPush response", 0,
              wr_all(sv[1], srv_wire, sizeof(srv_wire)));

        unsigned char rx_buf[64];
        size_t got = 0;
        check("anytls: transport_read parses frames and returns PSH payload", 0,
              transport_read(&c, rx_buf, sizeof(rx_buf), &got));
        check("anytls: response length is 4", 4, (long)got);
        check("anytls: response content is PONG", 0, memcmp(rx_buf, "PONG", 4));

        transport_close(&c);
        close(sv[1]);
        check("anytls: nothing left on the heap", 0, LEAK_CHECK());
    }
    {
        struct vless_node trj;
        memset(&trj, 0, sizeof(trj));
        snprintf(trj.proto, sizeof(trj.proto), "%s", "trojan");
        snprintf(trj.host, sizeof(trj.host), "%s", "node.invalid");
        trj.port = 443;
        snprintf(trj.uuid, sizeof(trj.uuid), "%s", "trojan-secret");
        snprintf(trj.type, sizeof(trj.type), "%s", "tcp");
        snprintf(trj.security, sizeof(trj.security), "%s", "none");

        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return 2;
        g_give_fd = sv[0];
        g_tcp_dial = fake_dial;
        struct transport c;
        int rc = vless_connect(&trj, &c, 3);
        g_tcp_dial = NULL;
        check("trojan: connection established", 0, rc);

        unsigned char req_buf[128];
        size_t hdr_n = trojan_build_request(trj.uuid, VLESS_CMD_TCP, "example.com", NULL, 443, req_buf, sizeof(req_buf));
        memcpy(req_buf + hdr_n, "PING", 4);
        check("trojan: transport_write sends SHA224 header + payload", 0, transport_write(&c, req_buf, hdr_n + 4));

        unsigned char wire[128];
        ssize_t wn = recv(sv[1], wire, sizeof(wire), 0);
        char exp_hex[57];
        trojan_sha224_hex("trojan-secret", exp_hex);
        check("trojan: wire starts with SHA224(password) + CRLF", 0,
              wn == (ssize_t)(hdr_n + 4) ? memcmp(wire, exp_hex, 56) : -1);
        check("trojan: wire ends with CRLF + PING", 0, memcmp(wire + hdr_n - 2, "\r\nPING", 6));

        check("trojan: server writes PONG", 0, wr_all(sv[1], (const unsigned char *)"PONG", 4));
        unsigned char rx_buf[32];
        size_t got = 0;
        check("trojan: transport_read receives PONG", 0, transport_read(&c, rx_buf, sizeof(rx_buf), &got));
        check("trojan: response matches PONG", 0, got == 4 ? memcmp(rx_buf, "PONG", 4) : -1);
        transport_close(&c);
        close(sv[1]);
    }
    {
        struct vless_node s5;
        memset(&s5, 0, sizeof(s5));
        snprintf(s5.proto, sizeof(s5.proto), "%s", "socks5");
        snprintf(s5.host, sizeof(s5.host), "%s", "10.0.0.1");
        s5.port = 1080;
        snprintf(s5.uuid, sizeof(s5.uuid), "%s", "suser:spass");
        snprintf(s5.type, sizeof(s5.type), "%s", "tcp");
        snprintf(s5.security, sizeof(s5.security), "%s", "none");

        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return 2;
        static const unsigned char s5_srv_hs[4] = { 0x05, 0x02, 0x01, 0x00 };
        wr_all(sv[1], s5_srv_hs, sizeof(s5_srv_hs));
        g_give_fd = sv[0];
        g_tcp_dial = fake_dial;
        struct transport c;
        int rc = vless_connect(&s5, &c, 3);
        g_tcp_dial = NULL;
        check("socks5: RFC1929 auth handshake established", 0, rc);

        unsigned char hs_wire[64];
        ssize_t hwn = recv(sv[1], hs_wire, sizeof(hs_wire), 0);
        static const unsigned char exp_hs[] = {
            0x05, 0x02, 0x00, 0x02,
            0x01, 0x05, 's', 'u', 's', 'e', 'r', 0x05, 's', 'p', 'a', 's', 's'
        };
        check("socks5: client sent greeting + RFC1929 credentials", 0,
              hwn == (ssize_t)sizeof(exp_hs) ? memcmp(hs_wire, exp_hs, sizeof(exp_hs)) : -1);

        unsigned char req_buf[64];
        size_t req_n = socks5_build_connect("example.com", NULL, 80, req_buf, sizeof(req_buf));
        memcpy(req_buf + req_n, "PING", 4);
        check("socks5: transport_write sends CONNECT + payload", 0, transport_write(&c, req_buf, req_n + 4));

        static const unsigned char s5_rep[] = { 0x05, 0x00, 0x00, 0x01, 10, 0, 0, 1, 0x00, 0x50, 'P', 'O', 'N', 'G' };
        check("socks5: server writes CONNECT reply + PONG", 0, wr_all(sv[1], s5_rep, sizeof(s5_rep)));
        unsigned char rx_buf[64];
        size_t got = 0, skip = 0;
        check("socks5: transport_read receives reply + PONG", 0, transport_read(&c, rx_buf, sizeof(rx_buf), &got));
        check("socks5: socks5_parse_reply strips 10B BND.ADDR header", 0,
              socks5_parse_reply(rx_buf, got, &skip) == 0 && skip == 10 && got == 14 && !memcmp(rx_buf + skip, "PONG", 4) ? 0 : -1);
        transport_close(&c);
        close(sv[1]);
    }
    /* B4: VMess AEAD 16-bit chunk counter exhaustion check (must fail cleanly after chunk 0xFFFF
     * instead of wrapping around and reusing nonce 0). */
    {
        struct vless_node vmn;
        memset(&vmn, 0, sizeof(vmn));
        snprintf(vmn.proto, sizeof(vmn.proto), "%s", "vmess");
        snprintf(vmn.host, sizeof(vmn.host), "%s", "node.invalid");
        vmn.port = 443;
        snprintf(vmn.uuid, sizeof(vmn.uuid), "%s", "aes-128-gcm:11111111-2222-3333-4444-555555555555");
        snprintf(vmn.type, sizeof(vmn.type), "%s", "tcp");
        snprintf(vmn.security, sizeof(vmn.security), "%s", "none");

        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return 2;
        g_give_fd = sv[0];
        g_tcp_dial = fake_dial;
        struct transport c;
        int rc = vless_connect(&vmn, &c, 3);
        g_tcp_dial = NULL;
        check("vmess B4: connection established", 0, rc);

        unsigned char req_plain[64];
        size_t alen = ss_build_addr("example.com", NULL, 443, req_plain, sizeof(req_plain));
        memcpy(req_plain + alen, "FIRST", 5);
        check("vmess B4: initial request header + chunk 0 write succeeds", 0,
              transport_write(&c, req_plain, alen + 5));
        unsigned char drain[512];
        (void)recv(sv[1], drain, sizeof(drain), 0);

        /* Advance TX counter to 0xFFFF (last valid 16-bit nonce) */
        tr_venc_test_set_vmess_counts(&c, 0xFFFFu, 0);
        check("vmess B4: chunk 0xFFFF (65535) write succeeds", 0,
              transport_write(&c, (const unsigned char *)"LAST", 4));
        (void)recv(sv[1], drain, sizeof(drain), 0);

        /* Next write at 0x10000 (65536) must fail with TR_EVENC instead of wrapping nonce to 0 */
        check("vmess B4: chunk 0x10000 (65536) refused with TR_EVENC", TR_EVENC,
              transport_write(&c, (const unsigned char *)"WRAP", 4));
        check_str("vmess B4: TX nonce exhaustion reason reported",
                  "VMess AEAD TX nonce limit reached", tr_venc_reason());

        transport_close(&c);
        close(sv[1]);
        check("vmess B4: nothing left on the heap", 0, LEAK_CHECK());
    }
    {
        int fds0 = fd_count();
        /* Regression: hy2 transport_open initializes struct transport before disabled gate check,
         * and rejects overlong SNI (>255B) cleanly without buffer overflow or fd/heap leak. */
        vless_set_enable_hy2(0);
        struct transport hy_uninit;
        memset(&hy_uninit, 0x5A, sizeof(hy_uninit));
        struct tr_node htn;
        memset(&htn, 0, sizeof(htn));
        htn.proto = "hy2";
        htn.host = "127.0.0.1";
        htn.port = 8443;
        htn.type = "quic";
        htn.security = "tls";
        htn.uuid = "secret";
        check("hy2 disabled: transport_open returns TR_ENONODE", TR_ENONODE,
              transport_open(&hy_uninit, &htn, 1));
        transport_close(&hy_uninit); /* must not crash on uninitialized fields */

        vless_set_enable_hy2(1);
        char overlong_sni[301];
        memset(overlong_sni, 'a', 300);
        overlong_sni[300] = '\0';
        htn.sni = overlong_sni;
        int hysv[2];
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, hysv) != 0) return 2;
        g_give_fd = hysv[0];
        g_tcp_dial = fake_dial;
        struct transport hy_long;
        int hyrc = transport_open(&hy_long, &htn, 1);
        g_tcp_dial = NULL;
        close(hysv[1]);
        vless_set_enable_hy2(0);
        check("hy2 overlong sni (>255B): rejected with TR_EIO", TR_EIO, hyrc);
        check("hy2 overlong sni: no leaked descriptors", fds0, fd_count());
        check("hy2 overlong sni: nothing left on the heap", 0, LEAK_CHECK());
    }

#if !defined(__SANITIZE_ADDRESS__)
    printf("\nWARNING: built WITHOUT AddressSanitizer: the 'nothing left on the heap' checks\n");
    printf("         are vacuous. Return codes and descriptors are checked, the heap is NOT.\n");
#endif
    printf("\n%s\n", fails ? "SOME CHECKS FAILED" : "all checks passed");
    return fails ? 1 : 0;
}
