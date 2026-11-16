/* Hysteria2 transport over QUIC v1 (RFC 9000 / RFC 9001) + HTTP/3 + Salamander obfuscation.
 *
 * Implements:
 *   1. Salamander UDP obfuscation: [8-byte salt][payload ^ BLAKE2b-256(obfs_pass || salt)]
 *   2. QUIC v1 Initial, Handshake, and 1-RTT packet protection & header protection
 *   3. QUIC TLS 1.3 handshake with ALPN "h3", quic_transport_parameters (0x0039), and
 *      server certificate verification via cert_verify_server_ex
 *   4. HTTP/3 Control stream (Stream 2) + Hysteria2 Auth stream (Stream 0: POST /auth -> 233)
 *   5. Hysteria2 TCP proxy stream (Stream 4: varint 0x401) and UDP relay (DATAGRAM 0x31)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <sys/socket.h>

#include "transport.h"
#include "h2wire.h"
#include "reality.h"
#include "roots.h"
#include "certverify.h"

extern int vless_enable_hy2(void);

#define HY2_MAX_PKT         1600
#define HY2_INITIAL_MIN     1200
#define HY2_CRYPTO_CAP      16384
#define HY2_RX_CAP          65536
#define HY2_TX_CAP          262144u /* 256 KiB power-of-2 ring buffer for Stream 4 */
#define QUIC_MAX_ACK_RANGES 32
#define QUIC_SENT_MAX       256
#define QUIC_RETX_MAX       256

struct quic_pn_range {
    uint64_t low;
    uint64_t high;
};

struct quic_rx_space {
    struct quic_pn_range ranges[QUIC_MAX_ACK_RANGES];
    size_t n_ranges;
    int64_t largest_rx_us;
    uint32_t ack_eliciting_cnt;
    int ack_needed;
};

struct quic_sent_pkt {
    uint64_t pn;
    int64_t  sent_us;
    uint16_t bytes;
    uint8_t  in_use;
    uint8_t  level;          /* 0=Initial, 1=Handshake, 2=1-RTT */
    uint8_t  ack_eliciting;
    uint8_t  in_flight;
    uint8_t  has_crypto;
    uint8_t  has_s2;
    uint8_t  has_stream;
    uint8_t  fin;
    uint8_t  has_win_update;
    uint8_t  has_s4_blocked;
    uint8_t  has_conn_blocked;
    uint64_t sid;
    uint64_t soff;
    uint32_t slen;
    uint32_t coff;
    uint32_t clen;
    uint64_t msd_val;
    uint64_t md_val;
    uint64_t s4_blocked_val;
    uint64_t conn_blocked_val;
};

struct quic_fc_meta {
    uint8_t  has_win_update;
    uint8_t  has_s4_blocked;
    uint8_t  has_conn_blocked;
    uint64_t msd_val;
    uint64_t md_val;
    uint64_t s4_blocked_val;
    uint64_t conn_blocked_val;
};

struct quic_retx_range {
    uint64_t soff;
    uint32_t slen;
    uint8_t  fin;
    uint8_t  in_use;
};

struct hy2_udp_reasm {
    uint16_t pkt_id;
    uint8_t  frag_cnt;
    uint8_t  in_use;
    uint32_t got_mask;
    uint16_t frag_lens[32];
    unsigned char *frags[32];
};

struct quic_level {
    struct sc_aead aead;
    enum sc_aead_alg alg;
    unsigned char iv[12];
    unsigned char hp[32];
    size_t klen;
    uint64_t pn;
    uint64_t max_rx_pn;
    int have_rx_pn;
    int ready;
};

struct hy2_ctx {
    int fd;
    int timeout_s;
    char obfs_pass[64];
    unsigned char scid[8];
    unsigned char dcid[20];
    size_t dcid_len;
    int got_server_scid;

    enum sc_hash hash_alg;
    enum sc_aead_alg suite_alg;
    size_t hash_len;

    struct quic_level tx_init, rx_init;
    struct quic_level tx_hs,   rx_hs;
    struct quic_level tx_app,  rx_app;
    struct sc_aead prev_rx_aead;
    unsigned char prev_rx_iv[12];
    int have_prev_rx;
    unsigned char c_ap_sec[48], s_ap_sec[48];
    uint8_t key_phase;

    /* Per-level received PN intervals for duplicate suppression & SACK frames */
    struct quic_rx_space rx_space[3];

    /* RFC 9002 loss detection, RTT estimation, PTO & NewReno congestion control */
    struct quic_sent_pkt sent_pkts[QUIC_SENT_MAX];
    uint64_t largest_acked_pn[3];
    uint8_t  have_acked_pn[3];
    int64_t  latest_rtt_us;
    int64_t  smoothed_rtt_us;
    int64_t  rttvar_us;
    int64_t  min_rtt_us;
    int64_t  peer_max_ack_delay_us;
    uint8_t  peer_ack_delay_exp;
    uint32_t pto_count;
    uint64_t bytes_in_flight;
    uint64_t cwnd;
    uint64_t ssthresh;
    int64_t  recovery_start_us;

    /* Saved handshake & HTTP/3 control/auth payloads for packet-number-distinct retransmission */
    unsigned char ch_tx[600];
    size_t ch_tx_len;
    uint8_t ch_retx_due;

    unsigned char fin_tx[64];
    size_t fin_tx_len;
    uint8_t fin_retx_due;

    unsigned char s2_tx[8];
    size_t s2_tx_len;
    uint8_t s2_retx_due;

    unsigned char s0_tx[560];
    size_t s0_tx_len;
    uint8_t s0_retx_due;

    /* Stream 4 unacknowledged send ring buffer & retransmission queue */
    unsigned char *s4_tx_buf;
    uint64_t s4_una_off;
    uint64_t s4_sent_off;
    uint64_t s4_write_off;
    struct quic_retx_range s4_retx[QUIC_RETX_MAX];

    /* QUIC send & receive flow control (RFC 9000 §4) */
    uint64_t peer_max_data;
    uint64_t peer_s4_max_data;
    uint64_t peer_uni_max_data;
    uint64_t s4_blocked_at;
    uint64_t conn_blocked_at;
    uint64_t acked_s4_blocked_at;
    uint64_t acked_conn_blocked_at;
    uint8_t  tx_s4_blocked_due;
    uint8_t  tx_conn_blocked_due;
    uint8_t  ping_due;

    uint64_t local_max_data;
    uint64_t local_s4_max_data;
    uint64_t acked_local_max_data;
    uint64_t acked_local_s4_max_data;
    uint64_t local_s4_win;
    uint64_t local_conn_win;
    uint64_t s4_rx_highest;
    uint64_t s4_rx_consumed;
    uint64_t s4_last_win_sent;
    uint8_t  rx_win_update_due;

    /* Handshake CRYPTO stream assembly [0]=Initial, [1]=Handshake */
    unsigned char *crypto_buf[2];
    unsigned char *crypto_seen[2];
    size_t crypto_len[2];
    size_t crypto_off[2];
    int proto_err;

    /* TCP / HTTP3 stream offsets */
    uint64_t s0_tx_off, s0_rx_off;
    uint64_t s2_tx_off;
    uint64_t s4_tx_off, s4_rx_off;

    /* Stream 0 (HTTP/3 Auth response) contiguous reassembly buffer */
    unsigned char s0_buf[2048];
    unsigned char s0_seen[2048];
    size_t s0_contig;
    size_t s0_parse_off;

    /* Out-of-order reassembly slots for Stream 4 (up to 64 segments) */
    struct {
        uint64_t off;
        size_t len;
        int fin;
        unsigned char *data;
    } ooo[64];

    /* Multi-fragment Hysteria2 UDP datagram reassembly slots */
    struct hy2_udp_reasm udp_reasm[4];

    int auth_ok;
    int auth_failed;
    int addr_sent;
    int resp_parsed;
    int is_udp;
    int peer_closed;
    uint32_t udp_sid;
    uint16_t udp_pkt_id;
    char udp_addr[280];

    /* Decrypted stream/datagram payload ready for transport_read */
    unsigned char *rx_buf;
    size_t rx_off, rx_len, rx_cap;

    /* Unparsed raw Stream 4 bytes waiting for Hysteria2 TCP response header */
    unsigned char s4_hdr[4096];
    size_t s4_hdr_len;
};

static int64_t hy2_now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000000LL + (int64_t)(t.tv_nsec / 1000);
}

static int64_t hy2_now_ms(void) {
    return hy2_now_us() / 1000;
}

static size_t quic_put_varint(unsigned char *p, uint64_t v) {
    if (v <= 63) {
        p[0] = (unsigned char)v;
        return 1;
    }
    if (v <= 16383) {
        p[0] = (unsigned char)(0x40u | (v >> 8));
        p[1] = (unsigned char)v;
        return 2;
    }
    if (v <= 1073741823ULL) {
        p[0] = (unsigned char)(0x80u | (v >> 24));
        p[1] = (unsigned char)(v >> 16);
        p[2] = (unsigned char)(v >> 8);
        p[3] = (unsigned char)v;
        return 4;
    }
    p[0] = (unsigned char)(0xC0u | (v >> 56));
    p[1] = (unsigned char)(v >> 48);
    p[2] = (unsigned char)(v >> 40);
    p[3] = (unsigned char)(v >> 32);
    p[4] = (unsigned char)(v >> 24);
    p[5] = (unsigned char)(v >> 16);
    p[6] = (unsigned char)(v >> 8);
    p[7] = (unsigned char)v;
    return 8;
}

static int quic_get_varint(const unsigned char *p, size_t n, uint64_t *val, size_t *used) {
    if (!n) return -1;
    size_t len = (size_t)1u << (p[0] >> 6);
    if (n < len) return -1;
    uint64_t v = p[0] & 0x3Fu;
    for (size_t i = 1; i < len; i++) v = (v << 8) | p[i];
    *val = v;
    *used = len;
    return 0;
}

static int quic_hkdf_label(enum sc_hash alg, const unsigned char *prk, size_t prk_n,
                           const char *label, const unsigned char *ctx, size_t ctx_n,
                           unsigned char *out, size_t out_n) {
    size_t llen = strlen(label);
    unsigned char info[128];
    if (2 + 1 + 6 + llen + 1 + ctx_n > sizeof(info)) return -1;
    info[0] = (unsigned char)(out_n >> 8);
    info[1] = (unsigned char)out_n;
    info[2] = (unsigned char)(6 + llen);
    memcpy(info + 3, "tls13 ", 6);
    memcpy(info + 9, label, llen);
    info[9 + llen] = (unsigned char)ctx_n;
    if (ctx_n) memcpy(info + 10 + llen, ctx, ctx_n);
    return sc_hkdf_expand(alg, prk, prk_n, info, 10 + llen + ctx_n, out, out_n);
}

static void th_snapshot(const struct sc_hash_ctx *th, unsigned char out[48]) {
    struct sc_hash_ctx tmp;
    sc_hash_clone(&tmp, th);
    sc_hash_final(&tmp, out);
    sc_hash_free(&tmp);
}

static int ct_equal(const unsigned char *a, const unsigned char *b, size_t n) {
    unsigned char d = 0;
    for (size_t i = 0; i < n; i++) d |= a[i] ^ b[i];
    return d == 0;
}

static void quic_level_free(struct quic_level *lv) {
    if (lv->ready) sc_aead_free(&lv->aead);
    memset(lv, 0, sizeof(*lv));
}

static int quic_level_setup(struct quic_level *lv, enum sc_hash halg,
                            enum sc_aead_alg aalg, const unsigned char *secret, size_t hlen) {
    quic_level_free(lv);
    size_t klen = (aalg == SC_AES128_GCM) ? 16 : 32;
    unsigned char key[32];
    if (quic_hkdf_label(halg, secret, hlen, "quic key", NULL, 0, key, klen) != 0 ||
        quic_hkdf_label(halg, secret, hlen, "quic iv",  NULL, 0, lv->iv, 12) != 0 ||
        quic_hkdf_label(halg, secret, hlen, "quic hp",  NULL, 0, lv->hp, klen) != 0)
        return -1;
    if (sc_aead_setkey(&lv->aead, aalg, key) != 0) return -1;
    memset(key, 0, sizeof(key));
    lv->alg = aalg;
    lv->klen = klen;
    lv->pn = 0;
    lv->ready = 1;
    return 0;
}

static int quic_hp_mask(const struct quic_level *lv, const unsigned char sample[16], unsigned char mask[5]) {
    if (lv->alg == SC_CHACHA20_POLY1305)
        return sc_chacha20_hp(lv->hp, sample, mask);
    unsigned char blk[16];
    if (sc_aes_block(lv->hp, lv->klen, 0, sample, blk) != 0) return -1;
    memcpy(mask, blk, 5);
    return 0;
}

static void quic_make_nonce(const unsigned char iv[12], uint64_t pn, unsigned char nonce[12]) {
    memcpy(nonce, iv, 12);
    for (int i = 0; i < 8; i++)
        nonce[11 - i] ^= (unsigned char)(pn >> (8 * i));
}

/* Salamander UDP send/recv */
static int hy2_udp_send(struct hy2_ctx *h, const unsigned char *pkt, size_t len) {
    if (!h->obfs_pass[0]) {
        ssize_t w = send(h->fd, pkt, len, MSG_NOSIGNAL);
        return (w == (ssize_t)len) ? 0 : TR_EIO;
    }
    unsigned char obuf[8 + HY2_MAX_PKT + 64];
    if (len > sizeof(obuf) - 8) return TR_EIO;
    unsigned char salt[8], mask[32], in_key[128];
    if (xc_random(salt, 8) != 0) return TR_EIO;
    size_t plen = strlen(h->obfs_pass);
    if (plen > sizeof(in_key) - 8) plen = sizeof(in_key) - 8;
    memcpy(in_key, h->obfs_pass, plen);
    memcpy(in_key + plen, salt, 8);
    sc_blake2b_256(mask, in_key, plen + 8);
    memcpy(obuf, salt, 8);
    for (size_t i = 0; i < len; i++)
        obuf[8 + i] = pkt[i] ^ mask[i & 31];
    ssize_t w = send(h->fd, obuf, 8 + len, MSG_NOSIGNAL);
    return (w == (ssize_t)(8 + len)) ? 0 : TR_EIO;
}

static ssize_t hy2_udp_recv(struct hy2_ctx *h, unsigned char *out, size_t cap, int flags) {
    if (!h->obfs_pass[0])
        return recv(h->fd, out, cap, flags);
    unsigned char raw[2048];
    ssize_t r = recv(h->fd, raw, sizeof(raw), flags);
    if (r <= 0) return r;
    if (r <= 8) return 0;
    size_t plen = (size_t)(r - 8);
    if (plen > cap) plen = cap;
    unsigned char mask[32], in_key[128];
    size_t pass_len = strlen(h->obfs_pass);
    if (pass_len > sizeof(in_key) - 8) pass_len = sizeof(in_key) - 8;
    memcpy(in_key, h->obfs_pass, pass_len);
    memcpy(in_key + pass_len, raw, 8);
    sc_blake2b_256(mask, in_key, pass_len + 8);
    for (size_t i = 0; i < plen; i++)
        out[i] = raw[8 + i] ^ mask[i & 31];
    return (ssize_t)plen;
}

/* ---- Received PN Range Tracking & Multi-Range SACK Generation (RFC 9000 §13.2, §19.3) ---- */

static int quic_rx_pn_is_dup(const struct quic_rx_space *sp, uint64_t pn) {
    for (size_t i = 0; i < sp->n_ranges; i++) {
        if (pn >= sp->ranges[i].low && pn <= sp->ranges[i].high)
            return 1;
    }
    return 0;
}

static int quic_rx_pn_record(struct quic_rx_space *sp, uint64_t pn, int64_t now_us) {
    int was_ooo = (sp->n_ranges > 0 && pn < sp->ranges[0].high) ? 1 : 0;
    if (sp->n_ranges == 0 || pn > sp->ranges[0].high)
        sp->largest_rx_us = now_us;

    for (size_t i = 0; i < sp->n_ranges; i++) {
        if (pn >= sp->ranges[i].low && pn <= sp->ranges[i].high)
            return was_ooo;
        if (pn == sp->ranges[i].high + 1) {
            sp->ranges[i].high = pn;
            if (i > 0 && sp->ranges[i - 1].low == pn + 1) {
                sp->ranges[i - 1].low = sp->ranges[i].low;
                for (size_t j = i; j + 1 < sp->n_ranges; j++)
                    sp->ranges[j] = sp->ranges[j + 1];
                sp->n_ranges--;
            }
            return was_ooo || sp->n_ranges > 1;
        }
        if (sp->ranges[i].low > 0 && pn + 1 == sp->ranges[i].low) {
            sp->ranges[i].low = pn;
            if (i + 1 < sp->n_ranges && sp->ranges[i + 1].high + 1 == pn) {
                sp->ranges[i].low = sp->ranges[i + 1].low;
                for (size_t j = i + 1; j + 1 < sp->n_ranges; j++)
                    sp->ranges[j] = sp->ranges[j + 1];
                sp->n_ranges--;
            }
            return was_ooo || sp->n_ranges > 1;
        }
        if (pn > sp->ranges[i].high) {
            size_t lim = sp->n_ranges < QUIC_MAX_ACK_RANGES ? sp->n_ranges : QUIC_MAX_ACK_RANGES - 1;
            for (size_t j = lim; j > i; j--)
                sp->ranges[j] = sp->ranges[j - 1];
            sp->ranges[i].low = pn;
            sp->ranges[i].high = pn;
            if (sp->n_ranges < QUIC_MAX_ACK_RANGES)
                sp->n_ranges++;
            return was_ooo || sp->n_ranges > 1;
        }
    }

    if (sp->n_ranges < QUIC_MAX_ACK_RANGES) {
        sp->ranges[sp->n_ranges].low = pn;
        sp->ranges[sp->n_ranges].high = pn;
        sp->n_ranges++;
    }
    return was_ooo || sp->n_ranges > 1;
}

static size_t quic_build_ack_ranges(struct quic_rx_space *sp, int64_t now_us,
                                    unsigned char *out, size_t cap) {
    if (sp->n_ranges == 0 || cap < 16) return 0;
    size_t o = 0;
    out[o++] = 0x02; /* ACK frame (RFC 9000 §19.3) */
    o += quic_put_varint(out + o, sp->ranges[0].high);
    uint64_t delay = (now_us > sp->largest_rx_us) ? (uint64_t)(now_us - sp->largest_rx_us) >> 3 : 0;
    o += quic_put_varint(out + o, delay);

    size_t rcnt = sp->n_ranges - 1;
    if (o + 8 + rcnt * 16 > cap) {
        rcnt = (cap > o + 8) ? (cap - o - 8) / 16 : 0;
    }
    o += quic_put_varint(out + o, rcnt);
    o += quic_put_varint(out + o, sp->ranges[0].high - sp->ranges[0].low);

    for (size_t i = 1; i <= rcnt; i++) {
        uint64_t gap = (sp->ranges[i - 1].low - sp->ranges[i].high) - 2;
        uint64_t rlen = sp->ranges[i].high - sp->ranges[i].low;
        o += quic_put_varint(out + o, gap);
        o += quic_put_varint(out + o, rlen);
    }
    sp->ack_needed = 0;
    sp->ack_eliciting_cnt = 0;
    return o;
}

/* ---- RFC 9002 Sent Packet Tracking, Loss Detection, RTT, PTO & NewReno CC ---- */

static void quic_queue_s4_retx(struct hy2_ctx *h, uint64_t soff, uint32_t slen, uint8_t fin) {
    if (!slen && !fin) return;
    for (size_t i = 0; i < QUIC_RETX_MAX; i++) {
        if (h->s4_retx[i].in_use && h->s4_retx[i].soff == soff && h->s4_retx[i].slen == slen) {
            if (fin) h->s4_retx[i].fin = 1;
            return;
        }
    }
    for (size_t i = 0; i < QUIC_RETX_MAX; i++) {
        if (!h->s4_retx[i].in_use) {
            h->s4_retx[i].soff = soff;
            h->s4_retx[i].slen = slen;
            h->s4_retx[i].fin  = fin;
            h->s4_retx[i].in_use = 1;
            return;
        }
    }
}

static uint64_t quic_calc_s4_una(const struct hy2_ctx *h) {
    uint64_t una = h->s4_sent_off;
    for (size_t i = 0; i < QUIC_SENT_MAX; i++) {
        if (h->sent_pkts[i].in_use && h->sent_pkts[i].level == 2 &&
            h->sent_pkts[i].has_stream && h->sent_pkts[i].sid == 4) {
            if (h->sent_pkts[i].soff < una)
                una = h->sent_pkts[i].soff;
        }
    }
    for (size_t i = 0; i < QUIC_RETX_MAX; i++) {
        if (h->s4_retx[i].in_use && h->s4_retx[i].soff < una)
            una = h->s4_retx[i].soff;
    }
    return una;
}

static void quic_advance_local_rx_win(struct hy2_ctx *h, uint64_t ref_off) {
    uint64_t next_s4 = ref_off + h->local_s4_win;
    uint64_t next_md = ref_off + h->local_conn_win;
    if (next_s4 > h->local_s4_max_data) h->local_s4_max_data = next_s4;
    if (next_md > h->local_max_data) h->local_max_data = next_md;
    h->rx_win_update_due = 1;
}

static int quic_resched_fc_on_loss(struct hy2_ctx *h, const struct quic_sent_pkt *p) {
    int resched = 0;
    if (p->level != 2) return 0;
    if (p->has_win_update) {
        if ((p->msd_val > h->acked_local_s4_max_data || p->md_val > h->acked_local_max_data) &&
            (h->acked_local_s4_max_data < h->local_s4_max_data ||
             h->acked_local_max_data < h->local_max_data)) {
            h->rx_win_update_due = 1;
            resched = 1;
        }
    }
    if (p->has_s4_blocked &&
        h->s4_sent_off >= h->peer_s4_max_data &&
        h->s4_sent_off < h->s4_write_off &&
        h->acked_s4_blocked_at != h->peer_s4_max_data) {
        h->tx_s4_blocked_due = 1;
        resched = 1;
    }
    if (p->has_conn_blocked &&
        (h->s0_tx_len + h->s2_tx_len + h->s4_sent_off) >= h->peer_max_data &&
        h->s4_sent_off < h->s4_write_off &&
        h->acked_conn_blocked_at != h->peer_max_data) {
        h->tx_conn_blocked_due = 1;
        resched = 1;
    }
    return resched;
}

static void quic_record_sent(struct hy2_ctx *h, uint8_t level, uint64_t pn, size_t bytes,
                             uint8_t ack_eliciting, uint8_t has_crypto, uint32_t coff, uint32_t clen,
                             uint8_t has_s2, uint8_t has_stream, uint64_t sid,
                             uint64_t soff, uint32_t slen, uint8_t fin,
                             const struct quic_fc_meta *fc) {
    if (!ack_eliciting) return;
    int64_t now_us = hy2_now_us();
    size_t slot = QUIC_SENT_MAX;
    for (size_t i = 0; i < QUIC_SENT_MAX; i++) {
        if (!h->sent_pkts[i].in_use) {
            slot = i;
            break;
        }
    }
    if (slot == QUIC_SENT_MAX) {
        /* Evict oldest entry after queuing its payload for retransmission if needed */
        int64_t oldest_us = INT64_MAX;
        slot = 0;
        for (size_t i = 0; i < QUIC_SENT_MAX; i++) {
            if (h->sent_pkts[i].sent_us < oldest_us) {
                oldest_us = h->sent_pkts[i].sent_us;
                slot = i;
            }
        }
        struct quic_sent_pkt *ev = &h->sent_pkts[slot];
        if (ev->in_flight) {
            if (h->bytes_in_flight >= ev->bytes) h->bytes_in_flight -= ev->bytes;
            else h->bytes_in_flight = 0;
        }
        if (ev->level == 2 && ev->ack_eliciting) {
            if (ev->has_stream && ev->sid == 4)
                quic_queue_s4_retx(h, ev->soff, ev->slen, ev->fin);
            (void)quic_resched_fc_on_loss(h, ev);
        }
    }

    struct quic_sent_pkt *p = &h->sent_pkts[slot];
    memset(p, 0, sizeof(*p));
    p->pn            = pn;
    p->sent_us       = now_us;
    p->bytes         = (uint16_t)(bytes > 65535 ? 65535 : bytes);
    p->in_use        = 1;
    p->level         = level;
    p->ack_eliciting = ack_eliciting;
    p->in_flight     = ack_eliciting;
    p->has_crypto    = has_crypto;
    p->coff          = coff;
    p->clen          = clen;
    p->has_s2        = has_s2;
    p->has_stream    = has_stream;
    p->sid           = sid;
    p->soff          = soff;
    p->slen          = slen;
    p->fin           = fin;
    if (fc) {
        p->has_win_update   = fc->has_win_update;
        p->has_s4_blocked   = fc->has_s4_blocked;
        p->has_conn_blocked = fc->has_conn_blocked;
        p->msd_val          = fc->msd_val;
        p->md_val           = fc->md_val;
        p->s4_blocked_val   = fc->s4_blocked_val;
        p->conn_blocked_val = fc->conn_blocked_val;
    }
    if (p->in_flight)
        h->bytes_in_flight += p->bytes;
}

static void quic_mark_pkt_lost(struct hy2_ctx *h, struct quic_sent_pkt *p, int64_t now_us) {
    if (!p->ack_eliciting) {
        /* Already probed and rescheduled by PTO */
        p->in_use = 0;
        return;
    }
    if (p->in_flight) {
        if (h->bytes_in_flight >= p->bytes) h->bytes_in_flight -= p->bytes;
        else h->bytes_in_flight = 0;
        p->in_flight = 0;
        /* NewReno congestion event (RFC 9002 §7.3.2): at most once per recovery epoch */
        if (p->sent_us > h->recovery_start_us) {
            h->recovery_start_us = now_us;
            h->cwnd /= 2;
            if (h->cwnd < 4800) h->cwnd = 4800;
            h->ssthresh = h->cwnd;
        }
    }
    if (p->level == 0 && p->has_crypto) {
        h->ch_retx_due = 1;
    } else if (p->level == 1 && p->has_crypto) {
        h->fin_retx_due = 1;
    } else if (p->level == 2) {
        if (p->has_s2 && !h->auth_ok)
            h->s2_retx_due = 1;
        if (p->has_stream && p->sid == 0 && !h->auth_ok)
            h->s0_retx_due = 1;
        if (p->has_stream && p->sid == 4)
            quic_queue_s4_retx(h, p->soff, p->slen, p->fin);
        (void)quic_resched_fc_on_loss(h, p);
    }
    p->in_use = 0;
}

static void quic_detect_lost(struct hy2_ctx *h, int level, int64_t now_us) {
    if (level < 0 || level > 2 || !h->have_acked_pn[level]) return;
    uint64_t la = h->largest_acked_pn[level];
    int64_t ref_rtt = h->latest_rtt_us > h->smoothed_rtt_us ? h->latest_rtt_us : h->smoothed_rtt_us;
    int64_t loss_delay = (ref_rtt * 9) / 8;
    if (loss_delay < 2000) loss_delay = 2000; /* 2ms floor */

    for (size_t i = 0; i < QUIC_SENT_MAX; i++) {
        struct quic_sent_pkt *p = &h->sent_pkts[i];
        if (!p->in_use || p->level != (uint8_t)level || p->pn >= la)
            continue;
        /* RFC 9002 §6.1.1 Packet Threshold (kPacketThreshold = 3) or §6.1.2 Time Threshold */
        if (la >= p->pn + 3 || (now_us - p->sent_us >= loss_delay)) {
            quic_mark_pkt_lost(h, p, now_us);
        }
    }
    if (level == 2)
        h->s4_una_off = quic_calc_s4_una(h);
}

static void quic_on_ack_ranges(struct hy2_ctx *h, int level,
                               const struct quic_pn_range *acked, size_t n_acked,
                               uint64_t ack_delay_raw, int64_t now_us) {
    if (!n_acked || level < 0 || level > 2) return;
    uint64_t largest = acked[0].high;
    if (!h->have_acked_pn[level] || largest > h->largest_acked_pn[level]) {
        h->largest_acked_pn[level] = largest;
        h->have_acked_pn[level] = 1;
    }

    for (size_t i = 0; i < QUIC_SENT_MAX; i++) {
        struct quic_sent_pkt *p = &h->sent_pkts[i];
        if (!p->in_use || p->level != (uint8_t)level) continue;
        int is_acked = 0;
        for (size_t k = 0; k < n_acked; k++) {
            if (p->pn >= acked[k].low && p->pn <= acked[k].high) {
                is_acked = 1;
                break;
            }
        }
        if (!is_acked) continue;

        /* Update RTT if largest acked was newly acknowledged (RFC 9002 §5.3) */
        if (p->pn == largest && p->ack_eliciting) {
            int64_t rtt = now_us - p->sent_us;
            if (rtt < 500) rtt = 500;
            int first_sample = (h->min_rtt_us == 0);
            h->latest_rtt_us = rtt;
            if (h->min_rtt_us == 0 || rtt < h->min_rtt_us)
                h->min_rtt_us = rtt;
            int64_t adj_rtt = rtt;
            if (level == 2) {
                uint8_t exp = h->peer_ack_delay_exp <= 20 ? h->peer_ack_delay_exp : 20;
                uint64_t max_raw = (uint64_t)INT64_MAX >> exp;
                int64_t ack_del = ack_delay_raw > max_raw ? INT64_MAX : (int64_t)(ack_delay_raw << exp);
                if (ack_del > h->peer_max_ack_delay_us)
                    ack_del = h->peer_max_ack_delay_us;
                if (rtt >= h->min_rtt_us + ack_del)
                    adj_rtt = rtt - ack_del;
            }
            if (first_sample) {
                h->smoothed_rtt_us = adj_rtt;
                h->rttvar_us = adj_rtt / 2;
            } else {
                int64_t diff = h->smoothed_rtt_us > adj_rtt
                                   ? (h->smoothed_rtt_us - adj_rtt)
                                   : (adj_rtt - h->smoothed_rtt_us);
                h->rttvar_us = (3 * h->rttvar_us + diff) / 4;
                h->smoothed_rtt_us = (7 * h->smoothed_rtt_us + adj_rtt) / 8;
            }
        }

        h->pto_count = 0;
        if (p->in_flight) {
            if (h->bytes_in_flight >= p->bytes) h->bytes_in_flight -= p->bytes;
            else h->bytes_in_flight = 0;
            p->in_flight = 0;
            if (p->sent_us > h->recovery_start_us) {
                if (h->cwnd < h->ssthresh) {
                    h->cwnd += p->bytes;
                } else {
                    uint64_t inc = (1200ULL * p->bytes) / (h->cwnd ? h->cwnd : 1200ULL);
                    h->cwnd += inc ? inc : 1;
                }
                if (h->cwnd > HY2_TX_CAP) h->cwnd = HY2_TX_CAP;
            }
        }

        if (level == 0 && p->has_crypto) h->ch_retx_due = 0;
        if (level == 1 && p->has_crypto) h->fin_retx_due = 0;
        if (level == 2) {
            if (p->has_s2) h->s2_retx_due = 0;
            if (p->has_stream && p->sid == 0) h->s0_retx_due = 0;
            if (p->has_win_update) {
                if (p->msd_val > h->acked_local_s4_max_data)
                    h->acked_local_s4_max_data = p->msd_val;
                if (p->md_val > h->acked_local_max_data)
                    h->acked_local_max_data = p->md_val;
                if (h->acked_local_s4_max_data >= h->local_s4_max_data &&
                    h->acked_local_max_data >= h->local_max_data) {
                    h->rx_win_update_due = 0;
                }
            }
            if (p->has_s4_blocked && p->s4_blocked_val == h->peer_s4_max_data) {
                h->acked_s4_blocked_at = p->s4_blocked_val;
                h->tx_s4_blocked_due = 0;
            }
            if (p->has_conn_blocked && p->conn_blocked_val == h->peer_max_data) {
                h->acked_conn_blocked_at = p->conn_blocked_val;
                h->tx_conn_blocked_due = 0;
            }
            if (p->has_stream && p->sid == 4) {
                uint64_t ack_soff = p->soff;
                uint32_t ack_slen = p->slen;
                for (size_t r = 0; r < QUIC_RETX_MAX; r++) {
                    if (h->s4_retx[r].in_use &&
                        h->s4_retx[r].soff == ack_soff &&
                        h->s4_retx[r].slen == ack_slen) {
                        h->s4_retx[r].in_use = 0;
                    }
                }
                for (size_t m = 0; m < QUIC_SENT_MAX; m++) {
                    if (m != i && h->sent_pkts[m].in_use && h->sent_pkts[m].level == 2 &&
                        h->sent_pkts[m].has_stream && h->sent_pkts[m].sid == 4 &&
                        h->sent_pkts[m].soff == ack_soff && h->sent_pkts[m].slen == ack_slen) {
                        if (h->sent_pkts[m].has_win_update ||
                            h->sent_pkts[m].has_s4_blocked ||
                            h->sent_pkts[m].has_conn_blocked) {
                            h->sent_pkts[m].has_stream = 0;
                        } else {
                            if (h->sent_pkts[m].in_flight) {
                                if (h->bytes_in_flight >= h->sent_pkts[m].bytes)
                                    h->bytes_in_flight -= h->sent_pkts[m].bytes;
                                else
                                    h->bytes_in_flight = 0;
                            }
                            h->sent_pkts[m].in_use = 0;
                        }
                    }
                }
            }
        }
        p->in_use = 0;
    }

    quic_detect_lost(h, level, now_us);
    if (level == 2)
        h->s4_una_off = quic_calc_s4_una(h);
}

static void quic_ack_all_before_app(struct hy2_ctx *h) {
    for (size_t i = 0; i < QUIC_SENT_MAX; i++) {
        struct quic_sent_pkt *p = &h->sent_pkts[i];
        if (!p->in_use) continue;
        if (p->level < 2 || p->has_s2 || (p->has_stream && p->sid == 0)) {
            if (p->in_flight) {
                if (h->bytes_in_flight >= p->bytes) h->bytes_in_flight -= p->bytes;
                else h->bytes_in_flight = 0;
            }
            p->in_use = 0;
        }
    }
    h->ch_retx_due  = 0;
    h->fin_retx_due = 0;
    h->s2_retx_due  = 0;
    h->s0_retx_due  = 0;
    h->pto_count    = 0;
}

static void quic_check_pto(struct hy2_ctx *h, int64_t now_us) {
    int64_t last_sent_us = 0;
    int has_inflight = 0;
    for (size_t i = 0; i < QUIC_SENT_MAX; i++) {
        if (h->sent_pkts[i].in_use && h->sent_pkts[i].ack_eliciting) {
            has_inflight = 1;
            if (h->sent_pkts[i].sent_us > last_sent_us)
                last_sent_us = h->sent_pkts[i].sent_us;
        }
    }
    if (!has_inflight) return;

    int64_t srtt = h->smoothed_rtt_us ? h->smoothed_rtt_us : 30000;
    int64_t rvar = h->rttvar_us ? h->rttvar_us : 15000;
    int64_t k4r  = 4 * rvar > 1000 ? 4 * rvar : 1000;
    int64_t pto  = srtt + k4r + (h->auth_ok ? h->peer_max_ack_delay_us : 0);
    if (pto < 15000) pto = 15000; /* 15ms minimum PTO */
    uint32_t shift = h->pto_count < 6 ? h->pto_count : 6;
    pto <<= shift;

    if (now_us - last_sent_us < pto) return;

    h->pto_count++;
    /* Probe up to 2 oldest unacknowledged ack-eliciting packets by scheduling their frames for
     * retransmission in fresh QUIC packets with new packet numbers (RFC 9002 §6.2.4) */
    int probed = 0;
    for (int pass = 0; pass < 2; pass++) {
        size_t best = QUIC_SENT_MAX;
        int64_t oldest_us = INT64_MAX;
        for (size_t i = 0; i < QUIC_SENT_MAX; i++) {
            struct quic_sent_pkt *p = &h->sent_pkts[i];
            if (p->in_use && p->ack_eliciting && p->sent_us < oldest_us) {
                oldest_us = p->sent_us;
                best = i;
            }
        }
        if (best == QUIC_SENT_MAX) break;
        struct quic_sent_pkt *p = &h->sent_pkts[best];
        if (p->in_flight) {
            if (h->bytes_in_flight >= p->bytes) h->bytes_in_flight -= p->bytes;
            else h->bytes_in_flight = 0;
            p->in_flight = 0;
        }
        p->ack_eliciting = 0;
        if (p->level == 0 && p->has_crypto) {
            h->ch_retx_due = 1;
            probed++;
        } else if (p->level == 1 && p->has_crypto) {
            h->fin_retx_due = 1;
            probed++;
        } else if (p->level == 2) {
            if (p->has_s2 && !h->auth_ok) { h->s2_retx_due = 1; probed++; }
            if (p->has_stream && p->sid == 0 && !h->auth_ok) { h->s0_retx_due = 1; probed++; }
            if (p->has_stream && p->sid == 4) {
                quic_queue_s4_retx(h, p->soff, p->slen, p->fin);
                probed++;
            }
            if (quic_resched_fc_on_loss(h, p))
                probed++;
        }
    }
    if (!probed && h->tx_app.ready)
        h->ping_due = 1;
}

/* Seal & send a Long Header packet (type: 0=Initial, 2=Handshake) */
static int quic_send_long_ex(struct hy2_ctx *h, int pkt_type, struct quic_level *lv,
                             const unsigned char *frames, size_t frames_len, int pad_initial,
                             uint8_t ack_eliciting, uint8_t has_crypto, uint32_t coff, uint32_t clen) {
    unsigned char pkt[HY2_MAX_PKT];
    size_t o = 0;
    uint64_t pn = lv->pn++;
    size_t pn_len = (pn < 16384) ? 2 : 4;
    uint8_t pn_bits = (pn_len == 2) ? 0x01u : 0x03u;

    /* Long header: 1 (Form=1) | 1 (Fixed=1) | 2-bit type | 00 | pn_bits */
    pkt[o++] = (unsigned char)(0xC0u | ((pkt_type & 3) << 4) | pn_bits);
    /* Version 1 (0x00000001) */
    pkt[o++] = 0x00; pkt[o++] = 0x00; pkt[o++] = 0x00; pkt[o++] = 0x01;
    /* DCID */
    pkt[o++] = (unsigned char)h->dcid_len;
    memcpy(pkt + o, h->dcid, h->dcid_len);
    o += h->dcid_len;
    /* SCID (8 bytes) */
    pkt[o++] = 8;
    memcpy(pkt + o, h->scid, 8);
    o += 8;
    if (pkt_type == 0) {
        /* Token Length = 0 */
        pkt[o++] = 0x00;
    }

    size_t pay_len = frames_len < (4 - pn_len) ? (4 - pn_len) : frames_len;
    if (pad_initial && o + 2 + pn_len + pay_len + 16 < HY2_INITIAL_MIN)
        pay_len = HY2_INITIAL_MIN - (o + 2 + pn_len + 16);
    if (o + 2 + pn_len + pay_len + 16 > sizeof(pkt)) return TR_EIO;

    /* 2-byte varint length = pn_len + pay_len + 16 (AEAD tag) */
    size_t rem_len = pn_len + pay_len + 16;
    pkt[o++] = (unsigned char)(0x40u | (rem_len >> 8));
    pkt[o++] = (unsigned char)rem_len;

    size_t pn_off = o;
    for (size_t i = 0; i < pn_len; i++)
        pkt[o++] = (unsigned char)(pn >> (8 * (pn_len - 1 - i)));

    size_t hdr_len = o;
    memcpy(pkt + o, frames, frames_len);
    if (pay_len > frames_len)
        memset(pkt + o + frames_len, 0, pay_len - frames_len); /* PADDING (0x00) frames */

    unsigned char nonce[12];
    quic_make_nonce(lv->iv, pn, nonce);
    if (sc_aead_seal(&lv->aead, nonce, pkt, hdr_len, pkt + hdr_len, pay_len, pkt + hdr_len + pay_len) != 0)
        return TR_EIO;

    unsigned char mask[5];
    if (quic_hp_mask(lv, pkt + pn_off + 4, mask) != 0) return TR_EIO;
    pkt[0] ^= (unsigned char)(mask[0] & 0x0Fu);
    for (size_t i = 0; i < pn_len; i++)
        pkt[pn_off + i] ^= mask[1 + i];

    size_t wire_len = hdr_len + pay_len + 16;
    int rc = hy2_udp_send(h, pkt, wire_len);
    if (rc == 0 && ack_eliciting) {
        quic_record_sent(h, (pkt_type == 0) ? 0 : 1, pn, wire_len,
                         ack_eliciting, has_crypto, coff, clen, 0, 0, 0, 0, 0, 0, NULL);
    }
    return rc;
}

static int quic_send_long(struct hy2_ctx *h, int pkt_type, struct quic_level *lv,
                          const unsigned char *frames, size_t frames_len, int pad_initial) {
    return quic_send_long_ex(h, pkt_type, lv, frames, frames_len, pad_initial, 0, 0, 0, 0);
}

/* Seal & send a 1-RTT Short Header packet */
static int quic_send_1rtt_ex(struct hy2_ctx *h, const unsigned char *frames, size_t frames_len,
                             uint8_t ack_eliciting, uint8_t has_s2,
                             uint8_t has_stream, uint64_t sid, uint64_t soff, uint32_t slen, uint8_t fin,
                             const struct quic_fc_meta *fc) {
    unsigned char pkt[HY2_MAX_PKT];
    size_t o = 0;
    uint64_t pn = h->tx_app.pn++;
    size_t pn_len = (pn < 16384) ? 2 : 4;
    uint8_t pn_bits = (pn_len == 2) ? 0x01u : 0x03u;

    /* Short header: 0 (Form=0) | 1 (Fixed=1) | 00 | K (key_phase) | pn_bits */
    pkt[o++] = (unsigned char)(0x40u | (h->key_phase ? 0x04u : 0x00u) | pn_bits);
    memcpy(pkt + o, h->dcid, h->dcid_len);
    o += h->dcid_len;

    size_t pn_off = o;
    for (size_t i = 0; i < pn_len; i++)
        pkt[o++] = (unsigned char)(pn >> (8 * (pn_len - 1 - i)));
    size_t hdr_len = o;

    /* Ensure at least 4 bytes before sample offset (pn_off + 4) */
    size_t min_pay = (pn_len < 4) ? (4 - pn_len) : 1;
    size_t pay_len = frames_len < min_pay ? min_pay : frames_len;
    if (hdr_len + pay_len + 16 > sizeof(pkt)) return TR_EIO;
    memcpy(pkt + hdr_len, frames, frames_len);
    if (pay_len > frames_len)
        memset(pkt + hdr_len + frames_len, 0, pay_len - frames_len);

    unsigned char nonce[12];
    quic_make_nonce(h->tx_app.iv, pn, nonce);
    if (sc_aead_seal(&h->tx_app.aead, nonce, pkt, hdr_len, pkt + hdr_len, pay_len, pkt + hdr_len + pay_len) != 0)
        return TR_EIO;

    unsigned char mask[5];
    if (quic_hp_mask(&h->tx_app, pkt + pn_off + 4, mask) != 0) return TR_EIO;
    pkt[0] ^= (unsigned char)(mask[0] & 0x1Fu);
    for (size_t i = 0; i < pn_len; i++)
        pkt[pn_off + i] ^= mask[1 + i];

    size_t wire_len = hdr_len + pay_len + 16;
    int rc = hy2_udp_send(h, pkt, wire_len);
    if (rc == 0 && ack_eliciting) {
        quic_record_sent(h, 2, pn, wire_len, ack_eliciting, 0, 0, 0,
                         has_s2, has_stream, sid, soff, slen, fin, fc);
    } else if (rc != 0 && fc) {
        if (fc->has_win_update) h->rx_win_update_due = 1;
        if (fc->has_s4_blocked) h->tx_s4_blocked_due = 1;
        if (fc->has_conn_blocked) h->tx_conn_blocked_due = 1;
    }
    return rc;
}

static int rx_append(struct hy2_ctx *h, const unsigned char *d, size_t n) {
    if (!n) return 0;
    if (h->rx_off > 0 && h->rx_len == 0) h->rx_off = 0;
    if (h->rx_off + h->rx_len + n > h->rx_cap) {
        if (h->rx_off > 0) {
            memmove(h->rx_buf, h->rx_buf + h->rx_off, h->rx_len);
            h->rx_off = 0;
        }
        while (h->rx_len + n > h->rx_cap) {
            size_t ncap = h->rx_cap ? h->rx_cap * 2 : HY2_RX_CAP;
            unsigned char *nb = realloc(h->rx_buf, ncap);
            if (!nb) return -1;
            h->rx_buf = nb;
            h->rx_cap = ncap;
        }
    }
    memcpy(h->rx_buf + h->rx_off + h->rx_len, d, n);
    h->rx_len += n;
    return 0;
}

static void hy2_s4_deliver_inorder(struct hy2_ctx *h, const unsigned char *d, size_t n, int fin) {
    h->s4_rx_off += n;
    if (fin) h->peer_closed = 1;
    if (!n) return;

    if (!h->resp_parsed) {
        size_t copy = n < sizeof(h->s4_hdr) - h->s4_hdr_len ? n : sizeof(h->s4_hdr) - h->s4_hdr_len;
        memcpy(h->s4_hdr + h->s4_hdr_len, d, copy);
        h->s4_hdr_len += copy;
        /* Parse [uint8 status][varint msg_len][msg][varint pad_len][padding] */
        if (h->s4_hdr_len < 3) return;
        uint8_t status = h->s4_hdr[0];
        uint64_t mlen = 0, plen = 0;
        size_t u1 = 0, u2 = 0;
        if (quic_get_varint(h->s4_hdr + 1, h->s4_hdr_len - 1, &mlen, &u1) != 0) return;
        if (mlen > 2048 || 1 + u1 + (size_t)mlen >= sizeof(h->s4_hdr)) {
            h->proto_err = TR_EIO;
            h->peer_closed = 1;
            return;
        }
        if (1 + u1 + (size_t)mlen >= h->s4_hdr_len) return;
        size_t p_pos = 1 + u1 + (size_t)mlen;
        if (quic_get_varint(h->s4_hdr + p_pos, h->s4_hdr_len - p_pos, &plen, &u2) != 0) return;
        if (plen > 2048 || p_pos + u2 + (size_t)plen > sizeof(h->s4_hdr)) {
            h->proto_err = TR_EIO;
            h->peer_closed = 1;
            return;
        }
        size_t total_hdr = p_pos + u2 + (size_t)plen;
        if (h->s4_hdr_len < total_hdr) return;
        if (status != 0) {
            h->peer_closed = 1;
            return;
        }
        h->resp_parsed = 1;
        h->s4_rx_consumed += total_hdr;
        size_t rem_in_hdr = h->s4_hdr_len - total_hdr;
        if (rem_in_hdr > 0)
            rx_append(h, h->s4_hdr + total_hdr, rem_in_hdr);
        if (n > copy)
            rx_append(h, d + copy, n - copy);
        return;
    }
    rx_append(h, d, n);
}

static int qpack_get_int(const unsigned char *p, size_t n, unsigned bits, uint64_t *val, size_t *used) {
    if (!n) return -1;
    uint64_t max_pre = (1ULL << bits) - 1;
    uint64_t v = p[0] & max_pre;
    size_t pos = 1;
    if (v < max_pre) {
        *val = v;
        *used = pos;
        return 0;
    }
    unsigned shift = 0;
    for (;;) {
        if (pos >= n || shift > 56) return -1;
        unsigned char b = p[pos++];
        v += (uint64_t)(b & 0x7Fu) << shift;
        if (!(b & 0x80u)) break;
        shift += 7;
    }
    *val = v;
    *used = pos;
    return 0;
}

static int qpack_val_is_status(const unsigned char *val, size_t vlen, int huff, int *out_status) {
    if (!huff) {
        if (vlen != 3 || val[0] < '0' || val[0] > '9' ||
            val[1] < '0' || val[1] > '9' || val[2] < '0' || val[2] > '9')
            return -1;
        *out_status = (val[0] - '0') * 100 + (val[1] - '0') * 10 + (val[2] - '0');
        return 0;
    }
    if (vlen < 2 || vlen > 3) return -1;
    int sv = status_huff(val, vlen);
    if (sv < 100 || sv > 999) return -1;
    *out_status = sv;
    return 0;
}

static int qpack_check_status_233(const unsigned char *buf, size_t len) {
    size_t pos = 0, u = 0;
    uint64_t ric = 0, dbase = 0;
    /* QPACK Header Block Prefix (RFC 9204 §4.5.1): Required Insert Count (8+) + Delta Base (7+) */
    if (qpack_get_int(buf + pos, len - pos, 8, &ric, &u) != 0) return -1;
    pos += u;
    if (qpack_get_int(buf + pos, len - pos, 7, &dbase, &u) != 0) return -1;
    pos += u;
    if (ric != 0 || dbase != 0) return -1; /* Dynamic table capacity is 0 */

    int status_code = -1;
    int status_count = 0;
    while (pos < len) {
        unsigned char b = buf[pos];
        if (b & 0x80u) {
            /* Indexed Field Line: 1 T Index(6+) */
            if (!(b & 0x40u)) return -1;
            uint64_t idx = 0;
            if (qpack_get_int(buf + pos, len - pos, 6, &idx, &u) != 0) return -1;
            pos += u;
            if (idx > 98) return -1;
            if ((idx >= 24 && idx <= 28) || (idx >= 63 && idx <= 71)) return -1;
        } else if ((b & 0xC0u) == 0x40u) {
            /* Literal Field Line With Name Reference: 01 N T NameIdx(4+) H ValLen(7+) Val */
            if (!(b & 0x10u)) return -1;
            uint64_t nidx = 0, vlen = 0;
            if (qpack_get_int(buf + pos, len - pos, 4, &nidx, &u) != 0) return -1;
            pos += u;
            if (nidx > 98 || pos >= len) return -1;
            int vhuff = (buf[pos] & 0x80u) != 0;
            if (qpack_get_int(buf + pos, len - pos, 7, &vlen, &u) != 0) return -1;
            pos += u;
            if (vlen > len - pos) return -1;
            int is_status = (nidx >= 24 && nidx <= 28) || (nidx >= 63 && nidx <= 71);
            if (is_status) {
                int sc = -1;
                if (qpack_val_is_status(buf + pos, (size_t)vlen, vhuff, &sc) != 0) return -1;
                status_code = sc;
                status_count++;
                if (status_count > 1 || status_code != 233) return -1;
            }
            pos += (size_t)vlen;
        } else if ((b & 0xE0u) == 0x20u) {
            /* Literal Field Line With Literal Name: 001 N H NameLen(3+) Name H ValLen(7+) Val */
            int nhuff = (b & 0x08u) != 0;
            uint64_t nlen = 0, vlen = 0;
            if (qpack_get_int(buf + pos, len - pos, 3, &nlen, &u) != 0) return -1;
            pos += u;
            if (nlen > len - pos) return -1;
            const unsigned char *name = buf + pos;
            pos += (size_t)nlen;
            if (pos >= len) return -1;
            int vhuff = (buf[pos] & 0x80u) != 0;
            if (qpack_get_int(buf + pos, len - pos, 7, &vlen, &u) != 0) return -1;
            pos += u;
            if (vlen > len - pos) return -1;
            const unsigned char *val = buf + pos;
            pos += (size_t)vlen;

            static const unsigned char huff_status[5] = { 0xB9, 0x12, 0x39, 0x6B, 0x43 };
            int is_status = (!nhuff && nlen == 7 && memcmp(name, ":status", 7) == 0) ||
                            (nhuff && nlen == 5 && memcmp(name, huff_status, 5) == 0);
            if (!is_status && ((!nhuff && nlen > 0 && name[0] == ':') ||
                               (nhuff && nlen > 0 && (name[0] & 0xFEu) == 0xB8u)))
                return -1;
            if (is_status) {
                int sc = -1;
                if (qpack_val_is_status(val, (size_t)vlen, vhuff, &sc) != 0) return -1;
                status_code = sc;
                status_count++;
                if (status_count > 1 || status_code != 233) return -1;
            }
        } else {
            return -1;
        }
    }
    return (status_count == 1 && status_code == 233) ? 1 : -1;
}

/* Process Stream 0 (HTTP/3 Auth response) and Stream 4 (Hysteria2 TCP stream) */
static void hy2_on_stream(struct hy2_ctx *h, uint64_t sid, uint64_t off,
                          const unsigned char *d, size_t n, int fin) {
    if (sid == 0) {
        if (h->auth_ok || h->auth_failed) return;
        if (off > sizeof(h->s0_buf) || n > sizeof(h->s0_buf) - (size_t)off) {
            h->auth_failed = 1;
            h->peer_closed = 1;
            return;
        }
        if (n > 0) {
            memcpy(h->s0_buf + (size_t)off, d, n);
            memset(h->s0_seen + (size_t)off, 1, n);
            while (h->s0_contig < sizeof(h->s0_buf) && h->s0_seen[h->s0_contig])
                h->s0_contig++;
        }
        while (h->s0_parse_off < h->s0_contig) {
            uint64_t ftype = 0, flen = 0;
            size_t u1 = 0, u2 = 0;
            size_t rem = h->s0_contig - h->s0_parse_off;
            const unsigned char *fp = h->s0_buf + h->s0_parse_off;
            if (quic_get_varint(fp, rem, &ftype, &u1) != 0) break;
            if (quic_get_varint(fp + u1, rem - u1, &flen, &u2) != 0) break;
            if (flen > sizeof(h->s0_buf) - h->s0_parse_off - u1 - u2) {
                h->auth_failed = 1;
                h->peer_closed = 1;
                return;
            }
            if (rem < u1 + u2 + (size_t)flen) break;
            if (ftype == 0x00) {
                /* DATA before HEADERS on HTTP/3 response stream is invalid */
                h->auth_failed = 1;
                h->peer_closed = 1;
                return;
            }
            if (ftype == 0x01) {
                if (qpack_check_status_233(fp + u1 + u2, (size_t)flen) == 1) {
                    h->auth_ok = 1;
                } else {
                    h->auth_failed = 1;
                    h->peer_closed = 1;
                }
                h->s0_parse_off += u1 + u2 + (size_t)flen;
                return;
            }
            h->s0_parse_off += u1 + u2 + (size_t)flen;
        }
        if (fin && !h->auth_ok && off + n <= h->s0_contig) {
            h->auth_failed = 1;
            h->peer_closed = 1;
        }
        return;
    }
    if (sid != 4) return;
    if (off > h->local_s4_max_data || n > h->local_s4_max_data - off) {
        h->proto_err = TR_EIO;
        h->peer_closed = 1;
        return;
    }
    if (off + n > h->s4_rx_highest)
        h->s4_rx_highest = off + n;
    if (off < h->s4_rx_off) {
        if (off + n <= h->s4_rx_off) {
            if (fin) h->peer_closed = 1;
            return;
        }
        size_t skip = (size_t)(h->s4_rx_off - off);
        d += skip;
        n -= skip;
        off = h->s4_rx_off;
    }
    if (off > h->s4_rx_off) {
        /* Stash out-of-order segment if not already queued */
        for (int i = 0; i < 64; i++) {
            if (h->ooo[i].data && h->ooo[i].off == off) return;
        }
        for (int i = 0; i < 64; i++) {
            if (!h->ooo[i].data) {
                h->ooo[i].data = malloc(n ? n : 1);
                if (h->ooo[i].data) {
                    if (n) memcpy(h->ooo[i].data, d, n);
                    h->ooo[i].off = off;
                    h->ooo[i].len = n;
                    h->ooo[i].fin = fin;
                }
                break;
            }
        }
        return;
    }
    hy2_s4_deliver_inorder(h, d, n, fin);
    /* Drain any contiguous queued out-of-order segments */
    for (;;) {
        int progressed = 0;
        for (int i = 0; i < 64; i++) {
            if (h->ooo[i].data && h->ooo[i].off <= h->s4_rx_off) {
                unsigned char *seg = h->ooo[i].data;
                uint64_t soff = h->ooo[i].off;
                size_t slen = h->ooo[i].len;
                int sfin = h->ooo[i].fin;
                h->ooo[i].data = NULL;
                if (soff + slen > h->s4_rx_off) {
                    size_t sk = (size_t)(h->s4_rx_off - soff);
                    hy2_s4_deliver_inorder(h, seg + sk, slen - sk, sfin);
                    progressed = 1;
                } else if (sfin) {
                    h->peer_closed = 1;
                }
                free(seg);
            }
        }
        if (!progressed) break;
    }
}

static void hy2_udp_reasm_free_slot(struct hy2_udp_reasm *s) {
    for (int i = 0; i < 32; i++) {
        free(s->frags[i]);
        s->frags[i] = NULL;
        s->frag_lens[i] = 0;
    }
    s->in_use = 0;
    s->got_mask = 0;
}

/* Process Hysteria2 UDP datagram frame (single or fragmented):
 * [uint32_be session_id][uint16_be pkt_id][uint8 frag_id][uint8 frag_count][varint addr_len][addr][payload] */
static void hy2_on_datagram(struct hy2_ctx *h, const unsigned char *d, size_t n) {
    if (!h->is_udp || n < 9) return;
    /* HTTP/3 Quarter Stream ID varint at the start of H3 DATAGRAM (0x00 for stream 0) */
    uint64_t qsid = 0;
    size_t qused = 0;
    if (quic_get_varint(d, n, &qsid, &qused) == 0 && qsid == 0 && n > qused + 8) {
        uint32_t sid_raw = ((uint32_t)d[0] << 24) | ((uint32_t)d[1] << 16) | ((uint32_t)d[2] << 8) | d[3];
        if (sid_raw != h->udp_sid) {
            d += qused;
            n -= qused;
        }
    }
    if (n < 9) return;
    uint32_t pkt_sid = ((uint32_t)d[0] << 24) | ((uint32_t)d[1] << 16) | ((uint32_t)d[2] << 8) | d[3];
    if (pkt_sid != h->udp_sid) return;
    uint16_t pkt_id = (uint16_t)(((uint16_t)d[4] << 8) | d[5]);
    uint8_t frag_id = d[6];
    uint8_t frag_cnt = d[7];
    if (frag_cnt == 0 || frag_cnt > 32 || frag_id >= frag_cnt) return;

    uint64_t alen = 0;
    size_t u = 0;
    if (quic_get_varint(d + 8, n - 8, &alen, &u) != 0) return;
    if (alen > n - 8 - u) return;
    const unsigned char *pay = d + 8 + u + (size_t)alen;
    size_t plen = n - (8 + u + (size_t)alen);
    if (!plen || plen > 65535) return;

    if (frag_cnt == 1) {
        unsigned char lhdr[2] = { (unsigned char)(plen >> 8), (unsigned char)plen };
        rx_append(h, lhdr, 2);
        rx_append(h, pay, plen);
        return;
    }

    int slot = -1;
    for (int i = 0; i < 4; i++) {
        if (h->udp_reasm[i].in_use && h->udp_reasm[i].pkt_id == pkt_id &&
            h->udp_reasm[i].frag_cnt == frag_cnt) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        for (int i = 0; i < 4; i++) {
            if (!h->udp_reasm[i].in_use) { slot = i; break; }
        }
        if (slot < 0) {
            slot = 0;
            hy2_udp_reasm_free_slot(&h->udp_reasm[0]);
        }
        h->udp_reasm[slot].in_use = 1;
        h->udp_reasm[slot].pkt_id = pkt_id;
        h->udp_reasm[slot].frag_cnt = frag_cnt;
        h->udp_reasm[slot].got_mask = 0;
    }

    struct hy2_udp_reasm *rs = &h->udp_reasm[slot];
    if (!rs->frags[frag_id]) {
        rs->frags[frag_id] = malloc(plen);
        if (!rs->frags[frag_id]) return;
        memcpy(rs->frags[frag_id], pay, plen);
        rs->frag_lens[frag_id] = (uint16_t)plen;
        rs->got_mask |= (1u << frag_id);
    }

    uint32_t want_mask = (frag_cnt == 32) ? 0xFFFFFFFFu : ((1u << frag_cnt) - 1u);
    if (rs->got_mask == want_mask) {
        size_t total_len = 0;
        for (uint8_t i = 0; i < frag_cnt; i++)
            total_len += rs->frag_lens[i];
        if (total_len > 0 && total_len <= 65535) {
            unsigned char lhdr[2] = { (unsigned char)(total_len >> 8), (unsigned char)total_len };
            rx_append(h, lhdr, 2);
            for (uint8_t i = 0; i < frag_cnt; i++)
                rx_append(h, rs->frags[i], rs->frag_lens[i]);
        }
        hy2_udp_reasm_free_slot(rs);
    }
}

/* Parse frames inside a decrypted QUIC payload */
static int quic_parse_frames(struct hy2_ctx *h, int level, const unsigned char *p, size_t n, int *ack_eliciting) {
    size_t pos = 0;
    int64_t now_us = hy2_now_us();
    while (pos < n) {
        uint64_t ftype = 0;
        size_t u = 0;
        if (quic_get_varint(p + pos, n - pos, &ftype, &u) != 0) return -1;
        pos += u;

        if (ftype == 0x00) { /* PADDING */
            continue;
        } else if (ftype == 0x01) { /* PING */
            *ack_eliciting = 1;
        } else if (ftype == 0x02 || ftype == 0x03) { /* ACK */
            uint64_t largest = 0, delay = 0, rcnt = 0, first_rng = 0;
            size_t u1, u2, u3, u4;
            if (quic_get_varint(p + pos, n - pos, &largest, &u1) != 0) return -1;
            pos += u1;
            if (quic_get_varint(p + pos, n - pos, &delay, &u2) != 0) return -1;
            pos += u2;
            if (quic_get_varint(p + pos, n - pos, &rcnt, &u3) != 0) return -1;
            pos += u3;
            if (quic_get_varint(p + pos, n - pos, &first_rng, &u4) != 0) return -1;
            pos += u4;
            if (first_rng > largest) return -1;

            struct quic_pn_range acked[64];
            size_t n_acked = 0;
            acked[n_acked].high = largest;
            acked[n_acked].low  = largest - first_rng;
            n_acked++;
            uint64_t cur_low = largest - first_rng;

            for (uint64_t i = 0; i < rcnt; i++) {
                uint64_t gap = 0, alen = 0;
                if (quic_get_varint(p + pos, n - pos, &gap, &u1) != 0) return -1;
                pos += u1;
                if (quic_get_varint(p + pos, n - pos, &alen, &u2) != 0) return -1;
                pos += u2;
                if (gap > UINT64_MAX - 2 || cur_low < gap + 2) return -1;
                uint64_t r_high = cur_low - gap - 2;
                if (alen > r_high) return -1;
                uint64_t r_low = r_high - alen;
                cur_low = r_low;
                if (n_acked < 64) {
                    acked[n_acked].high = r_high;
                    acked[n_acked].low  = r_low;
                    n_acked++;
                }
            }
            if (ftype == 0x03) {
                uint64_t ect0, ect1, ce;
                if (quic_get_varint(p + pos, n - pos, &ect0, &u1) != 0) return -1;
                pos += u1;
                if (quic_get_varint(p + pos, n - pos, &ect1, &u1) != 0) return -1;
                pos += u1;
                if (quic_get_varint(p + pos, n - pos, &ce, &u1) != 0) return -1;
                pos += u1;
            }
            quic_on_ack_ranges(h, level, acked, n_acked, delay, now_us);
        } else if (ftype == 0x06) { /* CRYPTO */
            *ack_eliciting = 1;
            uint64_t coff = 0, clen = 0;
            size_t u1, u2;
            if (quic_get_varint(p + pos, n - pos, &coff, &u1) != 0) return -1;
            pos += u1;
            if (quic_get_varint(p + pos, n - pos, &clen, &u2) != 0) return -1;
            pos += u2;
            if (clen > n - pos) return -1;
            if (level < 0 || level > 1 || coff > HY2_CRYPTO_CAP || clen > HY2_CRYPTO_CAP - coff) {
                h->proto_err = TLS13_EBADREC;
                return -1;
            }
            if (h->crypto_buf[level] && h->crypto_seen[level] && clen > 0) {
                memcpy(h->crypto_buf[level] + (size_t)coff, p + pos, (size_t)clen);
                memset(h->crypto_seen[level] + (size_t)coff, 1, (size_t)clen);
                while (h->crypto_len[level] < HY2_CRYPTO_CAP &&
                       h->crypto_seen[level][h->crypto_len[level]]) {
                    h->crypto_len[level]++;
                }
            }
            pos += (size_t)clen;
        } else if (ftype == 0x07) { /* NEW_TOKEN */
            *ack_eliciting = 1;
            uint64_t tlen = 0;
            size_t u1;
            if (quic_get_varint(p + pos, n - pos, &tlen, &u1) != 0) return -1;
            pos += u1;
            if (tlen > n - pos) return -1;
            pos += (size_t)tlen;
        } else if (ftype >= 0x08 && ftype <= 0x0F) { /* STREAM */
            *ack_eliciting = 1;
            uint64_t sid = 0, soff = 0, slen = 0;
            size_t u1;
            if (quic_get_varint(p + pos, n - pos, &sid, &u1) != 0) return -1;
            pos += u1;
            if (ftype & 0x04) {
                if (quic_get_varint(p + pos, n - pos, &soff, &u1) != 0) return -1;
                pos += u1;
            }
            if (ftype & 0x02) {
                if (quic_get_varint(p + pos, n - pos, &slen, &u1) != 0) return -1;
                pos += u1;
                if (slen > n - pos) return -1;
            } else {
                slen = n - pos;
            }
            hy2_on_stream(h, sid, soff, p + pos, (size_t)slen, (ftype & 0x01) != 0);
            pos += (size_t)slen;
        } else if (ftype == 0x18) { /* NEW_CONNECTION_ID */
            *ack_eliciting = 1;
            uint64_t seq, rpt;
            size_t u1;
            if (quic_get_varint(p + pos, n - pos, &seq, &u1) != 0) return -1;
            pos += u1;
            if (quic_get_varint(p + pos, n - pos, &rpt, &u1) != 0) return -1;
            pos += u1;
            if (pos >= n) return -1;
            size_t cid_len = p[pos++];
            if (pos + cid_len + 16 > n) return -1;
            pos += cid_len + 16;
        } else if (ftype == 0x1C || ftype == 0x1D) { /* CONNECTION_CLOSE */
            h->peer_closed = 1;
            return 0;
        } else if (ftype == 0x1E) { /* HANDSHAKE_DONE */
            *ack_eliciting = 1;
        } else if (ftype == 0x30 || ftype == 0x31) { /* DATAGRAM */
            *ack_eliciting = 1;
            uint64_t dlen = n - pos;
            if (ftype == 0x31) {
                size_t u1;
                if (quic_get_varint(p + pos, n - pos, &dlen, &u1) != 0) return -1;
                pos += u1;
                if (dlen > n - pos) return -1;
            }
            hy2_on_datagram(h, p + pos, (size_t)dlen);
            pos += (size_t)dlen;
        } else if (ftype == 0x04) { /* RESET_STREAM */
            *ack_eliciting = 1;
            uint64_t sid, errc, fsz;
            size_t u1;
            if (quic_get_varint(p + pos, n - pos, &sid, &u1) != 0) return -1;
            pos += u1;
            if (quic_get_varint(p + pos, n - pos, &errc, &u1) != 0) return -1;
            pos += u1;
            if (quic_get_varint(p + pos, n - pos, &fsz, &u1) != 0) return -1;
            pos += u1;
            if (sid == 4) h->peer_closed = 1;
        } else if (ftype == 0x05) { /* STOP_SENDING */
            *ack_eliciting = 1;
            uint64_t sid, errc;
            size_t u1;
            if (quic_get_varint(p + pos, n - pos, &sid, &u1) != 0) return -1;
            pos += u1;
            if (quic_get_varint(p + pos, n - pos, &errc, &u1) != 0) return -1;
            pos += u1;
        } else if (ftype == 0x10) { /* MAX_DATA */
            *ack_eliciting = 1;
            uint64_t v;
            size_t u1;
            if (quic_get_varint(p + pos, n - pos, &v, &u1) != 0) return -1;
            pos += u1;
            if (v > h->peer_max_data)
                h->peer_max_data = v;
        } else if (ftype == 0x12 || ftype == 0x13) { /* MAX_STREAMS */
            *ack_eliciting = 1;
            uint64_t v;
            size_t u1;
            if (quic_get_varint(p + pos, n - pos, &v, &u1) != 0) return -1;
            pos += u1;
        } else if (ftype == 0x11) { /* MAX_STREAM_DATA */
            *ack_eliciting = 1;
            uint64_t sid, v;
            size_t u1;
            if (quic_get_varint(p + pos, n - pos, &sid, &u1) != 0) return -1;
            pos += u1;
            if (quic_get_varint(p + pos, n - pos, &v, &u1) != 0) return -1;
            pos += u1;
            if (sid == 4 && v > h->peer_s4_max_data)
                h->peer_s4_max_data = v;
        } else if (ftype == 0x15) { /* STREAM_DATA_BLOCKED */
            *ack_eliciting = 1;
            uint64_t sid, v;
            size_t u1;
            if (quic_get_varint(p + pos, n - pos, &sid, &u1) != 0) return -1;
            pos += u1;
            if (quic_get_varint(p + pos, n - pos, &v, &u1) != 0) return -1;
            pos += u1;
            if (sid == 4)
                quic_advance_local_rx_win(h, h->s4_rx_consumed);
        } else if (ftype == 0x14) { /* DATA_BLOCKED */
            *ack_eliciting = 1;
            uint64_t v;
            size_t u1;
            if (quic_get_varint(p + pos, n - pos, &v, &u1) != 0) return -1;
            pos += u1;
            quic_advance_local_rx_win(h, h->s4_rx_consumed);
        } else if (ftype == 0x16 || ftype == 0x17 || ftype == 0x19) {
            /* STREAMS_BLOCKED / RETIRE_CONNECTION_ID */
            *ack_eliciting = 1;
            uint64_t v;
            size_t u1;
            if (quic_get_varint(p + pos, n - pos, &v, &u1) != 0) return -1;
            pos += u1;
        } else if (ftype == 0x1A || ftype == 0x1B) { /* PATH_CHALLENGE / PATH_RESPONSE */
            *ack_eliciting = 1;
            if (n - pos < 8) return -1;
            pos += 8;
        } else {
            break;
        }
    }
    return 0;
}

static void quic_on_rx_authenticated(struct hy2_ctx *h, int level, uint64_t pn,
                                     const unsigned char *pay, size_t pay_len) {
    int64_t now_us = hy2_now_us();
    struct quic_rx_space *sp = &h->rx_space[level];
    if (quic_rx_pn_is_dup(sp, pn)) {
        /* Duplicate packet: suppress frame execution, schedule ACK so peer knows it arrived */
        sp->ack_needed = 1;
        return;
    }
    int ack_el = 0;
    quic_parse_frames(h, level, pay, pay_len, &ack_el);
    int ooo = quic_rx_pn_record(sp, pn, now_us);
    if (ack_el) {
        sp->ack_eliciting_cnt++;
        sp->ack_needed = 1;
        if (ooo || level < 2)
            sp->ack_eliciting_cnt += 2;
    }
}

/* Process a single UDP datagram (which may contain coalesced QUIC packets) */
static int quic_process_datagram(struct hy2_ctx *h, unsigned char *dgram, size_t dlen) {
    size_t pos = 0;
    while (pos < dlen) {
        unsigned char *pkt = dgram + pos;
        size_t rem = dlen - pos;
        if (rem < 21) break;

        if (pkt[0] & 0x80) {
            /* Long Header packet */
            int ptype = (pkt[0] >> 4) & 3;
            if (rem < 7) break;
            size_t dcid_len = pkt[5];
            if (6 + dcid_len + 1 > rem) break;
            size_t scid_len = pkt[6 + dcid_len];
            size_t off = 7 + dcid_len + scid_len;
            if (off > rem) break;
            const unsigned char *scid_ptr = pkt + 7 + dcid_len;

            if (ptype == 0) {
                uint64_t tok_len = 0;
                size_t u1 = 0;
                if (quic_get_varint(pkt + off, rem - off, &tok_len, &u1) != 0) break;
                if (tok_len > rem - off - u1) break;
                off += u1 + (size_t)tok_len;
            } else if (ptype != 2) {
                break;
            }

            uint64_t plen = 0;
            size_t u2 = 0;
            if (quic_get_varint(pkt + off, rem - off, &plen, &u2) != 0) break;
            off += u2;
            if (plen < 20 || plen > rem - off) break;
            size_t total_pkt_len = off + (size_t)plen;

            struct quic_level *lv = (ptype == 0) ? &h->rx_init : &h->rx_hs;
            if (!lv->ready) {
                pos += total_pkt_len;
                continue;
            }

            size_t pn_off = off;
            unsigned char mask[5];
            if (quic_hp_mask(lv, pkt + pn_off + 4, mask) != 0) break;
            pkt[0] ^= (unsigned char)(mask[0] & 0x0Fu);
            size_t pn_len = (size_t)((pkt[0] & 0x03u) + 1u);
            uint64_t pn = 0;
            for (size_t i = 0; i < pn_len; i++) {
                pkt[pn_off + i] ^= mask[1 + i];
                pn = (pn << 8) | pkt[pn_off + i];
            }
            if (lv->have_rx_pn) {
                uint64_t win = 1ULL << (pn_len * 8);
                uint64_t hwin = win >> 1;
                uint64_t expected = lv->max_rx_pn + 1;
                uint64_t cand = (expected & ~(win - 1)) | pn;
                if (cand + hwin <= expected && cand + win < (1ULL << 62)) cand += win;
                else if (cand > expected + hwin && cand >= win) cand -= win;
                pn = cand;
            }
            size_t hdr_len = pn_off + pn_len;
            size_t ciph_len = (size_t)plen - pn_len;
            if (ciph_len < 16) break;
            size_t pay_len = ciph_len - 16;

            unsigned char nonce[12];
            quic_make_nonce(lv->iv, pn, nonce);
            if (sc_aead_open(&lv->aead, nonce, pkt, hdr_len, pkt + hdr_len, pay_len, pkt + hdr_len + pay_len) == 0) {
                if (!h->got_server_scid && scid_len <= sizeof(h->dcid)) {
                    memcpy(h->dcid, scid_ptr, scid_len);
                    h->dcid_len = scid_len;
                    h->got_server_scid = 1;
                }
                if (!lv->have_rx_pn || pn > lv->max_rx_pn) {
                    lv->max_rx_pn = pn;
                    lv->have_rx_pn = 1;
                }
                quic_on_rx_authenticated(h, (ptype == 0) ? 0 : 1, pn, pkt + hdr_len, pay_len);
            } else {
                /* Restore header protection in case packet is re-processed after key derivation */
                for (size_t i = 0; i < pn_len; i++) pkt[pn_off + i] ^= mask[1 + i];
                pkt[0] ^= (unsigned char)(mask[0] & 0x0Fu);
            }
            pos += total_pkt_len;
        } else {
            /* Short Header (1-RTT) packet: consumes the rest of the UDP datagram */
            if (!h->rx_app.ready || rem < 1 + 8 + 4 + 16) break;
            size_t pn_off = 1 + 8; /* our SCID is 8 bytes */
            unsigned char mask[5];
            if (quic_hp_mask(&h->rx_app, pkt + pn_off + 4, mask) != 0) break;
            pkt[0] ^= (unsigned char)(mask[0] & 0x1Fu);
            uint8_t pkt_kp = (pkt[0] >> 2) & 1u;
            size_t pn_len = (size_t)((pkt[0] & 0x03u) + 1u);
            uint64_t pn = 0;
            for (size_t i = 0; i < pn_len; i++) {
                pkt[pn_off + i] ^= mask[1 + i];
                pn = (pn << 8) | pkt[pn_off + i];
            }
            /* Reconstruct full packet number if truncated */
            if (h->rx_app.have_rx_pn) {
                uint64_t win = 1ULL << (pn_len * 8);
                uint64_t hwin = win >> 1;
                uint64_t expected = h->rx_app.max_rx_pn + 1;
                uint64_t cand = (expected & ~(win - 1)) | pn;
                if (cand + hwin <= expected && cand + win < (1ULL << 62)) cand += win;
                else if (cand > expected + hwin && cand >= win) cand -= win;
                pn = cand;
            }
            size_t hdr_len = pn_off + pn_len;
            if (rem < hdr_len + 16) break;
            size_t pay_len = rem - hdr_len - 16;

            /* RFC 9001 §6: Key Update if Key Phase bit flipped and packet authenticates */
            if (pkt_kp != h->key_phase) {
                if (h->have_prev_rx && h->rx_app.have_rx_pn && pn <= h->rx_app.max_rx_pn) {
                    /* Reordered packet encrypted under the previous key phase */
                    unsigned char pnonce[12];
                    quic_make_nonce(h->prev_rx_iv, pn, pnonce);
                    if (sc_aead_open(&h->prev_rx_aead, pnonce, pkt, hdr_len, pkt + hdr_len, pay_len, pkt + hdr_len + pay_len) == 0) {
                        quic_on_rx_authenticated(h, 2, pn, pkt + hdr_len, pay_len);
                    }
                    break;
                }
                if (!h->rx_app.have_rx_pn || pn > h->rx_app.max_rx_pn) {
                    unsigned char next_s[48], next_c[48], next_k[32], next_iv[12];
                    struct sc_aead next_aead;
                    memset(&next_aead, 0, sizeof(next_aead));
                    if (quic_hkdf_label(h->hash_alg, h->s_ap_sec, h->hash_len, "quic ku", NULL, 0, next_s, h->hash_len) == 0 &&
                        quic_hkdf_label(h->hash_alg, next_s, h->hash_len, "quic key", NULL, 0, next_k, h->rx_app.klen) == 0 &&
                        quic_hkdf_label(h->hash_alg, next_s, h->hash_len, "quic iv",  NULL, 0, next_iv, 12) == 0 &&
                        sc_aead_setkey(&next_aead, h->rx_app.alg, next_k) == 0) {
                        unsigned char knonce[12];
                        quic_make_nonce(next_iv, pn, knonce);
                        if (sc_aead_open(&next_aead, knonce, pkt, hdr_len, pkt + hdr_len, pay_len, pkt + hdr_len + pay_len) == 0) {
                            if (h->have_prev_rx) sc_aead_free(&h->prev_rx_aead);
                            h->prev_rx_aead = h->rx_app.aead;
                            memcpy(h->prev_rx_iv, h->rx_app.iv, 12);
                            h->have_prev_rx = 1;
                            h->rx_app.aead = next_aead;
                            memcpy(h->rx_app.iv, next_iv, 12);
                            memcpy(h->s_ap_sec, next_s, h->hash_len);
                            /* Also rotate client 1-RTT traffic key & IV (HP key never changes per RFC 9001 §6.1) */
                            if (quic_hkdf_label(h->hash_alg, h->c_ap_sec, h->hash_len, "quic ku", NULL, 0, next_c, h->hash_len) == 0 &&
                                quic_hkdf_label(h->hash_alg, next_c, h->hash_len, "quic key", NULL, 0, next_k, h->tx_app.klen) == 0 &&
                                quic_hkdf_label(h->hash_alg, next_c, h->hash_len, "quic iv",  NULL, 0, h->tx_app.iv, 12) == 0) {
                                sc_aead_free(&h->tx_app.aead);
                                sc_aead_setkey(&h->tx_app.aead, h->tx_app.alg, next_k);
                                memcpy(h->c_ap_sec, next_c, h->hash_len);
                            }
                            h->key_phase = pkt_kp;
                            h->rx_app.max_rx_pn = pn;
                            h->rx_app.have_rx_pn = 1;
                            quic_on_rx_authenticated(h, 2, pn, pkt + hdr_len, pay_len);
                            break;
                        }
                        sc_aead_free(&next_aead);
                    }
                }
            }

            unsigned char nonce[12];
            quic_make_nonce(h->rx_app.iv, pn, nonce);
            if (sc_aead_open(&h->rx_app.aead, nonce, pkt, hdr_len, pkt + hdr_len, pay_len, pkt + hdr_len + pay_len) == 0) {
                if (!h->rx_app.have_rx_pn || pn > h->rx_app.max_rx_pn) {
                    h->rx_app.max_rx_pn = pn;
                    h->rx_app.have_rx_pn = 1;
                }
                quic_on_rx_authenticated(h, 2, pn, pkt + hdr_len, pay_len);
            }
            break;
        }
    }
    return 0;
}

static size_t build_quic_client_hello(const struct hy2_ctx *h, const struct tr_node *n,
                                      const unsigned char scid[8],
                                      const unsigned char xpub[32], unsigned char *out) {
    unsigned char rnd[32];
    xc_random(rnd, 32);

    const char *sni = (n->sni && n->sni[0]) ? n->sni : n->host;
    size_t sni_len = sni ? strlen(sni) : 0;
    if (sni_len > 255) return 0;

    size_t o = 4; /* reserve 4 bytes for Handshake header [0x01][len24] */
    out[o++] = 0x03; out[o++] = 0x03; /* legacy_version */
    memcpy(out + o, rnd, 32); o += 32;
    out[o++] = 0x00; /* legacy_session_id = empty (RFC 9001 §8.4) */

    /* Cipher Suites: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256 */
    out[o++] = 0x00; out[o++] = 0x06;
    out[o++] = 0x13; out[o++] = 0x01;
    out[o++] = 0x13; out[o++] = 0x02;
    out[o++] = 0x13; out[o++] = 0x03;

    /* Compression methods */
    out[o++] = 0x01; out[o++] = 0x00;

    size_t ext_len_pos = o;
    o += 2;

    /* 1. server_name (0x0000) */
    if (sni_len > 0) {
        out[o++] = 0x00; out[o++] = 0x00;
        size_t el = sni_len + 5;
        out[o++] = (unsigned char)(el >> 8); out[o++] = (unsigned char)el;
        out[o++] = (unsigned char)((sni_len + 3) >> 8); out[o++] = (unsigned char)(sni_len + 3);
        out[o++] = 0x00;
        out[o++] = (unsigned char)(sni_len >> 8); out[o++] = (unsigned char)sni_len;
        memcpy(out + o, sni, sni_len); o += sni_len;
    }

    /* 2. supported_versions (0x002b) -> TLS 1.3 (0x0304) */
    out[o++] = 0x00; out[o++] = 0x2b;
    out[o++] = 0x00; out[o++] = 0x03;
    out[o++] = 0x02; out[o++] = 0x03; out[o++] = 0x04;

    /* 3. supported_groups (0x000a) -> X25519 (0x001d) */
    out[o++] = 0x00; out[o++] = 0x0a;
    out[o++] = 0x00; out[o++] = 0x04;
    out[o++] = 0x00; out[o++] = 0x02;
    out[o++] = 0x00; out[o++] = 0x1d;

    /* 4. signature_algorithms (0x000d) */
    static const unsigned char sig_ext[] = {
        0x00, 0x0d, 0x00, 0x14, 0x00, 0x12,
        0x04, 0x03, 0x05, 0x03, 0x06, 0x03,
        0x08, 0x07, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06,
        0x04, 0x01, 0x05, 0x01
    };
    memcpy(out + o, sig_ext, sizeof(sig_ext));
    o += sizeof(sig_ext);

    /* 5. key_share (0x0033) -> X25519 (0x001d, 32B) */
    out[o++] = 0x00; out[o++] = 0x33;
    out[o++] = 0x00; out[o++] = 0x26;
    out[o++] = 0x00; out[o++] = 0x24;
    out[o++] = 0x00; out[o++] = 0x1d;
    out[o++] = 0x00; out[o++] = 0x20;
    memcpy(out + o, xpub, 32); o += 32;

    /* 6. ALPN (0x0010) -> "h3" */
    out[o++] = 0x00; out[o++] = 0x10;
    out[o++] = 0x00; out[o++] = 0x05;
    out[o++] = 0x00; out[o++] = 0x03;
    out[o++] = 0x02; out[o++] = 'h'; out[o++] = '3';

    /* 7. quic_transport_parameters (0x0039) */
    unsigned char tp[128];
    size_t tpo = 0;
    #define PUT_TP_VAR(id, val) do { \
        tpo += quic_put_varint(tp + tpo, (id)); \
        unsigned char _vb[8]; \
        size_t _vl = quic_put_varint(_vb, (val)); \
        tpo += quic_put_varint(tp + tpo, _vl); \
        memcpy(tp + tpo, _vb, _vl); tpo += _vl; \
    } while (0)
    PUT_TP_VAR(0x01, 30000);                /* max_idle_timeout = 30s */
    PUT_TP_VAR(0x04, h->local_max_data);    /* initial_max_data */
    PUT_TP_VAR(0x05, h->local_s4_max_data); /* initial_max_stream_data_bidi_local */
    PUT_TP_VAR(0x06, h->local_s4_max_data); /* initial_max_stream_data_bidi_remote */
    PUT_TP_VAR(0x07, 1048576);              /* initial_max_stream_data_uni = 1MB */
    PUT_TP_VAR(0x08, 100);         /* initial_max_streams_bidi = 100 */
    PUT_TP_VAR(0x09, 100);         /* initial_max_streams_uni = 100 */
    PUT_TP_VAR(0x0e, 2);           /* active_connection_id_limit = 2 */
    /* disable_active_migration (0x0c) = zero-length value */
    tpo += quic_put_varint(tp + tpo, 0x0c);
    tpo += quic_put_varint(tp + tpo, 0);
    PUT_TP_VAR(0x20, 65535);       /* max_datagram_frame_size = 65535 */
    /* initial_source_connection_id (0x0f) = scid (8B) */
    tpo += quic_put_varint(tp + tpo, 0x0f);
    tpo += quic_put_varint(tp + tpo, 8);
    memcpy(tp + tpo, scid, 8); tpo += 8;
    #undef PUT_TP_VAR

    out[o++] = 0x00; out[o++] = 0x39;
    out[o++] = (unsigned char)(tpo >> 8); out[o++] = (unsigned char)tpo;
    memcpy(out + o, tp, tpo); o += tpo;

    size_t ext_len = o - (ext_len_pos + 2);
    out[ext_len_pos]     = (unsigned char)(ext_len >> 8);
    out[ext_len_pos + 1] = (unsigned char)ext_len;

    size_t body_len = o - 4;
    out[0] = 0x01; /* ClientHello */
    out[1] = (unsigned char)(body_len >> 16);
    out[2] = (unsigned char)(body_len >> 8);
    out[3] = (unsigned char)body_len;
    return o;
}

static int parse_server_hello(const unsigned char *sh, size_t len, uint16_t *suite, unsigned char srv_pub[32]) {
    if (len < 38) return -1;
    size_t pos = 34; /* version (2) + random (32) */
    size_t sid_len = sh[pos++];
    if (pos + sid_len + 3 > len) return -1;
    pos += sid_len;
    *suite = (uint16_t)(((uint16_t)sh[pos] << 8) | sh[pos + 1]);
    pos += 3; /* suite (2) + compression (1) */
    if (pos + 2 > len) return -1;
    size_t ext_len = ((size_t)sh[pos] << 8) | sh[pos + 1];
    pos += 2;
    if (pos + ext_len > len) return -1;
    size_t end = pos + ext_len;
    int got_ks = 0;
    while (pos + 4 <= end) {
        uint16_t et = (uint16_t)(((uint16_t)sh[pos] << 8) | sh[pos + 1]);
        size_t el = ((size_t)sh[pos + 2] << 8) | sh[pos + 3];
        pos += 4;
        if (pos + el > end) return -1;
        if (et == 0x0033 && el >= 36) { /* key_share */
            uint16_t grp = (uint16_t)(((uint16_t)sh[pos] << 8) | sh[pos + 1]);
            uint16_t kl  = (uint16_t)(((uint16_t)sh[pos + 2] << 8) | sh[pos + 3]);
            if (grp == 0x001d && kl == 32) {
                memcpy(srv_pub, sh + pos + 4, 32);
                got_ks = 1;
            }
        }
        pos += el;
    }
    return got_ks ? 0 : -1;
}

/* Parse server EncryptedExtensions (RFC 8446 §4.3.1, RFC 9001 §8.1) and verify ALPN + TP */
static int parse_encrypted_extensions(struct hy2_ctx *h, const unsigned char *ee, size_t len) {
    if (len < 2) return -1;
    size_t ext_len = ((size_t)ee[0] << 8) | ee[1];
    if (ext_len + 2 != len) return -1;
    int got_tp = 0, got_alpn = 0;
    size_t pos = 2;
    while (pos + 4 <= len) {
        uint16_t et = (uint16_t)(((uint16_t)ee[pos] << 8) | ee[pos + 1]);
        size_t el = ((size_t)ee[pos + 2] << 8) | ee[pos + 3];
        pos += 4;
        if (pos + el > len) return -1;
        if (et == 0x0010) { /* ALPN */
            if (el < 3) return -1;
            size_t list_len = ((size_t)ee[pos] << 8) | ee[pos + 1];
            if (list_len + 2 != el || list_len < 1) return -1;
            size_t plen = ee[pos + 2];
            if (1 + plen != list_len || plen != 2 || memcmp(ee + pos + 3, "h3", 2) != 0)
                return -1;
            got_alpn = 1;
        } else if (et == 0x0039) {
            got_tp = 1;
            size_t tpos = 0;
            while (tpos < el) {
                uint64_t tid = 0, tlen = 0;
                size_t u1 = 0, u2 = 0;
                if (quic_get_varint(ee + pos + tpos, el - tpos, &tid, &u1) != 0) return -1;
                tpos += u1;
                if (quic_get_varint(ee + pos + tpos, el - tpos, &tlen, &u2) != 0) return -1;
                tpos += u2;
                if (tlen > el - tpos) return -1;
                const unsigned char *vp = ee + pos + tpos;
                if (tid == 0x04 || tid == 0x06 || tid == 0x07 || tid == 0x0a || tid == 0x0b) {
                    uint64_t v = 0;
                    size_t uv = 0;
                    if (quic_get_varint(vp, (size_t)tlen, &v, &uv) != 0 || uv != (size_t)tlen)
                        return -1;
                    if (tid == 0x04) h->peer_max_data = v;
                    else if (tid == 0x06) h->peer_s4_max_data = v;
                    else if (tid == 0x07) h->peer_uni_max_data = v;
                    else if (tid == 0x0a && v <= 20) h->peer_ack_delay_exp = (uint8_t)v;
                    else if (tid == 0x0b && v <= 16384) h->peer_max_ack_delay_us = (int64_t)v * 1000;
                }
                tpos += (size_t)tlen;
            }
        }
        pos += el;
    }
    return (got_tp && got_alpn) ? 0 : -1;
}

static void hy2_drain_socket(struct hy2_ctx *h) {
    for (int i = 0; i < 256; i++) {
        unsigned char dgram[2048];
        ssize_t r = hy2_udp_recv(h, dgram, sizeof(dgram), MSG_DONTWAIT);
        if (r <= 0) break;
        quic_process_datagram(h, dgram, (size_t)r);
    }
}

static size_t hy2_Active_Sent_Count(const struct hy2_ctx *h) {
    size_t c = 0;
    for (size_t i = 0; i < QUIC_SENT_MAX; i++) {
        if (h->sent_pkts[i].in_use) c++;
    }
    return c;
}

/* Flush pending ACKs, retransmissions, flow-control updates, and queued Stream 4 data */
static int hy2_flush_tx(struct hy2_ctx *h, int64_t now_us) {
    /* 1. Initial level */
    if (h->tx_init.ready && (h->ch_retx_due || h->rx_space[0].ack_needed)) {
        unsigned char f[1200];
        size_t fo = 0;
        uint8_t ack_el = 0, has_cr = 0;
        if (h->rx_space[0].n_ranges > 0 && (h->rx_space[0].ack_needed || h->ch_retx_due))
            fo += quic_build_ack_ranges(&h->rx_space[0], now_us, f + fo, 256);
        if (h->ch_retx_due && h->ch_tx_len > 0 && h->ch_tx_len <= sizeof(f) - 10) {
            if (fo + 10 + h->ch_tx_len > sizeof(f) && fo > 0) {
                int rc = quic_send_long_ex(h, 0, &h->tx_init, f, fo, 0, 0, 0, 0, 0);
                if (rc) return rc;
                fo = 0;
            }
            f[fo++] = 0x06;
            f[fo++] = 0x00;
            fo += quic_put_varint(f + fo, h->ch_tx_len);
            memcpy(f + fo, h->ch_tx, h->ch_tx_len);
            fo += h->ch_tx_len;
            ack_el = 1;
            has_cr = 1;
            h->ch_retx_due = 0;
        }
        if (fo > 0) {
            int rc = quic_send_long_ex(h, 0, &h->tx_init, f, fo, has_cr ? 1 : 0,
                                       ack_el, has_cr, 0, (uint32_t)h->ch_tx_len);
            if (rc) return rc;
        }
    }

    /* 2. Handshake level */
    if (h->tx_hs.ready && (h->fin_retx_due || h->rx_space[1].ack_needed)) {
        unsigned char f[1200];
        size_t fo = 0;
        uint8_t ack_el = 0, has_cr = 0;
        if (h->rx_space[1].n_ranges > 0 && (h->rx_space[1].ack_needed || h->fin_retx_due))
            fo += quic_build_ack_ranges(&h->rx_space[1], now_us, f + fo, 256);
        if (h->fin_retx_due && h->fin_tx_len > 0 && h->fin_tx_len <= sizeof(f) - 10) {
            if (fo + 10 + h->fin_tx_len > sizeof(f) && fo > 0) {
                int rc = quic_send_long_ex(h, 2, &h->tx_hs, f, fo, 0, 0, 0, 0, 0);
                if (rc) return rc;
                fo = 0;
            }
            f[fo++] = 0x06;
            f[fo++] = 0x00;
            fo += quic_put_varint(f + fo, h->fin_tx_len);
            memcpy(f + fo, h->fin_tx, h->fin_tx_len);
            fo += h->fin_tx_len;
            ack_el = 1;
            has_cr = 1;
            h->fin_retx_due = 0;
        }
        if (fo > 0) {
            int rc = quic_send_long_ex(h, 2, &h->tx_hs, f, fo, 0,
                                       ack_el, has_cr, 0, (uint32_t)h->fin_tx_len);
            if (rc) return rc;
        }
    }

    if (!h->tx_app.ready) return 0;

    /* 3. 1-RTT Stream 2 (HTTP/3 SETTINGS) & Stream 0 (HY2 /auth) */
    if (h->s2_retx_due || h->s0_retx_due) {
        unsigned char f[1200];
        size_t fo = 0;
        uint8_t has_s2 = 0, has_s0 = 0;
        if (h->rx_space[2].ack_needed && h->rx_space[2].n_ranges > 0)
            fo += quic_build_ack_ranges(&h->rx_space[2], now_us, f + fo, 256);
        if (h->s2_retx_due && h->s2_tx_len > 0) {
            f[fo++] = 0x0A; /* STREAM(LEN=1, OFF=0, FIN=0) */
            f[fo++] = 0x02; /* sid = 2 */
            fo += quic_put_varint(f + fo, h->s2_tx_len);
            memcpy(f + fo, h->s2_tx, h->s2_tx_len);
            fo += h->s2_tx_len;
            has_s2 = 1;
            h->s2_retx_due = 0;
        }
        if (h->s0_retx_due && h->s0_tx_len > 0) {
            f[fo++] = 0x0B; /* STREAM(LEN=1, OFF=0, FIN=1) */
            f[fo++] = 0x00; /* sid = 0 */
            fo += quic_put_varint(f + fo, h->s0_tx_len);
            memcpy(f + fo, h->s0_tx, h->s0_tx_len);
            fo += h->s0_tx_len;
            has_s0 = 1;
            h->s0_retx_due = 0;
        }
        if (fo > 0) {
            int rc = quic_send_1rtt_ex(h, f, fo, 1, has_s2, has_s0, 0, 0, (uint32_t)h->s0_tx_len, 1, NULL);
            if (rc) return rc;
        }
    }

    /* 4. 1-RTT Stream 4 retransmissions (priority over new data, never consumes new flow-control credit) */
    while (h->s4_tx_buf && hy2_Active_Sent_Count(h) < QUIC_SENT_MAX - 8) {
        size_t best = QUIC_RETX_MAX;
        uint64_t min_soff = UINT64_MAX;
        for (size_t i = 0; i < QUIC_RETX_MAX; i++) {
            if (h->s4_retx[i].in_use && h->s4_retx[i].soff < min_soff) {
                min_soff = h->s4_retx[i].soff;
                best = i;
            }
        }
        if (best == QUIC_RETX_MAX) break;
        /* Allow retransmission if cwnd permits or nothing is currently in flight */
        if (h->bytes_in_flight > 0 && h->bytes_in_flight >= h->cwnd)
            break;

        uint64_t soff = h->s4_retx[best].soff;
        uint32_t slen = h->s4_retx[best].slen;
        uint8_t  sfin = h->s4_retx[best].fin;
        h->s4_retx[best].in_use = 0;

        unsigned char f[1400];
        size_t fo = 0;
        struct quic_fc_meta fc;
        memset(&fc, 0, sizeof(fc));
        if (h->rx_space[2].ack_needed && h->rx_space[2].n_ranges > 0)
            fo += quic_build_ack_ranges(&h->rx_space[2], now_us, f + fo, 180);
        if (h->rx_win_update_due) {
            f[fo++] = 0x11; /* MAX_STREAM_DATA */
            f[fo++] = 0x04; /* sid = 4 */
            fo += quic_put_varint(f + fo, h->local_s4_max_data);
            f[fo++] = 0x10; /* MAX_DATA */
            fo += quic_put_varint(f + fo, h->local_max_data);
            fc.has_win_update = 1;
            fc.msd_val = h->local_s4_max_data;
            fc.md_val  = h->local_max_data;
            h->rx_win_update_due = 0;
        }
        uint8_t stype = (soff ? 0x0Eu : 0x0Au) | (sfin ? 0x01u : 0x00u);
        f[fo++] = stype;
        f[fo++] = 0x04; /* sid = 4 */
        if (soff) fo += quic_put_varint(f + fo, soff);
        fo += quic_put_varint(f + fo, slen);
        for (uint32_t k = 0; k < slen; k++)
            f[fo + k] = h->s4_tx_buf[(soff + k) & (HY2_TX_CAP - 1)];
        fo += slen;

        int rc = quic_send_1rtt_ex(h, f, fo, 1, 0, 1, 4, soff, slen, sfin, &fc);
        if (rc) return rc;
    }

    /* 5. 1-RTT Stream 4 new data (bounded by peer flow control and congestion window) */
    while (h->s4_tx_buf && h->s4_sent_off < h->s4_write_off &&
           hy2_Active_Sent_Count(h) < QUIC_SENT_MAX - 16) {
        if (h->bytes_in_flight >= h->cwnd)
            break;

        uint64_t s4_credit = (h->peer_s4_max_data > h->s4_sent_off)
                                 ? (h->peer_s4_max_data - h->s4_sent_off) : 0;
        uint64_t conn_used = h->s0_tx_len + h->s2_tx_len + h->s4_sent_off;
        uint64_t conn_credit = (h->peer_max_data > conn_used)
                                   ? (h->peer_max_data - conn_used) : 0;
        uint64_t fc_credit = s4_credit < conn_credit ? s4_credit : conn_credit;

        if (fc_credit == 0) {
            if (s4_credit == 0 && h->s4_blocked_at != h->peer_s4_max_data) {
                h->s4_blocked_at = h->peer_s4_max_data;
                h->tx_s4_blocked_due = 1;
            }
            if (conn_credit == 0 && h->conn_blocked_at != h->peer_max_data) {
                h->conn_blocked_at = h->peer_max_data;
                h->tx_conn_blocked_due = 1;
            }
            break;
        }

        uint64_t cwnd_rem = h->cwnd - h->bytes_in_flight;
        size_t chunk = (size_t)(h->s4_write_off - h->s4_sent_off);
        if (chunk > 1100) chunk = 1100;
        if (chunk > fc_credit) chunk = (size_t)fc_credit;
        if (chunk > cwnd_rem) chunk = (size_t)cwnd_rem;
        if (!chunk) break;

        uint64_t soff = h->s4_sent_off;
        unsigned char f[1400];
        size_t fo = 0;
        struct quic_fc_meta fc;
        memset(&fc, 0, sizeof(fc));
        if (h->rx_space[2].ack_needed && h->rx_space[2].n_ranges > 0)
            fo += quic_build_ack_ranges(&h->rx_space[2], now_us, f + fo, 180);
        if (h->rx_win_update_due) {
            f[fo++] = 0x11; /* MAX_STREAM_DATA */
            f[fo++] = 0x04;
            fo += quic_put_varint(f + fo, h->local_s4_max_data);
            f[fo++] = 0x10; /* MAX_DATA */
            fo += quic_put_varint(f + fo, h->local_max_data);
            fc.has_win_update = 1;
            fc.msd_val = h->local_s4_max_data;
            fc.md_val  = h->local_max_data;
            h->rx_win_update_due = 0;
        }
        f[fo++] = soff ? 0x0E : 0x0A;
        f[fo++] = 0x04; /* sid = 4 */
        if (soff) fo += quic_put_varint(f + fo, soff);
        fo += quic_put_varint(f + fo, chunk);
        for (size_t k = 0; k < chunk; k++)
            f[fo + k] = h->s4_tx_buf[(soff + k) & (HY2_TX_CAP - 1)];
        fo += chunk;
        h->s4_sent_off += chunk;

        /* Check if we just exhausted peer flow control credit while more data remains */
        if (h->s4_sent_off < h->s4_write_off) {
            if (h->s4_sent_off >= h->peer_s4_max_data && h->s4_blocked_at != h->peer_s4_max_data) {
                h->s4_blocked_at = h->peer_s4_max_data;
                h->tx_s4_blocked_due = 1;
            }
            if (h->s0_tx_len + h->s2_tx_len + h->s4_sent_off >= h->peer_max_data &&
                h->conn_blocked_at != h->peer_max_data) {
                h->conn_blocked_at = h->peer_max_data;
                h->tx_conn_blocked_due = 1;
            }
        }

        int rc = quic_send_1rtt_ex(h, f, fo, 1, 0, 1, 4, soff, (uint32_t)chunk, 0, &fc);
        if (rc) return rc;
    }

    /* 6. Standalone 1-RTT control frames (ACK, MAX_STREAM_DATA, MAX_DATA, BLOCKED, PING) */
    if (h->rx_space[2].ack_needed || h->rx_win_update_due ||
        h->tx_s4_blocked_due || h->tx_conn_blocked_due || h->ping_due) {
        unsigned char f[384];
        size_t fo = 0;
        uint8_t ack_el = 0;
        struct quic_fc_meta fc;
        memset(&fc, 0, sizeof(fc));
        if (h->rx_space[2].ack_needed && h->rx_space[2].n_ranges > 0)
            fo += quic_build_ack_ranges(&h->rx_space[2], now_us, f + fo, 256);
        if (h->rx_win_update_due) {
            f[fo++] = 0x11; /* MAX_STREAM_DATA */
            f[fo++] = 0x04; /* sid = 4 */
            fo += quic_put_varint(f + fo, h->local_s4_max_data);
            f[fo++] = 0x10; /* MAX_DATA */
            fo += quic_put_varint(f + fo, h->local_max_data);
            fc.has_win_update = 1;
            fc.msd_val = h->local_s4_max_data;
            fc.md_val  = h->local_max_data;
            h->rx_win_update_due = 0;
            ack_el = 1;
        }
        if (h->tx_s4_blocked_due) {
            f[fo++] = 0x15; /* STREAM_DATA_BLOCKED */
            f[fo++] = 0x04; /* sid = 4 */
            fo += quic_put_varint(f + fo, h->peer_s4_max_data);
            fc.has_s4_blocked = 1;
            fc.s4_blocked_val = h->peer_s4_max_data;
            h->tx_s4_blocked_due = 0;
            ack_el = 1;
        }
        if (h->tx_conn_blocked_due) {
            f[fo++] = 0x14; /* DATA_BLOCKED */
            fo += quic_put_varint(f + fo, h->peer_max_data);
            fc.has_conn_blocked = 1;
            fc.conn_blocked_val = h->peer_max_data;
            h->tx_conn_blocked_due = 0;
            ack_el = 1;
        }
        if (h->ping_due) {
            f[fo++] = 0x01; /* PING */
            h->ping_due = 0;
            ack_el = 1;
        }
        if (fo > 0) {
            int rc = quic_send_1rtt_ex(h, f, fo, ack_el, 0, 0, 0, 0, 0, 0, &fc);
            if (rc) return rc;
        }
    }
    return 0;
}

static void hy2_tick(struct hy2_ctx *h) {
    if (!h || h->peer_closed || h->proto_err) return;
    hy2_drain_socket(h);
    int64_t now_us = hy2_now_us();
    for (int lvl = 0; lvl < 3; lvl++)
        quic_detect_lost(h, lvl, now_us);
    quic_check_pto(h, now_us);
    hy2_flush_tx(h, now_us);
    hy2_drain_socket(h);
}

/* Prepare HTTP/3 Control stream (Stream 2) and Hysteria2 /auth request (Stream 0) */
static int hy2_send_auth(struct hy2_ctx *h, const struct tr_node *n) {
    /* 1. Stream 2 (Unidirectional Control Stream): type 0x00 + SETTINGS frame (0x04) */
    static const unsigned char s2[8] = {
        0x00,                   /* Stream Type = Control Stream (0x00) */
        0x04, 0x05,             /* Frame Type = SETTINGS (0x04), Length = 5 */
        0x42, 0x76, 0x01,       /* H3_DATAGRAM_RFC9297 (0x276) = 1 */
        0x01, 0x00              /* QPACK_MAX_TABLE_CAPACITY = 0 */
    };
    memcpy(h->s2_tx, s2, sizeof(s2));
    h->s2_tx_len = sizeof(s2);
    h->s2_tx_off = sizeof(s2);

    /* 2. Stream 0 (Bidirectional Request Stream): HEADERS frame (0x01) for POST https://hysteria/auth */
    const char *pw = n->uuid ? n->uuid : "";
    size_t pw_len = strlen(pw);
    if (pw_len > 255) return TR_EIO;
    unsigned char qpack[512];
    size_t qo = 0;
    qpack[qo++] = 0x00; qpack[qo++] = 0x00; /* Required Insert Count = 0, Delta Base = 0 */
    qpack[qo++] = 0xd4; /* :method = POST (static 20 -> 0xC0 | 20 = 0xD4) */
    qpack[qo++] = 0xd7; /* :scheme = https (static 23 -> 0xC0 | 23 = 0xD7) */
    qpack[qo++] = 0x50; qpack[qo++] = 8; memcpy(qpack + qo, "hysteria", 8); qo += 8; /* :authority */
    qpack[qo++] = 0x51; qpack[qo++] = 5; memcpy(qpack + qo, "/auth", 5); qo += 5;    /* :path */

    /* user-agent: quic-go HTTP/3 */
    qpack[qo++] = 0x5f; qpack[qo++] = 95 - 15; /* static 95 = user-agent */
    qpack[qo++] = 14;
    memcpy(qpack + qo, "quic-go HTTP/3", 14); qo += 14;

    /* content-length: 0 (static 4 = 0xc4) */
    qpack[qo++] = 0xc4;

    /* hysteria-auth */
    qpack[qo++] = 0x27; qpack[qo++] = 13 - 7;
    memcpy(qpack + qo, "hysteria-auth", 13); qo += 13;
    if (pw_len < 127) {
        qpack[qo++] = (unsigned char)pw_len;
    } else {
        qpack[qo++] = 0x7F;
        size_t rem_pw = pw_len - 127;
        while (rem_pw >= 128) {
            qpack[qo++] = (unsigned char)((rem_pw & 0x7Fu) | 0x80u);
            rem_pw >>= 7;
        }
        qpack[qo++] = (unsigned char)rem_pw;
    }
    if (qo + pw_len + 64 > sizeof(qpack)) return TR_EIO;
    memcpy(qpack + qo, pw, pw_len); qo += pw_len;

    /* hysteria-cc-rx: 100000000 */
    qpack[qo++] = 0x27; qpack[qo++] = 14 - 7;
    memcpy(qpack + qo, "hysteria-cc-rx", 14); qo += 14;
    qpack[qo++] = 9; memcpy(qpack + qo, "100000000", 9); qo += 9;

    /* hysteria-padding */
    qpack[qo++] = 0x27; qpack[qo++] = 16 - 7;
    memcpy(qpack + qo, "hysteria-padding", 16); qo += 16;
    qpack[qo++] = 16;
    memcpy(qpack + qo, "aaaaaaaaaaaaaaaa", 16); qo += 16;

    if (1 + 4 + qo > sizeof(h->s0_tx)) return TR_EIO;
    size_t ho = 0;
    h->s0_tx[ho++] = 0x01; /* HEADERS frame */
    ho += quic_put_varint(h->s0_tx + ho, qo);
    memcpy(h->s0_tx + ho, qpack, qo);
    ho += qo;
    h->s0_tx_len = ho;
    h->s0_tx_off = ho;

    h->s2_retx_due = 1;
    h->s0_retx_due = 1;
    return hy2_flush_tx(h, hy2_now_us());
}

static int hy2_open(struct transport *t, const struct tr_node *n, int timeout_s) {
    if (!vless_enable_hy2()) return TR_ENONODE;
    int fd = tr_dial_udp(n->host, n->port, n->mport, timeout_s);
    if (fd < 0) return fd;
    t->link.fd = fd;
    t->link.plain = 1;

    struct hy2_ctx *h = calloc(1, sizeof(*h));
    if (!h) return TR_EIO;
    t->hy2 = h;
    h->fd = fd;
    h->timeout_s = timeout_s > 0 ? timeout_s : 8;
    if (n->obfs_pass && n->obfs_pass[0])
        snprintf(h->obfs_pass, sizeof(h->obfs_pass), "%s", n->obfs_pass);

    h->smoothed_rtt_us       = 30000; /* 30ms initial RTT estimate */
    h->rttvar_us             = 15000;
    h->peer_max_ack_delay_us = 25000;
    h->peer_ack_delay_exp    = 3;
    h->cwnd                  = 14400; /* 12 * 1200B initial window */
    h->ssthresh              = UINT64_MAX;
    h->peer_max_data         = 16777216ULL;
    h->peer_s4_max_data      = 6291456ULL;
    h->peer_uni_max_data     = 1048576ULL;
    h->s4_blocked_at         = UINT64_MAX;
    h->conn_blocked_at       = UINT64_MAX;
    h->acked_s4_blocked_at   = UINT64_MAX;
    h->acked_conn_blocked_at = UINT64_MAX;
    h->local_max_data        = 16777216ULL;
    h->local_s4_max_data     = 6291456ULL;
    h->local_s4_win          = 6291456ULL;
    h->local_conn_win        = 16777216ULL;
    const char *rxw_env = getenv("TUNVLESS_HY2_RX_WIN");
    if (rxw_env && rxw_env[0]) {
        unsigned long wv = strtoul(rxw_env, NULL, 10);
        if (wv >= 2048 && wv <= 16777216UL) {
            h->local_s4_win      = (uint64_t)wv;
            h->local_s4_max_data = (uint64_t)wv;
            h->local_conn_win    = (uint64_t)wv * 2;
            h->local_max_data    = (uint64_t)wv * 2;
        }
    }
    h->acked_local_max_data    = h->local_max_data;
    h->acked_local_s4_max_data = h->local_s4_max_data;

    h->rx_cap = HY2_RX_CAP;
    h->rx_buf = malloc(h->rx_cap);
    h->s4_tx_buf = malloc(HY2_TX_CAP);
    h->crypto_buf[0] = calloc(1, HY2_CRYPTO_CAP);
    h->crypto_buf[1] = calloc(1, HY2_CRYPTO_CAP);
    h->crypto_seen[0] = calloc(1, HY2_CRYPTO_CAP);
    h->crypto_seen[1] = calloc(1, HY2_CRYPTO_CAP);
    if (!h->rx_buf || !h->s4_tx_buf || !h->crypto_buf[0] || !h->crypto_buf[1] ||
        !h->crypto_seen[0] || !h->crypto_seen[1]) return TR_EIO;

    if (xc_random(h->scid, 8) != 0 || xc_random(h->dcid, 8) != 0) return TR_EIO;
    h->dcid_len = 8;

    /* QUIC v1 Initial Secrets (RFC 9001 §5.2) */
    static const unsigned char quic_v1_salt[20] = {
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
        0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
    };
    unsigned char init_sec[32], c_in[32], s_in[32];
    if (sc_hkdf_extract(SC_SHA256, quic_v1_salt, 20, h->dcid, 8, init_sec) != 0 ||
        quic_hkdf_label(SC_SHA256, init_sec, 32, "client in", NULL, 0, c_in, 32) != 0 ||
        quic_hkdf_label(SC_SHA256, init_sec, 32, "server in", NULL, 0, s_in, 32) != 0 ||
        quic_level_setup(&h->tx_init, SC_SHA256, SC_AES128_GCM, c_in, 32) != 0 ||
        quic_level_setup(&h->rx_init, SC_SHA256, SC_AES128_GCM, s_in, 32) != 0)
        return TR_EIO;

    unsigned char xpriv[32], xpub[32];
    if (xc_x25519_keypair(xpriv, xpub) != 0) return TR_EIO;

    h->ch_tx_len = build_quic_client_hello(h, n, h->scid, xpub, h->ch_tx);
    if (!h->ch_tx_len) return TR_EIO;
    h->ch_retx_due = 1;
    if (hy2_flush_tx(h, hy2_now_us()) != 0) return TR_EIO;

    struct sc_hash_ctx th;
    int th_inited = 0;
    unsigned char hs_secret[48], c_hs_sec[48], s_hs_sec[48];
    unsigned char *cert_der = NULL;
    size_t cert_der_len = 0;
    unsigned char cert_th[48];
    int got_sh = 0, got_ee = 0, got_cert = 0, got_cv = 0, got_fin = 0;

    int64_t deadline = hy2_now_ms() + (int64_t)h->timeout_s * 1000;

    while (!h->auth_ok) {
        if (h->proto_err) {
            free(cert_der);
            if (th_inited) sc_hash_free(&th);
            return h->proto_err;
        }
        if (h->auth_failed) {
            free(cert_der);
            if (th_inited) sc_hash_free(&th);
            return TR_ECLOSED;
        }
        int64_t now = hy2_now_ms();
        if (now >= deadline) {
            free(cert_der);
            if (th_inited) sc_hash_free(&th);
            return TLS13_ETIMEOUT;
        }

        int64_t now_us = hy2_now_us();
        for (int lvl = 0; lvl < 3; lvl++)
            quic_detect_lost(h, lvl, now_us);
        quic_check_pto(h, now_us);
        hy2_flush_tx(h, now_us);

        struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
        int wait_ms = (int)(deadline - now);
        if (wait_ms > 20) wait_ms = 20;
        if (wait_ms < 1) wait_ms = 1;
        int pr = poll(&pfd, 1, wait_ms);
        if (pr <= 0) continue;

        unsigned char dgram[2048];
        ssize_t r = hy2_udp_recv(h, dgram, sizeof(dgram), MSG_DONTWAIT);
        if (r <= 0) continue;
        unsigned char dgram_copy[2048], dgram_copy2[2048];
        if (!got_sh) memcpy(dgram_copy, dgram, (size_t)r);
        if (!got_fin) memcpy(dgram_copy2, dgram, (size_t)r);
        quic_process_datagram(h, dgram, (size_t)r);
        if (h->proto_err) {
            free(cert_der);
            if (th_inited) sc_hash_free(&th);
            return h->proto_err;
        }

        /* Step A: Parse ServerHello from Initial CRYPTO stream */
        while (!got_sh && h->crypto_len[0] >= h->crypto_off[0] + 4) {
            const unsigned char *m = h->crypto_buf[0] + h->crypto_off[0];
            size_t mlen = ((size_t)m[1] << 16) | ((size_t)m[2] << 8) | m[3];
            if (h->crypto_len[0] < h->crypto_off[0] + 4 + mlen) break;
            if (m[0] != 2) { free(cert_der); return TLS13_EBADREC; }

            uint16_t suite = 0;
            unsigned char srv_pub[32], shared[32];
            if (parse_server_hello(m + 4, mlen, &suite, srv_pub) != 0) {
                free(cert_der);
                return TLS13_ENOKEYSHARE;
            }
            if (suite == 0x1301) {
                h->hash_alg = SC_SHA256; h->suite_alg = SC_AES128_GCM; h->hash_len = 32;
            } else if (suite == 0x1302) {
                h->hash_alg = SC_SHA384; h->suite_alg = SC_AES256_GCM; h->hash_len = 48;
            } else if (suite == 0x1303) {
                h->hash_alg = SC_SHA256; h->suite_alg = SC_CHACHA20_POLY1305; h->hash_len = 32;
            } else {
                free(cert_der);
                return TLS13_EBADSUITE;
            }
            if (sc_x25519(shared, xpriv, srv_pub) != 0) {
                free(cert_der);
                return REALITY_ECRYPTO;
            }
            sc_hash_init(&th, h->hash_alg);
            th_inited = 1;
            sc_hash_update(&th, h->ch_tx, h->ch_tx_len);
            sc_hash_update(&th, m, 4 + mlen);

            unsigned char sh_th[48], zeros[48] = {0}, early_sec[48], d_sec[48], empty_h[48];
            th_snapshot(&th, sh_th);
            sc_hash(h->hash_alg, NULL, 0, empty_h);
            sc_hkdf_extract(h->hash_alg, zeros, h->hash_len, zeros, h->hash_len, early_sec);
            quic_hkdf_label(h->hash_alg, early_sec, h->hash_len, "derived", empty_h, h->hash_len, d_sec, h->hash_len);
            sc_hkdf_extract(h->hash_alg, d_sec, h->hash_len, shared, 32, hs_secret);
            quic_hkdf_label(h->hash_alg, hs_secret, h->hash_len, "c hs traffic", sh_th, h->hash_len, c_hs_sec, h->hash_len);
            quic_hkdf_label(h->hash_alg, hs_secret, h->hash_len, "s hs traffic", sh_th, h->hash_len, s_hs_sec, h->hash_len);

            quic_level_setup(&h->tx_hs, h->hash_alg, h->suite_alg, c_hs_sec, h->hash_len);
            quic_level_setup(&h->rx_hs, h->hash_alg, h->suite_alg, s_hs_sec, h->hash_len);
            h->crypto_off[0] += 4 + mlen;
            got_sh = 1;
            h->ch_retx_due = 0;

            /* Re-parse any coalesced Handshake packet in the unmodified datagram copy */
            quic_process_datagram(h, dgram_copy, (size_t)r);
            if (h->proto_err) {
                free(cert_der);
                if (th_inited) sc_hash_free(&th);
                return h->proto_err;
            }
            if (h->rx_space[0].n_ranges > 0) {
                unsigned char ia[64];
                size_t ian = quic_build_ack_ranges(&h->rx_space[0], hy2_now_us(), ia, sizeof(ia));
                if (ian > 0) quic_send_long(h, 0, &h->tx_init, ia, ian, 1);
            }
        }

        /* Step B: Parse Handshake messages strictly in order:
         * EncryptedExtensions (8) -> Certificate (11) -> CertificateVerify (15) -> Finished (20) */
        while (got_sh && !got_fin && h->crypto_len[1] >= h->crypto_off[1] + 4) {
            const unsigned char *m = h->crypto_buf[1] + h->crypto_off[1];
            size_t mlen = ((size_t)m[1] << 16) | ((size_t)m[2] << 8) | m[3];
            if (h->crypto_len[1] < h->crypto_off[1] + 4 + mlen) break;
            uint8_t mtype = m[0];

            if (mtype == 8) { /* EncryptedExtensions */
                if (got_ee || got_cert || got_cv ||
                    parse_encrypted_extensions(h, m + 4, mlen) != 0) {
                    free(cert_der);
                    if (th_inited) sc_hash_free(&th);
                    return TLS13_EBADREC;
                }
                sc_hash_update(&th, m, 4 + mlen);
                got_ee = 1;
            } else if (mtype == 11) { /* Certificate */
                if (!got_ee || got_cert || got_cv || mlen < 4) {
                    free(cert_der);
                    if (th_inited) sc_hash_free(&th);
                    return TLS13_ECERT;
                }
                free(cert_der);
                cert_der = malloc(mlen);
                if (!cert_der) {
                    if (th_inited) sc_hash_free(&th);
                    return TR_EIO;
                }
                memcpy(cert_der, m + 4, mlen);
                cert_der_len = mlen;
                sc_hash_update(&th, m, 4 + mlen);
                th_snapshot(&th, cert_th);
                got_cert = 1;
            } else if (mtype == 15) { /* CertificateVerify */
                if (!got_ee || !got_cert || got_cv || mlen < 4 || !cert_der) {
                    free(cert_der);
                    if (th_inited) sc_hash_free(&th);
                    return TLS13_ECERT;
                }
                struct cert_policy pol = {
                    .pcs = n->pcs, .pks = n->pks, .vcn = n->vcn, .insecure = n->insecure
                };
                const char *vhost = (n->sni && n->sni[0]) ? n->sni : n->host;
                const struct cert_policy *pol_p = (pol.pcs || pol.pks || pol.vcn || pol.insecure) ? &pol : NULL;
                int vrc = cert_verify_server_ex(cert_der, cert_der_len, m + 4, mlen,
                                                cert_th, h->hash_len, vhost, tls_cert_roots(), pol_p);
                if (vrc != 0) {
                    free(cert_der);
                    if (th_inited) sc_hash_free(&th);
                    return vrc;
                }
                sc_hash_update(&th, m, 4 + mlen);
                got_cv = 1;
            } else if (mtype == 20) { /* Server Finished */
                if (!got_ee || !got_cert || !got_cv) {
                    free(cert_der);
                    if (th_inited) sc_hash_free(&th);
                    return (!got_cert || !got_cv) ? TLS13_ECERT : TLS13_EBADREC;
                }
                if (mlen != h->hash_len) {
                    free(cert_der);
                    if (th_inited) sc_hash_free(&th);
                    return TLS13_EFINISHED;
                }
                unsigned char fin_th[48], fk[48], exp_vd[48];
                th_snapshot(&th, fin_th);
                quic_hkdf_label(h->hash_alg, s_hs_sec, h->hash_len, "finished", NULL, 0, fk, h->hash_len);
                sc_hmac(h->hash_alg, fk, h->hash_len, fin_th, h->hash_len, exp_vd);
                if (!ct_equal(exp_vd, m + 4, h->hash_len)) {
                    free(cert_der);
                    if (th_inited) sc_hash_free(&th);
                    return TLS13_EFINISHED;
                }
                sc_hash_update(&th, m, 4 + mlen);

                /* Derive 1-RTT Application Traffic Secrets */
                unsigned char sf_th[48], zeros[48] = {0}, d_sec[48], master[48], empty_h[48];
                unsigned char c_ap_sec[48], s_ap_sec[48];
                th_snapshot(&th, sf_th);
                sc_hash(h->hash_alg, NULL, 0, empty_h);
                quic_hkdf_label(h->hash_alg, hs_secret, h->hash_len, "derived", empty_h, h->hash_len, d_sec, h->hash_len);
                sc_hkdf_extract(h->hash_alg, d_sec, h->hash_len, zeros, h->hash_len, master);
                quic_hkdf_label(h->hash_alg, master, h->hash_len, "c ap traffic", sf_th, h->hash_len, c_ap_sec, h->hash_len);
                quic_hkdf_label(h->hash_alg, master, h->hash_len, "s ap traffic", sf_th, h->hash_len, s_ap_sec, h->hash_len);

                quic_level_setup(&h->tx_app, h->hash_alg, h->suite_alg, c_ap_sec, h->hash_len);
                quic_level_setup(&h->rx_app, h->hash_alg, h->suite_alg, s_ap_sec, h->hash_len);
                memcpy(h->c_ap_sec, c_ap_sec, h->hash_len);
                memcpy(h->s_ap_sec, s_ap_sec, h->hash_len);
                h->key_phase = 0;

                /* Build Client Finished & send Initial ACK + Handshake ACK & Client Finished */
                if (h->rx_space[0].n_ranges > 0) {
                    unsigned char ia[64];
                    size_t ian = quic_build_ack_ranges(&h->rx_space[0], hy2_now_us(), ia, sizeof(ia));
                    if (ian > 0) quic_send_long(h, 0, &h->tx_init, ia, ian, 0);
                }

                unsigned char c_fk[48], c_vd[48];
                quic_hkdf_label(h->hash_alg, c_hs_sec, h->hash_len, "finished", NULL, 0, c_fk, h->hash_len);
                sc_hmac(h->hash_alg, c_fk, h->hash_len, sf_th, h->hash_len, c_vd);

                h->fin_tx[0] = 20; /* Finished */
                h->fin_tx[1] = 0;
                h->fin_tx[2] = 0;
                h->fin_tx[3] = (unsigned char)h->hash_len;
                memcpy(h->fin_tx + 4, c_vd, h->hash_len);
                h->fin_tx_len = 4 + h->hash_len;
                h->fin_retx_due = 1;
                h->rx_space[1].ack_needed = 1;
                hy2_flush_tx(h, hy2_now_us());

                got_fin = 1;
                quic_process_datagram(h, dgram_copy2, (size_t)r);
                hy2_send_auth(h, n);
            } else {
                free(cert_der);
                if (th_inited) sc_hash_free(&th);
                return TLS13_EBADREC;
            }
            h->crypto_off[1] += 4 + mlen;
        }
        hy2_flush_tx(h, hy2_now_us());
    }

    quic_ack_all_before_app(h);
    hy2_flush_tx(h, hy2_now_us());

    free(cert_der);
    if (th_inited) sc_hash_free(&th);
    free(h->crypto_buf[0]); h->crypto_buf[0] = NULL;
    free(h->crypto_buf[1]); h->crypto_buf[1] = NULL;
    free(h->crypto_seen[0]); h->crypto_seen[0] = NULL;
    free(h->crypto_seen[1]); h->crypto_seen[1] = NULL;

    /* Put UDP socket into non-blocking mode for the event loop */
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    return 0;
}

/* Parse SOCKS5 target address [atyp][addr][port] into "host:port" */
static size_t parse_socks_target(const unsigned char *d, size_t n, int *is_udp, char *out, size_t cap) {
    if (!n) return 0;
    *is_udp = (d[0] & 0x80) != 0;
    uint8_t atyp = d[0] & 0x7Fu;
    if (atyp == 0x01 && n >= 7) {
        uint16_t port = (uint16_t)(((uint16_t)d[5] << 8) | d[6]);
        snprintf(out, cap, "%u.%u.%u.%u:%u", d[1], d[2], d[3], d[4], port);
        return 7;
    }
    if (atyp == 0x03 && n >= 2 && n >= (size_t)4 + d[1]) {
        size_t hlen = d[1];
        uint16_t port = (uint16_t)(((uint16_t)d[2 + hlen] << 8) | d[3 + hlen]);
        snprintf(out, cap, "%.*s:%u", (int)hlen, (const char *)(d + 2), port);
        return 4 + hlen;
    }
    if (atyp == 0x04 && n >= 19) {
        uint16_t port = (uint16_t)(((uint16_t)d[17] << 8) | d[18]);
        snprintf(out, cap, "[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]:%u",
                 d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8],
                 d[9], d[10], d[11], d[12], d[13], d[14], d[15], d[16], port);
        return 19;
    }
    return 0;
}

static int hy2_queue_stream4(struct hy2_ctx *h, const unsigned char *d, size_t n) {
    size_t done = 0;
    int64_t deadline = hy2_now_ms() + (int64_t)(h->timeout_s > 0 ? h->timeout_s : 8) * 1000;
    while (done < n) {
        if (h->peer_closed || h->proto_err) return TR_ECLOSED;

        uint64_t in_buf = h->s4_write_off - h->s4_una_off;
        size_t avail = (in_buf < HY2_TX_CAP) ? (size_t)(HY2_TX_CAP - in_buf) : 0;
        if (avail > 0) {
            size_t take = (n - done < avail) ? (n - done) : avail;
            for (size_t k = 0; k < take; k++)
                h->s4_tx_buf[(h->s4_write_off + k) & (HY2_TX_CAP - 1)] = d[done + k];
            h->s4_write_off += take;
            h->s4_tx_off = h->s4_write_off;
            done += take;
            hy2_tick(h);
            if (h->peer_closed || h->proto_err) return TR_ECLOSED;
            if (done == n) break;
        } else {
            hy2_tick(h);
            if (h->peer_closed || h->proto_err) return TR_ECLOSED;
        }

        if (hy2_now_ms() >= deadline)
            return TR_EIO;
        struct pollfd pfd = { .fd = h->fd, .events = POLLIN, .revents = 0 };
        poll(&pfd, 1, 10);
    }
    return 0;
}

static int hy2_send_dgram(struct hy2_ctx *h, const unsigned char *d, size_t n) {
    if (!n || n > 65535) return 0;
    size_t alen = strlen(h->udp_addr);
    if (alen > 260) return TR_EIO;
    size_t max_slice = 1100;
    size_t frag_cnt = (n + max_slice - 1) / max_slice;
    if (frag_cnt == 0 || frag_cnt > 32) return TR_EIO;

    uint16_t pid = ++h->udp_pkt_id;
    for (size_t fid = 0; fid < frag_cnt; fid++) {
        size_t off = fid * max_slice;
        size_t slen = (n - off > max_slice) ? max_slice : (n - off);
        unsigned char frame[1500];
        size_t fo = 0;
        if (h->rx_space[2].ack_needed && h->rx_space[2].n_ranges > 0)
            fo += quic_build_ack_ranges(&h->rx_space[2], hy2_now_us(), frame + fo, 180);
        frame[fo++] = 0x31; /* QUIC DATAGRAM with length */
        size_t len_pos = fo;
        fo += 2; /* reserve 2-byte varint for length */
        size_t d_start = fo;
        frame[fo++] = (unsigned char)(h->udp_sid >> 24);
        frame[fo++] = (unsigned char)(h->udp_sid >> 16);
        frame[fo++] = (unsigned char)(h->udp_sid >> 8);
        frame[fo++] = (unsigned char)h->udp_sid;
        frame[fo++] = (unsigned char)(pid >> 8);
        frame[fo++] = (unsigned char)pid;
        frame[fo++] = (unsigned char)fid;
        frame[fo++] = (unsigned char)frag_cnt;
        fo += quic_put_varint(frame + fo, alen);
        memcpy(frame + fo, h->udp_addr, alen);
        fo += alen;
        memcpy(frame + fo, d + off, slen);
        fo += slen;
        size_t pay_len = fo - d_start;
        frame[len_pos]     = (unsigned char)(0x40u | (pay_len >> 8));
        frame[len_pos + 1] = (unsigned char)pay_len;
        int rc = quic_send_1rtt_ex(h, frame, fo, 1, 0, 0, 0, 0, 0, 0, NULL);
        if (rc) return rc;
    }
    hy2_tick(h);
    return 0;
}

static int hy2_write(struct transport *t, const unsigned char *d, size_t n) {
    struct hy2_ctx *h = t->hy2;
    if (!h) return TR_EIO;

    if (!h->addr_sent) {
        int is_udp = 0;
        char target[280];
        size_t alen = parse_socks_target(d, n, &is_udp, target, sizeof(target));
        if (!alen) return TR_EIO;
        h->addr_sent = 1;
        h->is_udp = is_udp;
        d += alen;
        n -= alen;

        if (is_udp) {
            snprintf(h->udp_addr, sizeof(h->udp_addr), "%s", target);
            xc_random((unsigned char *)&h->udp_sid, 4);
            if (!h->udp_sid) h->udp_sid = 1;
            return n ? hy2_send_dgram(h, d, n) : 0;
        }

        /* Build Hysteria2 TCP request on Stream 4: [varint 0x401][varint addr_len][addr][varint pad_len=0] */
        unsigned char req[512];
        size_t ro = 0;
        size_t tlen = strlen(target);
        ro += quic_put_varint(req + ro, 0x401);
        ro += quic_put_varint(req + ro, tlen);
        memcpy(req + ro, target, tlen);
        ro += tlen;
        req[ro++] = 0x00; /* pad_len = 0 */

        int rc = hy2_queue_stream4(h, req, ro);
        if (rc) return rc;
        if (n > 0)
            return hy2_queue_stream4(h, d, n);
        return 0;
    }

    if (h->is_udp)
        return hy2_send_dgram(h, d, n);
    return hy2_queue_stream4(h, d, n);
}

static int hy2_read(struct transport *t, unsigned char *d, size_t cap, size_t *got) {
    *got = 0;
    struct hy2_ctx *h = t->hy2;
    if (!h || !cap) return 0;

    hy2_tick(h);

    for (;;) {
        if (h->rx_len > 0) {
            size_t k = h->rx_len < cap ? h->rx_len : cap;
            memcpy(d, h->rx_buf + h->rx_off, k);
            h->rx_off += k;
            h->rx_len -= k;
            if (!h->rx_len) h->rx_off = 0;
            *got = k;

            if (!h->is_udp) {
                h->s4_rx_consumed += k;
                uint64_t step = h->local_s4_win / 2;
                if (step > 16384) step = 16384;
                if (step < 1024) step = 1024;
                if (h->s4_rx_consumed - h->s4_last_win_sent >= step ||
                    h->local_s4_max_data - h->s4_rx_consumed < h->local_s4_win / 2) {
                    h->s4_last_win_sent = h->s4_rx_consumed;
                    quic_advance_local_rx_win(h, h->s4_rx_consumed);
                    hy2_flush_tx(h, hy2_now_us());
                }
            }
            return 0;
        }
        if (h->peer_closed || h->proto_err) return TR_ECLOSED;

        unsigned char dgram[2048];
        ssize_t r = hy2_udp_recv(h, dgram, sizeof(dgram), MSG_DONTWAIT);
        if (r <= 0) {
            hy2_flush_tx(h, hy2_now_us());
            if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return 0;
            return r == 0 ? 0 : TR_EIO;
        }
        quic_process_datagram(h, dgram, (size_t)r);
        hy2_flush_tx(h, hy2_now_us());
    }
}

static int hy2_pending(const struct transport *t) {
    if (!t->hy2) return 0;
    if (t->hy2->rx_len > 0 || t->hy2->peer_closed || t->hy2->proto_err) return 1;
    hy2_tick(t->hy2);
    return (t->hy2->rx_len > 0 || t->hy2->peer_closed || t->hy2->proto_err);
}

static void hy2_close(struct transport *t) {
    struct hy2_ctx *h = t->hy2;
    if (!h) return;
    quic_level_free(&h->tx_init);
    quic_level_free(&h->rx_init);
    quic_level_free(&h->tx_hs);
    quic_level_free(&h->rx_hs);
    quic_level_free(&h->tx_app);
    quic_level_free(&h->rx_app);
    if (h->have_prev_rx) sc_aead_free(&h->prev_rx_aead);
    for (int i = 0; i < 64; i++) free(h->ooo[i].data);
    for (int i = 0; i < 4; i++) hy2_udp_reasm_free_slot(&h->udp_reasm[i]);
    free(h->crypto_buf[0]);
    free(h->crypto_buf[1]);
    free(h->crypto_seen[0]);
    free(h->crypto_seen[1]);
    free(h->s4_tx_buf);
    free(h->rx_buf);
    free(h);
    t->hy2 = NULL;
}

static long hy2_room(struct transport *t) {
    struct hy2_ctx *h = t->hy2;
    if (!h) return 0;
    hy2_tick(h);
    if (h->peer_closed || h->proto_err) return 0;
    if (h->is_udp) return 65535;

    uint64_t in_buf = h->s4_write_off - h->s4_una_off;
    uint64_t reserve = h->addr_sent ? 0 : 300;
    uint64_t buf_room = (in_buf + reserve < HY2_TX_CAP) ? (HY2_TX_CAP - in_buf - reserve) : 0;

    uint64_t s4_fc = (h->peer_s4_max_data > h->s4_write_off + reserve)
                         ? (h->peer_s4_max_data - h->s4_write_off - reserve) : 0;
    uint64_t conn_used = h->s0_tx_len + h->s2_tx_len + h->s4_write_off + reserve;
    uint64_t conn_fc = (h->peer_max_data > conn_used)
                           ? (h->peer_max_data - conn_used) : 0;
    uint64_t fc_room = s4_fc < conn_fc ? s4_fc : conn_fc;

    uint64_t room = buf_room < fc_room ? buf_room : fc_room;
    if (room > 262144) room = 262144;
    return (long)room;
}

const struct transport_ops tr_hy2 = {
    .name = "quic", .alpn = "h3", .zc = 0,
    .open = hy2_open, .write = hy2_write, .read = hy2_read,
    .moved = NULL, .close = hy2_close, .pending = hy2_pending, .busy = NULL, .room = hy2_room,
};
