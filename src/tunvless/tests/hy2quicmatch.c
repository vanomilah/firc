/* Regression tests for Hysteria2 / QUIC (trhy2.c) audit fixes:
 *   1. hy2_flush_tx bounds ACK ranges and never overflows Initial/Handshake frame buffers.
 *   2. ack_delay_raw shift avoids signed 64-bit UB under extreme peer values.
 *   3. hy2_on_datagram drops mismatched UDP session_ids.
 *   4. parse_encrypted_extensions enforces QUIC TPs (0x0039) + ALPN "h3" (0x0010).
 *   5. hy2_pending surfaces peer_closed and proto_err.
 */
#define _GNU_SOURCE
#include "unit.h"
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../src/proto/transport/trhy2.c"

int main(void) {
    int sv[2] = {-1, -1};
    check("socketpair created", 0, socketpair(AF_UNIX, SOCK_DGRAM, 0, sv));

    struct hy2_ctx *h = calloc(1, sizeof(*h));
    check("hy2_ctx alloc", 1, h != NULL);
    h->fd = sv[0];
    h->is_udp = 1;
    h->udp_sid = 0x11223344u;
    h->peer_ack_delay_exp = 20;
    h->peer_max_ack_delay_us = 25000;

    unsigned char zkey[32] = {0};
    check("tx_init level derive", 0, quic_level_setup(&h->tx_init, SC_SHA256, SC_AES128_GCM, zkey, 32));
    check("tx_hs level derive", 0, quic_level_setup(&h->tx_hs, SC_SHA256, SC_AES128_GCM, zkey, 32));

    /* 1. Populate all 32 fragmented PN ranges + large ch_tx & fin_tx retx simultaneously */
    for (size_t i = 0; i < QUIC_MAX_ACK_RANGES; i++) {
        uint64_t pn = (uint64_t)(QUIC_MAX_ACK_RANGES - i) * 100000ULL;
        h->rx_space[0].ranges[i].low = pn;
        h->rx_space[0].ranges[i].high = pn + 1;
        h->rx_space[1].ranges[i].low = pn;
        h->rx_space[1].ranges[i].high = pn + 1;
    }
    h->rx_space[0].n_ranges = QUIC_MAX_ACK_RANGES;
    h->rx_space[0].ack_needed = 1;
    h->rx_space[1].n_ranges = QUIC_MAX_ACK_RANGES;
    h->rx_space[1].ack_needed = 1;

    memset(h->ch_tx, 0xAA, sizeof(h->ch_tx));
    h->ch_tx_len = sizeof(h->ch_tx); /* 600 bytes */
    h->ch_retx_due = 1;

    memset(h->fin_tx, 0xBB, sizeof(h->fin_tx));
    h->fin_tx_len = sizeof(h->fin_tx); /* 64 bytes */
    h->fin_retx_due = 1;

    check("hy2_flush_tx safe with max ACK ranges + full ch_tx/fin_tx", 0, hy2_flush_tx(h, 1000000));
    check("ch_retx_due cleared", 0, h->ch_retx_due);
    check("fin_retx_due cleared", 0, h->fin_retx_due);

    /* 2. Extreme ack_delay_raw with peer_ack_delay_exp=20 triggers no UBSan shift UB */
    h->sent_pkts[0].in_use = 1;
    h->sent_pkts[0].level = 2;
    h->sent_pkts[0].pn = 5;
    h->sent_pkts[0].ack_eliciting = 1;
    h->sent_pkts[0].in_flight = 1;
    h->sent_pkts[0].bytes = 1200;
    h->sent_pkts[0].sent_us = 100000;
    h->bytes_in_flight = 1200;
    unsigned char ack_pkt[64];
    size_t ao = 0;
    ack_pkt[ao++] = 0x02;
    ao += quic_put_varint(ack_pkt + ao, 5);
    ao += quic_put_varint(ack_pkt + ao, 0x3ffffffffffffffULL);
    ao += quic_put_varint(ack_pkt + ao, 0);
    ao += quic_put_varint(ack_pkt + ao, 0);
    int ack_el = 0;
    check("quic_parse_frames extreme ack_delay safe", 0, quic_parse_frames(h, 2, ack_pkt, ao, &ack_el));

    /* 3. UDP datagram with wrong session_id is dropped */
    unsigned char bad_dg[] = {0x00, 0x99, 0x88, 0x77, 0x66, 0x00, 0x01, 0x00, 0x01, 0x00, 'x'};
    hy2_on_datagram(h, bad_dg, sizeof(bad_dg));
    check("wrong udp_sid dropped", 0, (long)h->rx_len);

    unsigned char good_dg[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x00, 0x02, 0x00, 0x01, 0x00, 'o', 'k'};
    hy2_on_datagram(h, good_dg, sizeof(good_dg));
    check("matching udp_sid accepted", 4, (long)h->rx_len);

    /* 4. parse_encrypted_extensions rejects missing ALPN / non-h3 ALPN / accepts valid h3 + TP */
    const unsigned char ee_no_alpn[] = {0x00, 0x04, 0x00, 0x39, 0x00, 0x00};
    check("EE without ALPN rejected", -1, parse_encrypted_extensions(h, ee_no_alpn, sizeof(ee_no_alpn)));

    const unsigned char ee_bad_alpn[] = {
        0x00, 0x0d,
        0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '2',
        0x00, 0x39, 0x00, 0x00
    };
    check("EE with h2 ALPN rejected", -1, parse_encrypted_extensions(h, ee_bad_alpn, sizeof(ee_bad_alpn)));

    const unsigned char ee_good[] = {
        0x00, 0x0d,
        0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '3',
        0x00, 0x39, 0x00, 0x00
    };
    check("EE with h3 ALPN + TP accepted", 0, parse_encrypted_extensions(h, ee_good, sizeof(ee_good)));

    /* 5. hy2_pending reflects peer_closed / proto_err */
    h->rx_len = 0;
    struct transport tr = {.hy2 = h};
    check("hy2_pending false when idle", 0, hy2_pending(&tr));
    h->peer_closed = 1;
    check("hy2_pending true on peer_closed", 1, hy2_pending(&tr));
    h->peer_closed = 0;
    h->proto_err = 1;
    check("hy2_pending true on proto_err", 1, hy2_pending(&tr));

    hy2_close(&tr);
    close(sv[0]);
    close(sv[1]);
    return unit_done("hy2quicmatch");
}
