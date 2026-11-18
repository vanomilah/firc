/* Regression tests for FiniteProto (trfp.c) HTTP/1.1 framing, 32-bit offset guard,
 * and IPv6 authority bracketing.
 */
#define _GNU_SOURCE
#include "unit.h"
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../src/proto/transport/trfp.c"

static size_t build_fp_body(uint8_t *out, uint64_t down_start, uint64_t down_end,
                            const void *pay, uint32_t plen) {
    memset(out, 0, FP_RESP_HEADER_SIZE);
    memcpy(out, FP_PROTO_MAGIC, 4);
    out[4] = FP_STATUS_OK;
    put_be64(out + 30, down_start);
    put_be64(out + 38, down_end);
    put_be32(out + 54, plen);
    if (plen > 0) memcpy(out + FP_RESP_HEADER_SIZE, pay, plen);
    return FP_RESP_HEADER_SIZE + plen;
}

static int parse_http_wire(const char *wire, size_t wire_len, fp_parsed_resp_t *out_resp,
                           uint8_t *down_buf, size_t down_cap) {
    int sv[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return -99;
    ssize_t wr = write(sv[1], wire, wire_len);
    shutdown(sv[1], SHUT_WR);
    struct tr_link l;
    memset(&l, 0, sizeof(l));
    l.fd = sv[0];
    l.plain = 1;
    struct fp_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    char hdr[16];
    snprintf(hdr, sizeof(hdr), "test");
    int rc = (wr == (ssize_t)wire_len)
                 ? fp_rpc_once(&ctx, &l, "POST", false, "001122",
                               (const uint8_t *)hdr, 4, "test", out_resp, down_buf, down_cap)
                 : -98;
    close(sv[0]);
    close(sv[1]);
    return rc;
}

int main(void) {
    uint8_t fp_body[FP_RESP_HEADER_SIZE + 16];
    size_t blen = build_fp_body(fp_body, 0, 5, "hello", 5);
    fp_parsed_resp_t resp;
    uint8_t down[128];

    /* 1. Multi-line HTTP/1.1 chunked trailers succeed cleanly without leaving trailing bytes */
    char wire_ok[1024];
    int n0 = snprintf(wire_ok, sizeof(wire_ok),
                      "HTTP/1.1 200 OK\r\n"
                      "Transfer-Encoding: chunked\r\n"
                      "X-FP-Version: fp/1\r\n\r\n"
                      "%zx\r\n",
                      blen);
    memcpy(wire_ok + n0, fp_body, blen);
    const char *tail = "\r\n0\r\nX-Trailer-1: a\r\nX-Trailer-2: b\r\n\r\n";
    memcpy(wire_ok + n0 + blen, tail, strlen(tail));
    size_t tot_ok = (size_t)n0 + blen + strlen(tail);
    int rc_ok = parse_http_wire(wire_ok, tot_ok, &resp, down, sizeof(down));
    check("chunked multi-line trailers accepted (keep-alive)", 0, rc_ok);
    check("chunked payload_len decoded", 5, (long)resp.payload_len);
    check_mem("chunked payload matches", "hello", down, 5);

    /* 2. Trailing leftover bytes after Content-Length force conn_close=1 (keep-alive reset) */
    char wire_extra[1024];
    int n1 = snprintf(wire_extra, sizeof(wire_extra),
                      "HTTP/1.1 200 OK\r\n"
                      "Content-Length: %zu\r\n"
                      "X-FP-Version: fp/1\r\n\r\n",
                      blen);
    memcpy(wire_extra + n1, fp_body, blen);
    memcpy(wire_extra + n1 + blen, "GARBAGE", 7);
    int rc_extra = parse_http_wire(wire_extra, (size_t)n1 + blen + 7, &resp, down, sizeof(down));
    check("extra trailing bytes force conn_close=1", 1, rc_extra);

    /* 3. Non-empty chunk delimiter rejected */
    char wire_bad_delim[1024];
    int n2 = snprintf(wire_bad_delim, sizeof(wire_bad_delim),
                      "HTTP/1.1 200 OK\r\n"
                      "Transfer-Encoding: chunked\r\n"
                      "X-FP-Version: fp/1\r\n\r\n"
                      "%zx\r\n",
                      blen);
    memcpy(wire_bad_delim + n2, fp_body, blen);
    const char *bad_tail = "BADCHUNKDELIM\r\n0\r\n\r\n";
    memcpy(wire_bad_delim + n2 + blen, bad_tail, strlen(bad_tail));
    int rc_bad_delim = parse_http_wire(wire_bad_delim, (size_t)n2 + blen + strlen(bad_tail), &resp, down, sizeof(down));
    check("corrupt chunk delimiter rejected", -1, rc_bad_delim);

    /* 4. Non-numeric Content-Length suffix rejected */
    char wire_bad_cl[1024];
    int n3 = snprintf(wire_bad_cl, sizeof(wire_bad_cl),
                      "HTTP/1.1 200 OK\r\n"
                      "Content-Length: %zubogus\r\n"
                      "X-FP-Version: fp/1\r\n\r\n",
                      blen);
    memcpy(wire_bad_cl + n3, fp_body, blen);
    int rc_bad_cl = parse_http_wire(wire_bad_cl, (size_t)n3 + blen, &resp, down, sizeof(down));
    check("malformed Content-Length rejected", -1, rc_bad_cl);

    /* 5. tr_read_http_line rejects overlong header line instead of truncating */
    char overlong[64];
    memset(overlong, 'A', sizeof(overlong));
    overlong[63] = '\n';
    int sv[2] = {-1, -1};
    check("line socketpair created", 0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
    ssize_t w2 = write(sv[1], overlong, sizeof(overlong));
    shutdown(sv[1], SHUT_WR);
    struct tr_link l2;
    memset(&l2, 0, sizeof(l2));
    l2.fd = sv[0];
    l2.plain = 1;
    struct tr_reader rd;
    memset(&rd, 0, sizeof(rd));
    rd.l = &l2;
    char small_buf[16];
    check("overlong HTTP line returns -1", -1, (w2 == (ssize_t)sizeof(overlong)) ? tr_read_http_line(&rd, small_buf, sizeof(small_buf), 1000) : -99);
    close(sv[0]);
    close(sv[1]);

    return unit_done("fpmatch");
}
