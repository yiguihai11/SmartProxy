#ifndef SMARTPROXY_LWIP_ADAPTER_H
#define SMARTPROXY_LWIP_ADAPTER_H

#include <stdint.h>
#include "lwip/netif.h"
#include "lwip/tcp.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*sp_lwip_packet_output_fn)(const uint8_t *data, uint32_t len, uint64_t ctx_id);

typedef void (*sp_lwip_tcp_accept_fn)(
    uint64_t conn_id,
    int is_ipv6,
    const void *src_ip, uint16_t src_port,
    const void *dst_ip, uint16_t dst_port,
    uint64_t ctx_id
);

typedef void (*sp_lwip_tcp_recv_fn)(
    uint64_t conn_id,
    const uint8_t *data, uint16_t len,
    uint64_t ctx_id
);

typedef void (*sp_lwip_tcp_sent_fn)(
    uint64_t conn_id,
    uint16_t len,
    uint64_t ctx_id
);

typedef void (*sp_lwip_tcp_err_fn)(
    uint64_t conn_id,
    int err,
    uint64_t ctx_id
);

typedef void (*sp_lwip_udp_recv_fn)(
    uint64_t conn_id,
    int is_ipv6,
    const void *src_ip, uint16_t src_port,
    const void *dst_ip, uint16_t dst_port,
    const uint8_t *data, uint16_t len,
    uint64_t ctx_id
);

struct sp_tcp_conn;
struct sp_udp_conn;

struct sp_lwip {
    struct netif netif;
    struct tcp_pcb *tcp_listener;
    struct udp_pcb *udp_listener;

    sp_lwip_packet_output_fn packet_output;
    sp_lwip_tcp_accept_fn tcp_accept;
    sp_lwip_tcp_recv_fn tcp_recv;
    sp_lwip_tcp_sent_fn tcp_sent;
    sp_lwip_tcp_err_fn tcp_err;
    sp_lwip_udp_recv_fn udp_recv;

    uint64_t ctx_id;
    uint64_t next_conn_id;
    struct sp_tcp_conn *conn_buckets[256];
    struct sp_udp_conn *udp_conn_buckets[256];
    uint8_t output_buf[65536];
};

struct sp_lwip *sp_lwip_new(void);
void sp_lwip_destroy(struct sp_lwip *lw);
void sp_lwip_set_callbacks(
    struct sp_lwip *lw,
    sp_lwip_packet_output_fn packet_output,
    sp_lwip_tcp_accept_fn tcp_accept,
    sp_lwip_tcp_recv_fn tcp_recv,
    sp_lwip_tcp_sent_fn tcp_sent,
    sp_lwip_tcp_err_fn tcp_err,
    sp_lwip_udp_recv_fn udp_recv,
    uint64_t ctx_id
);

void sp_set_ip4_addr(ip4_addr_t *a, uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3);

int sp_lwip_init(struct sp_lwip *lw, const ip4_addr_t *ip, const ip4_addr_t *mask, const ip4_addr_t *gw);
void sp_lwip_set_mtu(struct sp_lwip *lw, uint16_t mtu);
void sp_lwip_free(struct sp_lwip *lw);
int sp_lwip_input(struct sp_lwip *lw, const void *data, uint32_t len);
void sp_lwip_timers(void);

int sp_lwip_tcp_write(struct sp_lwip *lw, uint64_t conn_id, const void *data, uint32_t len);
int sp_lwip_tcp_recved(struct sp_lwip *lw, uint64_t conn_id, uint32_t len);
int sp_lwip_tcp_close(struct sp_lwip *lw, uint64_t conn_id);
int sp_lwip_tcp_abort(struct sp_lwip *lw, uint64_t conn_id);
int sp_lwip_tcp_sndbuf(struct sp_lwip *lw, uint64_t conn_id);

int sp_lwip_udp_send(struct sp_lwip *lw, uint64_t conn_id, int is_ipv6, const void *src_ip, uint16_t src_port, const void *data, uint32_t len);
int sp_lwip_udp_close(struct sp_lwip *lw, uint64_t conn_id);

#ifdef __cplusplus
}
#endif
#endif
