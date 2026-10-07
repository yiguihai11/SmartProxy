#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "lwip_adapter.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "lwip/init.h"
#include "lwip/sys.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/timeouts.h"
#include "lwip/priv/tcp_priv.h"

struct sp_tcp_conn {
    struct sp_lwip *lw;
    struct tcp_pcb *pcb;
    uint64_t id;
    struct sp_tcp_conn *next;
};

static struct sp_tcp_conn *sp_find_conn(struct sp_lwip *lw, uint64_t id) {
    if (!lw || !id) return NULL;
    uint32_t b = (uint32_t)(id & SP_CONN_BUCKET_MASK);
    struct sp_tcp_conn *c = lw->conn_buckets[b];
    while (c) {
        if (c->id == id) return c;
        c = c->next;
    }
    return NULL;
}

static void sp_add_conn(struct sp_lwip *lw, struct sp_tcp_conn *conn) {
    uint32_t b = (uint32_t)(conn->id & SP_CONN_BUCKET_MASK);
    conn->next = lw->conn_buckets[b];
    lw->conn_buckets[b] = conn;
}

static void sp_remove_conn(struct sp_lwip *lw, struct sp_tcp_conn *conn) {
    uint32_t b = (uint32_t)(conn->id & SP_CONN_BUCKET_MASK);
    struct sp_tcp_conn **curr = &lw->conn_buckets[b];
    while (*curr) {
        if (*curr == conn) {
            *curr = conn->next;
            conn->next = NULL;
            return;
        }
        curr = &(*curr)->next;
    }
}

struct sp_udp_conn {
    struct sp_lwip *lw;
    struct udp_pcb *pcb;
    uint64_t id;
    struct sp_udp_conn *next;
};

static struct sp_udp_conn *sp_find_udp_conn(struct sp_lwip *lw, uint64_t id) {
    if (!lw || !id) return NULL;
    uint32_t b = (uint32_t)(id & SP_CONN_BUCKET_MASK);
    struct sp_udp_conn *c = lw->udp_conn_buckets[b];
    while (c) {
        if (c->id == id) return c;
        c = c->next;
    }
    return NULL;
}

static void sp_add_udp_conn(struct sp_lwip *lw, struct sp_udp_conn *conn) {
    uint32_t b = (uint32_t)(conn->id & SP_CONN_BUCKET_MASK);
    conn->next = lw->udp_conn_buckets[b];
    lw->udp_conn_buckets[b] = conn;
}

static void sp_remove_udp_conn(struct sp_lwip *lw, struct sp_udp_conn *conn) {
    uint32_t b = (uint32_t)(conn->id & SP_CONN_BUCKET_MASK);
    struct sp_udp_conn **curr = &lw->udp_conn_buckets[b];
    while (*curr) {
        if (*curr == conn) {
            *curr = conn->next;
            conn->next = NULL;
            return;
        }
        curr = &(*curr)->next;
    }
}

static err_t sp_output_pbuf(struct netif *n, struct pbuf *p) {
    struct sp_lwip *lw = n ? (struct sp_lwip *)n->state : NULL;
    if (!lw || !lw->packet_output) return ERR_IF;
    if (p->next == NULL) {
        lw->packet_output((const uint8_t *)p->payload, p->tot_len, lw->ctx_id);
        return ERR_OK;
    }
    u16_t copied = pbuf_copy_partial(p, lw->output_buf, (u16_t)p->tot_len, 0);
    if (copied != p->tot_len) return ERR_BUF;
    lw->packet_output(lw->output_buf, copied, lw->ctx_id);
    return ERR_OK;
}

static err_t sp_output(struct netif *n, struct pbuf *p, const ip4_addr_t *dst) {
    (void)dst;
    return sp_output_pbuf(n, p);
}

#if LWIP_IPV6
static err_t sp_output_ip6(struct netif *n, struct pbuf *p, const ip6_addr_t *dst) {
    (void)dst;
    return sp_output_pbuf(n, p);
}
#endif

static err_t sp_netif_init(struct netif *n) {
    n->name[0] = 's'; n->name[1] = 'p';
    n->mtu = 1500; n->flags = NETIF_FLAG_UP;
    n->output = sp_output;
#if LWIP_IPV6
    n->output_ip6 = sp_output_ip6;
#endif
    return ERR_OK;
}

static err_t sp_tcp_recv_cb(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    struct sp_tcp_conn *conn = (struct sp_tcp_conn *)arg;
    (void)pcb;
    if (!conn || !conn->lw) {
        if (p) pbuf_free(p);
        return ERR_ABRT;
    }

    struct sp_lwip *lw = conn->lw;
    if (!p) {
        // Remote sent FIN (EOF)
        if (lw->tcp_recv) {
            lw->tcp_recv(conn->id, NULL, 0, lw->ctx_id);
        }
        return ERR_OK;
    }

    if (err != ERR_OK) {
        pbuf_free(p);
        if (lw->tcp_err) {
            lw->tcp_err(conn->id, (int)err, lw->ctx_id);
        }
        return err;
    }

    if (lw->tcp_recv) {
        if (p->next == NULL) {
            lw->tcp_recv(conn->id, (const uint8_t *)p->payload, p->len, lw->ctx_id);
        } else {
            /*
             * A chained TCP pbuf would otherwise cross the cgo boundary once
             * per fragment. Aggregate it while the callback is synchronous so
             * Go pays one callback and one receive-buffer append per segment.
             */
            u16_t copied = pbuf_copy_partial(p, lw->output_buf, p->tot_len, 0);
            if (copied == p->tot_len) {
                lw->tcp_recv(conn->id, lw->output_buf, copied, lw->ctx_id);
            }
        }
    }
    pbuf_free(p);
    return ERR_OK;
}

static err_t sp_tcp_sent_cb(void *arg, struct tcp_pcb *pcb, u16_t len) {
    struct sp_tcp_conn *conn = (struct sp_tcp_conn *)arg;
    (void)pcb;
    if (conn && conn->lw && conn->lw->tcp_sent) {
        conn->lw->tcp_sent(conn->id, len, conn->lw->ctx_id);
    }
    return ERR_OK;
}

static void sp_tcp_err_cb(void *arg, err_t err) {
    struct sp_tcp_conn *conn = (struct sp_tcp_conn *)arg;
    if (!conn) return;
    struct sp_lwip *lw = conn->lw;
    uint64_t id = conn->id;

    conn->pcb = NULL; // PCB already deallocated by lwIP
    sp_remove_conn(lw, conn);
    free(conn);

    if (lw && lw->tcp_err) {
        lw->tcp_err(id, (int)err, lw->ctx_id);
    }
}

static err_t sp_tcp_accept_cb(void *arg, struct tcp_pcb *newpcb, err_t err) {
    struct sp_lwip *lw = (struct sp_lwip *)arg;
    if (err != ERR_OK || !lw || !newpcb) {
        return err != ERR_OK ? err : ERR_VAL;
    }

    struct sp_tcp_conn *conn = (struct sp_tcp_conn *)calloc(1, sizeof(struct sp_tcp_conn));
    if (!conn) {
        return ERR_MEM;
    }

    conn->lw = lw;
    conn->pcb = newpcb;
    conn->id = ++lw->next_conn_id;
    sp_add_conn(lw, conn);

    tcp_arg(newpcb, conn);
    tcp_recv(newpcb, sp_tcp_recv_cb);
    tcp_sent(newpcb, sp_tcp_sent_cb);
    tcp_err(newpcb, sp_tcp_err_cb);
    tcp_nagle_disable(newpcb);

    if (lw->tcp_accept) {
        int is_ipv6 = IP_IS_V6(&newpcb->local_ip) ? 1 : 0;
        const void *src_ip = is_ipv6 ? (const void *)&newpcb->remote_ip.u_addr.ip6.addr : (const void *)&newpcb->remote_ip.u_addr.ip4.addr;
        const void *dst_ip = is_ipv6 ? (const void *)&newpcb->local_ip.u_addr.ip6.addr : (const void *)&newpcb->local_ip.u_addr.ip4.addr;
        lw->tcp_accept(conn->id, is_ipv6, src_ip, newpcb->remote_port, dst_ip, newpcb->local_port, lw->ctx_id);
    }

    return ERR_OK;
}

static void sp_udp_recv_cb(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port) {
    struct sp_udp_conn *conn = (struct sp_udp_conn *)arg;
    (void)addr;
    (void)port;
    if (!conn || !conn->lw) {
        if (p) pbuf_free(p);
        return;
    }
    if (!p) return;

    struct sp_lwip *lw = conn->lw;
    if (!lw->udp_recv) {
        pbuf_free(p);
        return;
    }

    int is_ipv6 = IP_IS_V6(&pcb->local_ip) ? 1 : 0;
    const void *src_ip = is_ipv6 ? (const void *)&pcb->remote_ip.u_addr.ip6.addr : (const void *)&pcb->remote_ip.u_addr.ip4.addr;
    const void *dst_ip = is_ipv6 ? (const void *)&pcb->local_ip.u_addr.ip6.addr : (const void *)&pcb->local_ip.u_addr.ip4.addr;

    if (p->next == NULL) {
        lw->udp_recv(conn->id, is_ipv6, src_ip, pcb->remote_port, dst_ip, pcb->local_port, (const uint8_t *)p->payload, (uint16_t)p->tot_len, lw->ctx_id);
    } else {
        u16_t copied = pbuf_copy_partial(p, lw->output_buf, (u16_t)p->tot_len, 0);
        if (copied == p->tot_len) {
            lw->udp_recv(conn->id, is_ipv6, src_ip, pcb->remote_port, dst_ip, pcb->local_port, lw->output_buf, copied, lw->ctx_id);
        }
    }
    pbuf_free(p);
}

static void sp_udp_accept_cb(void *arg, struct udp_pcb *newpcb, struct pbuf *p, const ip_addr_t *addr, u16_t port) {
    struct sp_lwip *lw = (struct sp_lwip *)arg;
    (void)p;
    (void)addr;
    (void)port;
    if (!lw || !newpcb) return;

    struct sp_udp_conn *conn = (struct sp_udp_conn *)calloc(1, sizeof(struct sp_udp_conn));
    if (!conn) {
        udp_remove(newpcb);
        return;
    }

    conn->lw = lw;
    conn->pcb = newpcb;
    conn->id = ++lw->next_conn_id;
    sp_add_udp_conn(lw, conn);

    udp_bind_netif(newpcb, &lw->netif);
    udp_recv(newpcb, sp_udp_recv_cb, conn);
}

void sp_set_ip4_addr(ip4_addr_t *a, uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3) {
    if (!a) return;
    IP4_ADDR(a, b0, b1, b2, b3);
}

static int g_lwip_initialized = 0;

static void abort_all_netif_pcbs(struct netif *netif) {
    u8_t idx = netif_get_index(netif);
    for (int l = 1; l < NUM_TCP_PCB_LISTS; l++) {
        struct tcp_pcb *pcb = *tcp_pcb_lists[l];
        while (pcb != NULL) {
            struct tcp_pcb *next = pcb->next;
            if (pcb->netif_idx == idx || pcb->netif_idx == NETIF_NO_INDEX) {
                tcp_abort(pcb);
            }
            pcb = next;
        }
    }
}

static void remove_all_netif_udp_pcbs(struct netif *netif) {
    u8_t idx = netif_get_index(netif);
    struct udp_pcb *pcb = udp_pcbs;
    while (pcb != NULL) {
        struct udp_pcb *next = pcb->next;
        if (pcb->netif_idx == idx || pcb->pretend_netif_idx == idx) {
            udp_remove(pcb);
        }
        pcb = next;
    }
}

int sp_lwip_init(struct sp_lwip *lw, const ip4_addr_t *ip, const ip4_addr_t *mask, const ip4_addr_t *gw) {
    if (!lw) return -1;
    if (!g_lwip_initialized) {
        lwip_init();
        g_lwip_initialized = 1;
    }
    memset(&lw->netif, 0, sizeof(lw->netif));
    memset(lw->conn_buckets, 0, sizeof(lw->conn_buckets));
    memset(lw->udp_conn_buckets, 0, sizeof(lw->udp_conn_buckets));
    lw->next_conn_id = 0;
    lw->netif.state = lw;

    if (!netif_add(&lw->netif, ip, mask, gw, lw, sp_netif_init, ip_input)) return -2;
    netif_set_up(&lw->netif);
    netif_set_link_up(&lw->netif);
    netif_set_default(&lw->netif);

    // Enable PRETEND flags for transparent proxying
    netif_set_flags(&lw->netif, NETIF_FLAG_PRETEND_TCP | NETIF_FLAG_PRETEND_UDP | NETIF_FLAG_PRETEND_ICMP);

    // Set link-local IPv6 address (fe80::1)
    ip_2_ip6(&lw->netif.ip6_addr[0])->addr[0] = PP_HTONL(0xfe800000ul);
    ip_2_ip6(&lw->netif.ip6_addr[0])->addr[1] = 0;
    ip_2_ip6(&lw->netif.ip6_addr[0])->addr[2] = 0;
    ip_2_ip6(&lw->netif.ip6_addr[0])->addr[3] = PP_HTONL(0x00000001ul);
    netif_ip6_addr_set_state(&lw->netif, 0, IP6_ADDR_VALID);

    // Wildcard TCP listener
    struct tcp_pcb *l = tcp_new_ip_type(IPADDR_TYPE_ANY);
    if (!l) return -3;
    tcp_bind_netif(l, &lw->netif);
    err_t berr = tcp_bind(l, NULL, 0);
    if (berr != ERR_OK) {
        tcp_close(l);
        return -4;
    }
    lw->tcp_listener = tcp_listen(l);
    if (!lw->tcp_listener) {
        tcp_close(l);
        return -5;
    }
    tcp_arg(lw->tcp_listener, lw);
    tcp_accept(lw->tcp_listener, sp_tcp_accept_cb);

    // Wildcard UDP listener
    struct udp_pcb *u = udp_new_ip_type(IPADDR_TYPE_ANY);
    if (!u) {
        tcp_close(lw->tcp_listener);
        lw->tcp_listener = NULL;
        return -6;
    }
    udp_bind_netif(u, &lw->netif);
    err_t uerr = udp_bind(u, NULL, 0);
    if (uerr != ERR_OK) {
        udp_remove(u);
        tcp_close(lw->tcp_listener);
        lw->tcp_listener = NULL;
        return -7;
    }
    udp_recv(u, sp_udp_accept_cb, lw);
    lw->udp_listener = u;

    return 0;
}

void sp_lwip_set_mtu(struct sp_lwip *lw, uint16_t mtu) {
    if (!lw || mtu == 0) return;
    lw->netif.mtu = mtu;
#if LWIP_IPV6
    lw->netif.mtu6 = mtu;
#endif
}

struct sp_lwip *sp_lwip_new(void) {
    return (struct sp_lwip *)calloc(1, sizeof(struct sp_lwip));
}

void sp_lwip_set_callbacks(
    struct sp_lwip *lw,
    sp_lwip_packet_output_fn packet_output,
    sp_lwip_tcp_accept_fn tcp_accept,
    sp_lwip_tcp_recv_fn tcp_recv,
    sp_lwip_tcp_sent_fn tcp_sent,
    sp_lwip_tcp_err_fn tcp_err,
    sp_lwip_udp_recv_fn udp_recv,
    uint64_t ctx_id
) {
    if (!lw) return;
    lw->packet_output = packet_output;
    lw->tcp_accept = tcp_accept;
    lw->tcp_recv = tcp_recv;
    lw->tcp_sent = tcp_sent;
    lw->tcp_err = tcp_err;
    lw->udp_recv = udp_recv;
    lw->ctx_id = ctx_id;
}

void sp_lwip_free(struct sp_lwip *lw) {
    if (!lw) return;
    if (lw->tcp_listener) {
        tcp_close(lw->tcp_listener);
        lw->tcp_listener = NULL;
    }
    for (int i = 0; i < SP_CONN_BUCKETS; i++) {
        struct sp_tcp_conn *c = lw->conn_buckets[i];
        while (c) {
            struct sp_tcp_conn *next = c->next;
            if (c->pcb) {
                tcp_arg(c->pcb, NULL);
                tcp_recv(c->pcb, NULL);
                tcp_sent(c->pcb, NULL);
                tcp_err(c->pcb, NULL);
                tcp_abort(c->pcb);
                c->pcb = NULL;
            }
            free(c);
            c = next;
        }
        lw->conn_buckets[i] = NULL;
    }

    if (lw->udp_listener) {
        udp_remove(lw->udp_listener);
        lw->udp_listener = NULL;
    }
    for (int i = 0; i < SP_CONN_BUCKETS; i++) {
        struct sp_udp_conn *c = lw->udp_conn_buckets[i];
        while (c) {
            struct sp_udp_conn *next = c->next;
            if (c->pcb) {
                udp_remove(c->pcb);
                c->pcb = NULL;
            }
            free(c);
            c = next;
        }
        lw->udp_conn_buckets[i] = NULL;
    }

    abort_all_netif_pcbs(&lw->netif);
    remove_all_netif_udp_pcbs(&lw->netif);
    netif_remove(&lw->netif);
}

void sp_lwip_destroy(struct sp_lwip *lw) {
    if (!lw) return;
    sp_lwip_free(lw);
    free(lw);
}

int sp_lwip_input(struct sp_lwip *lw, const void *data, uint32_t len) {
    if (!lw || !data || !len || len > 65535) return ERR_ARG;
    struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)len, PBUF_POOL);
    if (!p) return ERR_MEM;
    if (pbuf_take(p, data, len) != ERR_OK) { pbuf_free(p); return ERR_BUF; }
    err_t e = lw->netif.input(p, &lw->netif);
    if (e != ERR_OK) pbuf_free(p);
    return e;
}


u32_t sys_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (u32_t)(ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000ULL);
}

void sp_lwip_timers(void) { sys_check_timeouts(); }

int sp_lwip_tcp_write(struct sp_lwip *lw, uint64_t conn_id, const void *data, uint32_t len) {
    if (!lw || !data || !len) return ERR_ARG;
    struct sp_tcp_conn *conn = sp_find_conn(lw, conn_id);
    if (!conn || !conn->pcb) return ERR_CONN;

    u16_t sndbuf = tcp_sndbuf(conn->pcb);
    if (sndbuf == 0) {
        return 0; // Backpressure: buffer full
    }

    uint32_t to_write = len > sndbuf ? sndbuf : len;
    if (to_write > 0xFFFF) to_write = 0xFFFF;

    err_t err = tcp_write(conn->pcb, data, (u16_t)to_write, TCP_WRITE_FLAG_COPY);
    if (err != ERR_OK) {
        return (int)err;
    }

    tcp_output(conn->pcb);
    return (int)to_write;
}

int sp_lwip_tcp_recved(struct sp_lwip *lw, uint64_t conn_id, uint32_t len) {
    if (!lw || !len) return ERR_ARG;
    struct sp_tcp_conn *conn = sp_find_conn(lw, conn_id);
    if (!conn || !conn->pcb) return ERR_CONN;

    while (len > 0) {
        u16_t chunk = len > 0xFFFF ? 0xFFFF : (u16_t)len;
        tcp_recved(conn->pcb, chunk);
        len -= chunk;
    }
    return 0;
}

int sp_lwip_tcp_close(struct sp_lwip *lw, uint64_t conn_id) {
    if (!lw) return ERR_ARG;
    struct sp_tcp_conn *conn = sp_find_conn(lw, conn_id);
    if (!conn) return ERR_CONN;

    if (conn->pcb) {
        tcp_arg(conn->pcb, NULL);
        tcp_recv(conn->pcb, NULL);
        tcp_sent(conn->pcb, NULL);
        tcp_err(conn->pcb, NULL);
        err_t err = tcp_close(conn->pcb);
        if (err != ERR_OK) {
            tcp_abort(conn->pcb);
        }
        conn->pcb = NULL;
    }
    sp_remove_conn(lw, conn);
    free(conn);
    return 0;
}

int sp_lwip_tcp_abort(struct sp_lwip *lw, uint64_t conn_id) {
    if (!lw) return ERR_ARG;
    struct sp_tcp_conn *conn = sp_find_conn(lw, conn_id);
    if (!conn) return ERR_CONN;

    if (conn->pcb) {
        tcp_arg(conn->pcb, NULL);
        tcp_recv(conn->pcb, NULL);
        tcp_sent(conn->pcb, NULL);
        tcp_err(conn->pcb, NULL);
        tcp_abort(conn->pcb);
        conn->pcb = NULL;
    }
    sp_remove_conn(lw, conn);
    free(conn);
    return 0;
}

int sp_lwip_tcp_sndbuf(struct sp_lwip *lw, uint64_t conn_id) {
    if (!lw) return ERR_ARG;
    struct sp_tcp_conn *conn = sp_find_conn(lw, conn_id);
    if (!conn || !conn->pcb) return ERR_CONN;
    return (int)tcp_sndbuf(conn->pcb);
}

int sp_lwip_udp_send(struct sp_lwip *lw, uint64_t conn_id, int is_ipv6, const void *src_ip, uint16_t src_port, const void *data, uint32_t len) {
    if (!lw || !src_ip || !data || !len || len > 0xFFFF) return ERR_ARG;
    struct sp_udp_conn *conn = sp_find_udp_conn(lw, conn_id);
    if (!conn || !conn->pcb) return ERR_CONN;

    ip_addr_t from_addr;
    if (is_ipv6) {
        memcpy(&from_addr.u_addr.ip6.addr, src_ip, 16);
        from_addr.type = IPADDR_TYPE_V6;
    } else {
        memcpy(&from_addr.u_addr.ip4.addr, src_ip, 4);
        from_addr.type = IPADDR_TYPE_V4;
    }

    /*
     * PBUF_REF borrows the caller's payload. The Go adapter pins req.data for
     * the complete sp_lwip_udp_send call, and this NO_SYS raw-API path sends
     * synchronously before returning. That removes the payload memcpy without
     * changing the lifetime visible to lwIP.
     */
    struct pbuf *p = pbuf_alloc_reference((void *)data, (u16_t)len, PBUF_REF);
    if (!p) return ERR_MEM;

    err_t err = udp_sendfrom(conn->pcb, p, &from_addr, src_port);
    pbuf_free(p);

    if (err != ERR_OK) return (int)err;
    return (int)len;
}

int sp_lwip_udp_close(struct sp_lwip *lw, uint64_t conn_id) {
    if (!lw) return ERR_ARG;
    struct sp_udp_conn *conn = sp_find_udp_conn(lw, conn_id);
    if (!conn) return ERR_CONN;

    if (conn->pcb) {
        udp_remove(conn->pcb);
        conn->pcb = NULL;
    }
    sp_remove_udp_conn(lw, conn);
    free(conn);
    return 0;
}
