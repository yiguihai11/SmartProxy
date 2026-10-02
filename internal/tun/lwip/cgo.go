//go:build with_lwip && cgo

package lwip

/*
#cgo CFLAGS: -I${SRCDIR}/c -I${SRCDIR}/c/arch -I${SRCDIR}/../../../third_party/lwip/src/include -DLWIP_NOASSERT -D_POSIX_C_SOURCE=200809L -Wno-tautological-constant-out-of-range-compare
#include <stdint.h>
#include "c/lwip_adapter.h"

extern void goPacketOutput(const uint8_t *data, uint32_t len, uint64_t ctx_id);
extern void goTcpAccept(uint64_t conn_id, int is_ipv6, const void *src_ip, uint16_t src_port, const void *dst_ip, uint16_t dst_port, uint64_t ctx_id);
extern void goTcpRecv(uint64_t conn_id, const uint8_t *data, uint16_t len, uint64_t ctx_id);
extern void goTcpSent(uint64_t conn_id, uint16_t len, uint64_t ctx_id);
extern void goTcpErr(uint64_t conn_id, int err, uint64_t ctx_id);
extern void goUdpRecv(uint64_t conn_id, int is_ipv6, const void *src_ip, uint16_t src_port, const void *dst_ip, uint16_t dst_port, const uint8_t *data, uint16_t len, uint64_t ctx_id);

static inline void sp_lwip_bind_go_callbacks(struct sp_lwip *lw, uint64_t ctx_id) {
    sp_lwip_set_callbacks(
        lw,
        goPacketOutput,
        goTcpAccept,
        goTcpRecv,
        goTcpSent,
        goTcpErr,
        goUdpRecv,
        ctx_id
    );
}
*/
import "C"

func bindGoCallbacks(lw *C.struct_sp_lwip, ctxID uint64) {
	C.sp_lwip_bind_go_callbacks(lw, C.uint64_t(ctxID))
}
