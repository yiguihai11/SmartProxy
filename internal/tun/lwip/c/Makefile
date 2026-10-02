LWIP_DIR ?= ../../../../third_party/lwip
CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Werror -std=c11
CPPFLAGS += -I. -I$(LWIP_DIR)/src/include -DLWIP_NOASSERT -D_POSIX_C_SOURCE=200809L
CFLAGS += -MMD -MP -Wno-unused-but-set-variable -Wno-unused-parameter -Wno-tautological-constant-out-of-range-compare

CORE_SRCS := \
 $(LWIP_DIR)/src/core/init.c \
 $(LWIP_DIR)/src/core/def.c \
 $(LWIP_DIR)/src/core/inet_chksum.c \
 $(LWIP_DIR)/src/core/ip.c \
 $(LWIP_DIR)/src/core/mem.c \
 $(LWIP_DIR)/src/core/memp.c \
 $(LWIP_DIR)/src/core/netif.c \
 $(LWIP_DIR)/src/core/pbuf.c \
 $(LWIP_DIR)/src/core/raw.c \
 $(LWIP_DIR)/src/core/stats.c \
 $(LWIP_DIR)/src/core/sys.c \
 $(LWIP_DIR)/src/core/tcp.c \
 $(LWIP_DIR)/src/core/tcp_in.c \
 $(LWIP_DIR)/src/core/tcp_out.c \
 $(LWIP_DIR)/src/core/timeouts.c \
 $(LWIP_DIR)/src/core/udp.c

IP4_SRCS := $(wildcard $(LWIP_DIR)/src/core/ipv4/*.c)
IP6_SRCS := $(wildcard $(LWIP_DIR)/src/core/ipv6/*.c)

OBJS := $(CORE_SRCS:.c=.o) $(IP4_SRCS:.c=.o) $(IP6_SRCS:.c=.o) lwip_adapter.o
DEPS := $(OBJS:.o=.d)

all: libsmartproxy_lwip.a

libsmartproxy_lwip.a: $(OBJS)
	ar rcs $@ $^

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

lwip_adapter.o: lwip_adapter.c lwip_adapter.h lwipopts.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

check: all
	@echo "lwIP C adapter build OK"

clean:
	rm -f libsmartproxy_lwip.a lwip_adapter.o lwip_adapter.d smoke smoke.o smoke.d
	find $(LWIP_DIR)/src -name '*.o' -o -name '*.d' | xargs -r rm -f

-include $(DEPS)
