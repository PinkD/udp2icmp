#ifndef __DEFS_H__
#define __DEFS_H__

#ifndef __x86_64__
// avoid include <gnu/stubs-32.h>
#define __x86_64__
#endif

#include "common.h"
#include "flags.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// NOTE: we don't use vmlinux.h at coding time because it's too long and will
//          slow down the IDE
//
// USE_VMLINUX is defined in Makefile
#ifdef USE_VMLINUX
#include "vmlinux.h"
#else
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>
#endif

#define htons bpf_htons
#define htonl bpf_htonl
#define ntohs bpf_ntohs
#define ntohl bpf_ntohl

#ifdef USE_VMLINUX
// defined in linux/if_ether.h
#define ETH_HLEN 14
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

// defined in linux/icmp.h
#define ICMP_ECHO 8
#define ICMP_ECHOREPLY 0
#endif  // _LINUX_ICMP_H

// TODO: support jumbo frame
#define MAX_MTU 1500

#define CHECK_DATA_END(x)             \
    if ((void *)(x + 1) > data_end) { \
        return XDP_PASS;              \
    }

static inline u16 csum_fold(u32 csum) {
    u32 sum;
    sum = (csum >> 16) + (csum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

static inline u32 hdr_csum(void *hdr, int len, u32 csum) {
    i64 ret = bpf_csum_diff(0, 0, hdr, len, csum);
    if (ret < 0) {
        return 0;
    }
    return csum_fold(ret);
}

// for client, init by usermode program, read by ingress
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, target_addr);
    __type(value, u32);
    __uint(max_entries, MAX_SERVER_NUM);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} server_addr_map SEC(".maps");

// for server, set by ingress, read by egress
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, target_addr);
    __type(value, u32);
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} client_addr_map SEC(".maps");

// ring buffer for log events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);  // 4M
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} log_event_rb SEC(".maps");

// this function is used by `bpf_printk` which is disabled because of performance
// so we add unused attribute to avoid warning
__attribute__((unused)) static const char *format_addr(target_addr *addr) {
    static char buf[64];

    if (addr->addr.v4.value) {
        u32 v = addr->addr.v4.value;
        u64 ip_data[5];
        ip_data[0] = (u64)v & 0xFF;
        ip_data[1] = (u64)(v >> 8) & 0xFF;
        ip_data[2] = (u64)(v >> 16) & 0xFF;
        ip_data[3] = (u64)(v >> 24) & 0xFF;
        ip_data[4] = (u64)htons(addr->port);
        bpf_snprintf(buf, sizeof(buf), "%d.%d.%d.%d:%d", ip_data, 5 * sizeof(u64));
    } else {
        // TODO: ipv6
    }
    return buf;
}

static inline void _log_any(int level, enum event_type type, enum direction direction,
                           target_addr *addr) {
    if (level < log_level) {
        return;
    }
    struct log_event *event = bpf_ringbuf_reserve(&log_event_rb, sizeof(struct log_event), 0);
    if (!event) {
        return;
    }
    event->level = level;
    event->type = type;
    event->direction = direction;
    if (addr) {
        event->addr = *addr;
    }
    bpf_ringbuf_submit(event, 0);
}

void log_trace(enum event_type type, enum direction direction, target_addr *addr) {
    _log_any(LOG_LEVEL_TREACE, type, direction, addr);
}

void log_debug(enum event_type type, enum direction direction, target_addr *addr) {
    _log_any(LOG_LEVEL_DEBUG, type, direction, addr);
}

void log_info(enum event_type type, enum direction direction, target_addr *addr) {
    _log_any(LOG_LEVEL_INFO, type, direction, addr);
}

void log_warn(enum event_type type, enum direction direction, target_addr *addr) {
    _log_any(LOG_LEVEL_WARN, type, direction, addr);
}

#endif  // __DEFS_H__
