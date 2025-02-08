#ifndef __COMMON_H__
#define __COMMON_H__

#ifdef USE_VMLINUX
#include "vmlinux.h"
#else
#include <linux/types.h>
#include <netinet/in.h>
#endif

// basic types
#define i8 __s8
#define u8 __u8
#define i16 __s16
#define u16 __u16
#define i32 __s32
#define u32 __u32
#define i64 __s64
#define u64 __u64
#define i128 __s128
#define u128 __u128

// log levels
//
enum log_level {
    // log more packet
    LOG_LEVEL_TREACE = -2,
    // log matched packet
    LOG_LEVEL_DEBUG = -1,
    // log first packet
    LOG_LEVEL_INFO = 0,
    // log abnormal packet
    LOG_LEVEL_WARN = 1,
    // log error, not used now
    LOG_LEVEL_ERROR = 2,
    // supress all log
    LOG_LEVEL_NONE = 3,

};

// NOTE: all fieds should always be in network byte order
typedef struct {
    union {
        union {
            struct in_addr raw;
            u32 value;
        } v4;
        union {
            struct in6_addr raw;
            u128 value;
        } v6;
    } addr;
    u16 port;
} target_addr;

enum event_type {
    // name format: EVET_TYPE_{MODE}_{PROTOCOL}_{REASON}

    // egress
    EVENT_TYPE_SERVER_UDP_NOT_CLIENT = 0x00,
    EVENT_TYPE_CLIENT_UDP_NOT_SERVER = 0x01,
    EVENT_TYPE_COMMON_UDP_APPEND_HEADER_ERROR = 0x02,
    EVENT_TYPE_COMMON_UDP_APPEND_HEADER_OK = 0x03,
    // ingress
    EVENT_TYPE_COMMON_ICMP_PACKET = 0x10,
    EVENT_TYPE_COMMON_ICMP_PING_PACKET = 0x11,
    EVENT_TYPE_CLIENT_ICMP_NOT_SERVER = 0x12,
    EVENT_TYPE_SERVER_ICMP_NEW_CLIENT = 0x13,
    EVENT_TYPE_COMMON_ICMP_REMOVE_HEADER_ERROR = 0x14,
    EVENT_TYPE_COMMON_ICMP_REMOVE_HEADER_OK = 0x15,
    // common
    EVENT_TYPE_COMMON_UPDATE_BPF_MAP_ERROR = 0x20,

};

enum direction {
    DIRECTION_NONE = 0,
    DIRECTION_INGRESS = 1,
    DIRECTION_EGRESS = 2,
};

struct log_event {
    enum log_level level;
    enum event_type type;
    enum direction direction;
    target_addr addr;
};

#define atomic_add __sync_fetch_and_add

#define MAX_SERVER_NUM 64

#endif  // __COMMON_H__
