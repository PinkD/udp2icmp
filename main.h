#ifndef __MAIN_H__
#define __MAIN_H__

#include "common.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define EPOLL_MAX_EVENTS 10
#define BPF_PIN_PATH "/sys/fs/bpf"

static enum log_level parse_log_level(char *level) {
    if (strcmp(level, "trace") == 0) {
        return LOG_LEVEL_TREACE;
    } else if (strcmp(level, "debug") == 0) {
        return LOG_LEVEL_DEBUG;
    } else if (strcmp(level, "info") == 0) {
        return LOG_LEVEL_INFO;
    } else if (strcmp(level, "warn") == 0) {
        return LOG_LEVEL_WARN;
    } else if (strcmp(level, "error") == 0) {
        return LOG_LEVEL_ERROR;
    } else if (strcmp(level, "none") == 0) {
        return LOG_LEVEL_NONE;
    } else {
        // default log level is info
        return LOG_LEVEL_INFO;
    }
}

char *format_log_level(enum log_level level) {
    switch (level) {
        case LOG_LEVEL_TREACE:
            return "trace";
        case LOG_LEVEL_DEBUG:
            return "debug";
        case LOG_LEVEL_INFO:
            return "info";
        case LOG_LEVEL_WARN:
            return "warn";
        case LOG_LEVEL_ERROR:
            return "error";
        case LOG_LEVEL_NONE:
            return "none";
        default:
            return "unknown";
    }
}

static target_addr *parse_ip_port(const char *str) {
    if (!str) {
        return NULL;
    }
    static target_addr addr = {0};

    char *colon = strrchr(str, ':');
    if (!colon) {
        return NULL;
    }

    const char *ip_str = str;
    size_t ip_len = colon - str;
    const char *port_str = colon + 1;

    if (*port_str == '\0') {
        return NULL;
    }

    if (ip_len == 0) {
        // empty ip, use 0.0.0.0
        addr.addr.v4.value = htonl(INADDR_ANY);
    } else {
        char ip_buf[16];
        if (ip_len >= sizeof(ip_buf)) {
            return NULL;
        }
        memcpy(ip_buf, ip_str, ip_len);
        ip_buf[ip_len] = '\0';

        if (inet_pton(AF_INET, ip_buf, &addr.addr.v4.raw) != 1) {
            return NULL;
        }
    }

    char *end;
    u16 port_num = (u16)strtoul(port_str, &end, 10);
    if (*end != '\0') {
        return NULL;
    }

    addr.port = htons(port_num);
    return &addr;
}

char *format_addr(target_addr *addr) {
    static char buf[64];
    if (addr->addr.v4.value) {
        u32 v = addr->addr.v4.value;
        int a = v & 0xFF;
        int b = (v >> 8) & 0xFF;
        int c = (v >> 16) & 0xFF;
        int d = (v >> 24) & 0xFF;
        sprintf(buf, "%d.%d.%d.%d:%d", a, b, c, d, ntohs(addr->port));
    } else {
        // TODO: ipv6
    }
    return buf;
}

int handle_event(void *ctx, void *data, size_t size) {
    struct log_event *e = data;
    char *lv = format_log_level(e->level);
    char *direction;
    switch (e->direction) {
        case DIRECTION_INGRESS:
            direction = "ingress";
            break;
        case DIRECTION_EGRESS:
            direction = "egress";
            break;
        case DIRECTION_NONE:
        default:
            direction = "none";
            break;
    }
    char *addr = format_addr(&e->addr);
    switch (e->type) {
        // egress
        case EVENT_TYPE_SERVER_UDP_NOT_CLIENT:
            printf("%s: %s: udp addr %s is not in client map\n", lv, direction, addr);
            break;
        case EVENT_TYPE_CLIENT_UDP_NOT_SERVER:
            printf("%s: %s: udp addr %s is not in server map\n", lv, direction, addr);
            break;
        case EVENT_TYPE_COMMON_UDP_APPEND_HEADER_ERROR:
            printf("%s: %s: udp packet(%s) append icmp header error\n", lv, direction, addr);
            break;
        case EVENT_TYPE_COMMON_UDP_APPEND_HEADER_OK:
            printf("%s: %s: udp packet(%s) append icmp header ok\n", lv, direction, addr);
            break;

        // ingress
        case EVENT_TYPE_COMMON_ICMP_PACKET:
            printf("%s: %s: icmp packet(%s)\n", lv, direction, addr);
            break;
        case EVENT_TYPE_COMMON_ICMP_PING_PACKET:
            printf("%s: %s: icmp packet(%s) seems to be a normal ping packet\n", lv, direction,
                   addr);
            break;
        case EVENT_TYPE_CLIENT_ICMP_NOT_SERVER:
            printf("%s: %s: icmp packet(%s) not from server\n", lv, direction, addr);
            break;
        case EVENT_TYPE_SERVER_ICMP_NEW_CLIENT:
            printf("%s: %s: icmp packet(%s) from new client\n", lv, direction, addr);
            break;
        case EVENT_TYPE_COMMON_ICMP_REMOVE_HEADER_ERROR:
            printf("%s: %s: icmp packet(%s) remove icmp header error\n", lv, direction, addr);
            break;
        case EVENT_TYPE_COMMON_ICMP_REMOVE_HEADER_OK:
            printf("%s: %s: icmp packet(%s) remove icmp header ok\n", lv, direction, addr);
            break;

        // common
        case EVENT_TYPE_COMMON_UPDATE_BPF_MAP_ERROR:
            printf("%s: %s: addr(%s) update bpf map error\n", lv, direction, addr);
            break;
        case EVENT_TYPE_COMMON_CHECKSUM_ERROR:
            printf("%s: %s: addr(%s) calc checksum error\n", lv, direction, addr);
            break;
        default:
            printf("Unknown event type: %d, direction: %s, log_level: %s, addr: %s\n", e->type,
                   direction, lv, addr);
            break;
    }
    return 0;
}

#endif  // __MAIN_H__
