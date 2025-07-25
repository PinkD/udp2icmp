#include "defs.h"
#include "flags.h"
#include "common.h"

static inline int calc_udp_checksum(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    CHECK_DATA_END(ip);
    struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    CHECK_DATA_END(udp);
    u32 checksum = 0;
    // udp pesudo header
    // 0        8        16       24       32
    // +--------+--------+--------+--------+
    // |          source address           |
    // +--------+--------+--------+--------+
    // |        destination address        |
    // +--------+--------+--------+--------+
    // |  zero  |protocol|   UDP length    |
    // +--------+--------+--------+--------+
    // 1. ip.saddr
    checksum += (ip->saddr >> 16) & 0xFFFF;
    checksum += (ip->saddr) & 0xFFFF;
    // 2. ip.daddr
    checksum += (ip->daddr >> 16) & 0xFFFF;
    checksum += (ip->daddr) & 0xFFFF;
    // 3. protocol
    checksum += htons(IPPROTO_UDP);
    // 4. udp length
    checksum += udp->len;

    // reset udp checksum for calculation
    udp->check = 0;
    u16 *payload = (void *)udp;
    CHECK_DATA_END(payload);
    // checksum is calculated in u16
    for (size_t i = 0; i < MAX_MTU; i += 2) {
        if ((void *)(payload + 1) > data_end) {
            break;
        }
        checksum += *payload;
        payload++;
    }
    // calculate last byte if exist
    if ((void *)payload + 1 <= data_end) {
        u8 last_byte = *(u8 *)payload;
        checksum += last_byte;
    }
    udp->check = csum_fold(checksum);
    return 0;
}

static inline int remove_icmp_header(struct xdp_md *ctx) {
    const int offset = sizeof(struct ethhdr) + sizeof(struct iphdr);
    u8 buf[offset];
    int ret;

    // from
    //  |ip header|icmp header|udp header|payload|
    // to
    //  |ip header|udp header|payload|

    // backup eth+ip header
    ret = bpf_xdp_load_bytes(ctx, 0, buf, offset);
    if (ret != 0) {
        return ret;
    }
    // shrink packet for icmp header
    ret = bpf_xdp_adjust_head(ctx, sizeof(struct icmphdr));
    if (ret != 0) {
        return ret;
    }

    struct iphdr *ip = (void *)(buf + sizeof(struct ethhdr));
    // modify protocol from icmp to udp
    ip->protocol = IPPROTO_UDP;
    // sub icmp header len
    u32 old_len = htons(ip->tot_len);
    u32 new_len = old_len - sizeof(struct icmphdr);
    ip->tot_len = htons(new_len);
    // reset checksum and recalculate
    ip->check = 0;
    ip->check = hdr_csum(ip, sizeof(struct iphdr), 0);

    // restore eth+ip header
    ret = bpf_xdp_store_bytes(ctx, 0, buf, offset);
    if (ret != 0) {
        return ret;
    }
    return 0;
}

SEC("xdp.frags")
int xdp_ingress(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    CHECK_DATA_END(eth);
    u16 proto = htons(eth->h_proto);
    switch (proto) {
        case ETH_P_IP:
            break;
        case ETH_P_IPV6:
            // TODO: handle ipv6
            return XDP_PASS;
        default:
            return XDP_PASS;
    }

    // ensure all fields 0
    target_addr peer = {0};
    struct iphdr *ip = data + sizeof(struct ethhdr);
    CHECK_DATA_END(ip);
    if (ip->version != 4) {
        return XDP_PASS;
    }
    peer.addr.v4.value = ip->daddr;
    if (ip->protocol != IPPROTO_ICMP) {
        return XDP_PASS;
    }
    int offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr);
    struct udphdr *udp = data + offset;
    CHECK_DATA_END(udp);
    peer.port = udp->dest;
    // we cannot use data_end to check udp length, because the packet might contain padding
    int udp_len = htons(ip->tot_len) - sizeof(struct iphdr) - sizeof(struct icmphdr);

    log_trace(EVENT_TYPE_COMMON_ICMP_PACKET, DIRECTION_EGRESS, &peer);
    printk_log("icmp packet from %s, udp.len: %d, udp_len: %d", format_addr(&peer), udp->len,
               udp_len);
    if (htons(udp->len) != udp_len) {
        // body of icmp is not udp packet, maybe normal ping packet
        log_debug(EVENT_TYPE_COMMON_ICMP_PING_PACKET, DIRECTION_INGRESS, &peer);
        printk_log("icmp packet from %s len mismatch, expected: %d, actual: %d", format_addr(&peer),
                   udp_len, htons(udp->len));
        return XDP_PASS;
    }

    if (!is_server_mode) {
        // in client mode, we only handle packets from server
        u32 *v = bpf_map_lookup_elem(&server_addr_map, &peer);
        if (!v) {
            log_debug(EVENT_TYPE_CLIENT_ICMP_NOT_SERVER, DIRECTION_INGRESS, &peer);
            return XDP_PASS;
        }
    } else {
        // in server mode, we handle all packets matches our pattern
        // TODO: modify map after modify packet
        u32 *v = bpf_map_lookup_elem(&client_addr_map, &peer);
        if (!v) {
            log_info(EVENT_TYPE_SERVER_ICMP_NEW_CLIENT, DIRECTION_INGRESS, &peer);
            // new client
            u32 v0 = 1;
            int ret = bpf_map_update_elem(&client_addr_map, &peer, &v0, BPF_NOEXIST);
            if (ret != 0) {
                log_warn(EVENT_TYPE_COMMON_UPDATE_BPF_MAP_ERROR, DIRECTION_INGRESS, &peer);
                printk_log(
                    "icmp packet from %s dropped because update map failed, "
                    "err: %d",
                    format_addr(&peer), ret);
                return XDP_DROP;
            }
        }
    }
    int ret = remove_icmp_header(ctx);
    if (ret != 0) {
        printk_log("icmp packet from %s dropped, err: %d", format_addr(&peer), ret);
        log_warn(EVENT_TYPE_COMMON_ICMP_REMOVE_HEADER_ERROR, DIRECTION_INGRESS, &peer);
        // the packet might be invalid because it has been modified by us
        return XDP_DROP;
    }
    printk_log("icmp packet from %s passed", format_addr(&peer));
    log_trace(EVENT_TYPE_COMMON_ICMP_REMOVE_HEADER_OK, DIRECTION_INGRESS, &peer);
    // TODO: decrypt payload

    ret = calc_udp_checksum(ctx);
    if (ret != 0) {
        printk_log("icmp packet from %s dropped, calc udp checksum error", format_addr(&peer));
        log_debug(EVENT_TYPE_COMMON_CHECKSUM_ERROR, DIRECTION_INGRESS, &peer);
        return XDP_DROP;
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
