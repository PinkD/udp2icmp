#include "defs.h"
#include "flags.h"
#include "common.h"

static inline int append_icmp_header(struct __sk_buff *ctx, u16 dst, u16 seq) {
    int ret;
    // --- step 1: extend packet for icmp header
    // from
    //  |ip header|udp header|payload|
    // to
    //  |ip header|icmp header|udp header|payload|
    ret = bpf_skb_adjust_room(ctx, sizeof(struct icmphdr), BPF_ADJ_ROOM_NET,
                              // BPF_F_ADJ_ROOM_NO_CSUM_RESET);
                              0);
    if (ret != 0) {
        return ret;
    }

    // refresh `data` and `data_end` because we modified packet by bpf_skb_adjust_room
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct iphdr *ip = (void *)(data + sizeof(struct ethhdr));
    CHECK_DATA_END(ip);
    // --- step 2: modify ip header
    // modify protocol from udp to icmp
    ip->protocol = IPPROTO_ICMP;
    // add icmp header len
    u16 old_len = htons(ip->tot_len);
    u16 new_len = old_len + sizeof(struct icmphdr);
    ip->tot_len = htons(new_len);
    // reset checksum and recalculate
    ip->check = 0;
    ip->check = hdr_csum(ip, sizeof(struct iphdr), 0);

    // --- step 3: construct icmp header
    struct icmphdr *icmp = (void *)(data + sizeof(struct ethhdr) + sizeof(struct iphdr));
    CHECK_DATA_END(icmp);
    if (is_server_mode) {
        // server always send echo reply
        icmp->type = ICMP_ECHOREPLY;
        icmp->code = 0;
    } else {
        // client always send echo request
        icmp->type = ICMP_ECHO;
        icmp->code = 0;
    }
    icmp->un.echo.id = dst;
    icmp->un.echo.sequence = seq;
    // set checksum to 0 for calculation below
    icmp->checksum = 0;

    // TODO: encrypt payload
    //   UDP = (payload XOR (key XOR SEQ))

    // --- step 4: reset udp checksum and calculate icmp checksum
    // NOTE: because the receiver may be behind a NAT, so the daddr may not be
    //       the same as the original daddr, we cannot use it to calculate udp checksum.
    //       so we use icmp checksum to ensure the packet is valid.
    struct udphdr *udp =
        (void *)(data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr));
    CHECK_DATA_END(udp);
    // reset udp checksum
    // NOTE: the udp checksum may be calculated by udp offloading, 
    //       so the sender may need to disable it by running
    //       `ethtool -K eth0 tx-checksumming off`
    udp->check = 0;

    // do not use hdr_csum because we will fold checksum later
    u32 icmp_checksum = bpf_csum_diff(0, 0, (void *)icmp, sizeof(struct icmphdr), 0);
    u16 *payload = (void *)icmp + sizeof(struct icmphdr);
    CHECK_DATA_END(payload);
    // checksum is calculated in u16
    for (size_t i = 0; i < MAX_MTU; i += 2) {
        if ((void *)(payload + 1) > data_end) {
            break;
        }
        icmp_checksum += *payload;
        payload++;
    }
    // calculate last byte if exist
    if ((void *)payload + 1 <= data_end) {
        u8 last_byte = *(u8 *)payload;
        icmp_checksum += last_byte;
    }
    icmp->checksum = csum_fold(icmp_checksum);
    return 0;
}

SEC("tc/egress")
int tc_egress(struct __sk_buff *ctx) {
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
            return TCX_PASS;
        default:
            return TCX_PASS;
    }

    // ensure all fields 0
    target_addr peer = {0};
    struct iphdr *ip = data + sizeof(struct ethhdr);
    CHECK_DATA_END(ip);
    if (ip->version != 4) {
        return TCX_PASS;
    }
    peer.addr.v4.value = ip->daddr;
    if (ip->protocol != IPPROTO_UDP) {
        return TCX_PASS;
    }

    u16 seq = 0;
    struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    CHECK_DATA_END(udp);
    peer.port = udp->dest;
    if (is_server_mode) {
        // server mode, only send to known clients
        u32 *v = bpf_map_lookup_elem(&client_addr_map, &peer);
        if (!v) {
            log_trace(EVENT_TYPE_SERVER_UDP_NOT_CLIENT, DIRECTION_EGRESS, &peer);
            printk_log("udp packet to %s, not in client addr map", format_addr(&peer));
            return TCX_PASS;
        }
        seq = *v;
        atomic_add(v, 1);
    } else {
        // client mode, only send to server
        u32 *v = bpf_map_lookup_elem(&server_addr_map, &peer);
        if (!v) {
            log_trace(EVENT_TYPE_CLIENT_UDP_NOT_SERVER, DIRECTION_EGRESS, &peer);
            printk_log("udp packet to %s, not in server addr map", format_addr(&peer));
            return TCX_PASS;
        }
        seq = *v;
        atomic_add(v, 1);
    }

    int ret = append_icmp_header(ctx, udp->dest, seq);
    if (ret != 0) {
        log_warn(EVENT_TYPE_COMMON_UDP_APPEND_HEADER_ERROR, DIRECTION_EGRESS, &peer);
        printk_log("udp packet to %s, is_server: %d, seq %d dropped", format_addr(&peer),
                   is_server_mode, seq);

        // the packet might be invalid because it has been modified by us
        return TCX_DROP;
    }
    if (seq == 1) {
        // first packet, use log info
        log_info(EVENT_TYPE_COMMON_UDP_APPEND_HEADER_OK, DIRECTION_EGRESS, &peer);
    } else {
        // other packets, use log debug
        log_debug(EVENT_TYPE_COMMON_UDP_APPEND_HEADER_OK, DIRECTION_EGRESS, &peer);
    }
    printk_log("udp packet to %s, is_server: %d, seq %d convert to icmp", format_addr(&peer),
               is_server_mode, seq);

    return TCX_PASS;
}

char _license[] SEC("license") = "GPL";
