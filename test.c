#include <stdio.h>
#include <bpf/bpf.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>

#include "common.h"
#include "main.h"
#include "egress.skel.h"

int main(int argc, char *argv[]) {
    struct __sk_buff skb = {0};
    int ip_len = sizeof(struct iphdr) + sizeof(struct udphdr) + 1;
    char pkt[sizeof(struct ethhdr) + ip_len];
    char out_pkt[sizeof(struct ethhdr) + ip_len + sizeof(struct icmphdr)];
    struct egress_bpf *skel;

    struct ethhdr *eth = (struct ethhdr *)pkt;
    eth->h_proto = htons(ETH_P_IP);

    struct iphdr *ip = (struct iphdr *)(pkt + sizeof(struct ethhdr));
    ip->version = 4;
    ip->protocol = IPPROTO_UDP;
    ip->tot_len = htons(ip_len);
    // 127.0.0.1 <-> 127.0.0.1
    ip->saddr = htonl(0x7f000001);
    ip->daddr = htonl(0x7f000001);
    ip->check = 1;

    struct udphdr *udp = (struct udphdr *)(pkt + sizeof(struct ethhdr) + sizeof(struct iphdr));
    udp->source = htons(23456);
    udp->dest = htons(12345);
    udp->len = htons(ip_len - sizeof(struct iphdr));
    udp->check = 2;

    struct bpf_test_run_opts test_opts = {
        .sz = sizeof(struct bpf_test_run_opts),

        .data_in = &pkt,
        .data_size_in = sizeof(pkt),
        .data_out = &out_pkt,
        .data_size_out = sizeof(out_pkt),

        .ctx_in = &skb,
        .ctx_size_in = sizeof(skb),
    };

    skel = egress_bpf__open_and_load();
    if (!skel) {
        printf("Failed to open and load skeleton\n");
        return 1;
    }
    skel->bss->log_level = LOG_LEVEL_TREACE;
    target_addr addr;
    addr.addr.v4.value = ip->daddr;
    addr.port = udp->dest;
    u32 v = 1;
    // TODO: this does not work
    int ret = bpf_map__update_elem(skel->maps.server_addr_map, &addr, sizeof(target_addr), &v,
                                   sizeof(v), 0);
    if (ret < 0) {
        fprintf(stderr, "Failed to update server_addr_map: %d\n", ret);
        return -1;
    }

    printf("eth %lu, ip %lu, udp %lu, icmp %lu, len(pkt): %lu\n", sizeof(struct ethhdr),
           sizeof(struct iphdr), sizeof(struct udphdr), sizeof(struct icmphdr), sizeof(pkt));
    printf("peer: %s\n", format_addr(&addr));
    printf("ip len: %d\n", htons(ip->tot_len));
    printf("ip check: %x\n", ip->check);
    printf("ip daddr: %x\n", ip->daddr);
    printf("udp dst: %d\n", htons(udp->dest));

    printf("------\n");

    // get the prog_fd from the skeleton, and run our test.
    int prog_fd = bpf_program__fd(skel->progs.tc_egress);
    int err = bpf_prog_test_run_opts(prog_fd, &test_opts);
    if (err != 0) {
        printf("Test run failed: %d\n", err);
    }

    ip = (struct iphdr *)(out_pkt + sizeof(struct ethhdr));
    udp = (struct udphdr *)(out_pkt + sizeof(struct ethhdr) + sizeof(struct iphdr) +
                            sizeof(struct icmphdr));
    struct icmphdr *icmp = (struct icmphdr *)(out_pkt + sizeof(struct ethhdr) +
                                              sizeof(struct iphdr));
    printf("ip len: %d\n", htons(ip->tot_len));
    printf("ip check: %x\n", ip->check);
    printf("ip daddr: %x\n", ip->daddr);
    printf("icmp checksum: %x\n", icmp->checksum);
    printf("udp dst: %d\n", htons(udp->dest));
    return 0;
}