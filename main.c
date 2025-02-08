#include "common.h"
#include "main.h"

#include <getopt.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include "ingress.skel.h"
#include "egress.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

static void help(char *cmd) {
    fprintf(stderr, "Usage: %s [options]\n\n", cmd);
    fprintf(stderr, "Description:\n    Wrap udp packet with icmp header using bpf.\n\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr,
            "  -h, --help                   Print help message.\n"
            "  -t, --target <ip:port>       Target address. Set multiple targets with multiple "
            "--target options.\n"
            "                               NOTE: This option indicates client mode.\n"
            "  -i, --interface <interface>  Interface to attach XDP program."
            "(Required)\n"
            // "  -m, --mode <mode>            Mode to attach XDP program.(native/skb, "
            // "default: skb)\n"
            "  -l, --log-level <level>      "
            "Log level.(trace/debug/info/warn/error/none, default: info)\n");
}

struct args {
    char *interface;
    char *mode;
    int target_num;
    char *target[MAX_SERVER_NUM];
    enum log_level log_level;
};

bool parse_args(int argc, char **argv, struct args *out) {
    int opt;
    struct args *args = out;
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"interface", required_argument, 0, 'i'},
        {"target", optional_argument, 0, 't'},
        {"mode", optional_argument, 0, 'm'},
        {"log-level", optional_argument, 0, 'l'},
        {0, 0, 0, 0},
    };

    while ((opt = getopt_long(argc, argv, "hi:m:l:t:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'h':
                return false;
            case 'i':
                args->interface = optarg;
                break;
            case 'm':
                args->mode = optarg;
                break;
            case 'l':
                args->log_level = parse_log_level(optarg);
                break;
            case 't':
                args->target[args->target_num] = optarg;
                args->target_num++;
                if (args->target_num >= MAX_SERVER_NUM) {
                    fprintf(stderr, "Too many targets, max: %d\n", MAX_SERVER_NUM);
                    return false;
                }
                break;
        }
    }
    return true;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        help(argv[0]);
        return -1;
    }
    struct args args = {
        .interface = NULL,
        // TODO: mode is not used now
        .mode = "skb",
        .log_level = LOG_LEVEL_INFO,
        .target_num = 0,
        .target = {0},
    };
    if (!parse_args(argc, argv, &args)) {
        help(argv[0]);
        return -1;
    }
    if (!args.interface) {
        fprintf(stderr, "--interface is required\n\n");
        help(argv[0]);
        return -1;
    }

    // print all logs to stderr if log level is below debug
    if (args.log_level >= LOG_LEVEL_INFO) {
        libbpf_set_print(NULL);
    }

    struct ingress_bpf *ingress = ingress_bpf__open();
    if (ingress == NULL) {
        fprintf(stderr, "Failed to open ingress BPF\n");
        return -1;
    }
    struct egress_bpf *egress = egress_bpf__open();
    if (egress == NULL) {
        printf("Failed to open egress BPF\n");
        return -1;
    }

    ingress->bss->log_level = args.log_level;
    egress->bss->log_level = args.log_level;
    target_addr addr[MAX_SERVER_NUM] = {0};
    if (args.target_num > 0) {
        // if target is set, we are in client mode
        printf("Running on client mode\n");
        for (int i = 0; i < args.target_num; i++) {
            target_addr *a = parse_ip_port(args.target[i]);
            if (!a) {
                fprintf(stderr, "Failed to parse target address %s\n", args.target[i]);
                return -1;
            }
            addr[i] = *a;
            printf("Using target[%d]: %s\n", i, format_addr(&addr[i]));
        }
    } else {
        // if target is not set, we are in server mode
        fprintf(stderr, "Running on server mode\n");
        ingress->bss->is_server_mode = 1;
        egress->bss->is_server_mode = 1;
    }

    int ret;
    ret = mount("", BPF_PIN_PATH, "bpf", 0, NULL);
    if (ret < 0) {
        fprintf(stderr, "Failed to mount %s: %d\n", BPF_PIN_PATH, ret);
        return -1;
    }

    ret = ingress_bpf__load(ingress);
    if (ret < 0) {
        fprintf(stderr, "Failed to load ingress BPF\n");
        return -1;
    }
    ret = egress_bpf__load(egress);
    if (ret < 0) {
        fprintf(stderr, "Failed to load egress BPF\n");
        ingress_bpf__destroy(ingress);
        return -1;
    }
    if (args.target_num > 0) {
        u32 v = 1;
        // only update ingress because the map is pinned by name
        for (int i = 0; i < args.target_num; i++) {
            int ret = bpf_map__update_elem(ingress->maps.server_addr_map, &addr[i],
                                           sizeof(target_addr), &v, sizeof(v), 0);
            if (ret < 0) {
                fprintf(stderr, "Failed to update server_addr_map for ingress: %d\n", ret);
                goto CLEAN_UP;
            }
        }
    }

    struct ring_buffer *rb =
        ring_buffer__new(bpf_map__fd(ingress->maps.log_event_rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto CLEAN_UP;
    }

    ret = ingress_bpf__attach(ingress);
    if (ret < 0) {
        fprintf(stderr, "Failed to attach ingress BPF\n");
        goto CLEAN_UP;
    }
    ret = egress_bpf__attach(egress);
    if (ret < 0) {
        fprintf(stderr, "Failed to attach egress BPF\n");
        goto CLEAN_UP;
    }
    int ifindex = if_nametoindex(args.interface);
    ingress->links.xdp_ingress = bpf_program__attach_xdp(ingress->progs.xdp_ingress, ifindex);
    if (!ingress->links.xdp_ingress) {
        fprintf(stderr, "Failed to attach ingress BPF to interface\n");
        goto CLEAN_UP;
    }
    egress->links.tc_egress = bpf_program__attach_tcx(egress->progs.tc_egress, ifindex, NULL);
    if (!egress->links.tc_egress) {
        fprintf(stderr, "Failed to attach egress BPF to interface\n");
        goto CLEAN_UP;
    }

    // handle signal
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGQUIT);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    if (sigprocmask(SIG_BLOCK, &set, NULL) == -1) {
        fprintf(stderr, "Failed to setup signal mask\n");
        goto CLEAN_UP;
    }
    int signal_fd = signalfd(-1, &set, 0);
    if (signal_fd == -1) {
        fprintf(stderr, "Failed to get signal fd\n");
        goto CLEAN_UP;
    }

    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        fprintf(stderr, "Failed to setup epoll\n");
        close(signal_fd);
        goto CLEAN_UP;
    }
    struct epoll_event event;
    event.events = EPOLLIN;
    event.data.fd = signal_fd;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, signal_fd, &event) == -1) {
        fprintf(stderr, "Failed to add signal fd to epoll\n");
        close(signal_fd);
        close(epoll_fd);
        goto CLEAN_UP;
    }

    int rb_fd = ring_buffer__epoll_fd(rb);
    event.data.fd = rb_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, rb_fd, &event) == -1) {
        fprintf(stderr, "Failed to add rb fd to epoll\n");
        close(signal_fd);
        close(epoll_fd);
        goto CLEAN_UP;
    }

    struct epoll_event events[EPOLL_MAX_EVENTS];
    int running = 1;
    while (running) {
        int n = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, -1);
        if (n == -1) {
            if (errno == EINTR) {
                continue;
            }
            fprintf(stderr, "Epoll wait error\n");
            break;
        }

        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == signal_fd) {
                struct signalfd_siginfo info;
                ssize_t len = read(signal_fd, &info, sizeof(info));
                if (len != sizeof(info)) {
                    fprintf(stderr, "Invalid signal info len\n");
                    continue;
                }
                fprintf(stderr, "Signal %s received, exiting\n", strsignal(info.ssi_signo));
                running = false;
                break;
            }
            if (events[i].data.fd == rb_fd) {
                ret = ring_buffer__poll(rb, 0);
                if (ret < 0) {
                    fprintf(stderr, "Failed to poll ring buffer\n");
                    running = false;
                    break;
                }
            }
        }
    }

    close(signal_fd);
    close(epoll_fd);
    bpf_object__unpin_maps(ingress->obj, BPF_PIN_PATH);
    ingress_bpf__detach(ingress);
    egress_bpf__detach(egress);
CLEAN_UP:
    if (rb) {
        ring_buffer__free(rb);
    }
    ingress_bpf__destroy(ingress);
    egress_bpf__destroy(egress);
    return ret;
}