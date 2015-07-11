#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/wait.h>

#include <arpa/inet.h>

#include <getopt.h>
#include <pcap.h>
#include <hiredis/hiredis.h>

char *mon_if = "mon0";          // monitoring interface (mon0 as default)
pcap_t *handle = NULL;
char errbuf[PCAP_ERRBUF_SIZE];

char *redis_host = "127.0.0.1"; // redis host (127.0.0.1 as default)
int redis_port = 6379;          // redis port (6379 as default)
redisContext *r = NULL;
redisReply *reply;

struct qf {
    char *queue;
    char *filter;
};
struct qf queue_filter[] = {
    {"rx_frame",      NULL},
    {"rx_beacon",     "type mgt subtype beacon"},
    {"rx_probe_req",  "type mgt subtype probe-req"},
    {"rx_probe_resp", "type mgt subtype probe-resp"},
    {"rx_auth",       "type mgt subtype auth"},
    {"rx_assoc_req",  "type mgt subtype assoc-req"},
    {"rx_assoc_resp", "type mgt subtype assoc-resp"},
    {"rx_eap_frame",  "type data and ether[30:2] = 0x888e"},
    {NULL,             NULL}
};

int wait_for_ack = 1;
const char RADIOTAP_NOACK[] = {
    0x00,                   // version
    0x00,                   // padding
    0x0a, 0x00,             // length
    0x00, 0x80, 0x00, 0x00, // IEEE80211_RADIOTAP_TX_FLAGS
    0x08, 0x00};            // IEEE80211_RADIOTAP_F_TX_NOACK
const char RADIOTAP_ACK[] = {
    0x00,                    // version
    0x00,                    // padding
    0x08, 0x00,              // length
    0x00, 0x00, 0x00, 0x00}; // no flags

void publish_frame(u_char *queue, const struct pcap_pkthdr *header, const u_char *packet) {
    reply = redisCommand(r, "PUBLISH %s.%s %b", mon_if, queue, packet, (size_t) header->len);
    if (reply != NULL) {
        freeReplyObject(reply);
    } else {
        fprintf(stderr, "[-] couldn't publish to rx_frame queue\n");
    }
}

void my_pcap_open_live() {
    handle = pcap_open_live(mon_if, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "[-] couldn't open monitoring interface (%s)\n", errbuf);
        exit(3);
    }
}

void my_redisConnect() {
    r = redisConnect(redis_host, redis_port);
    if (r == NULL || r->err) {
        if (r) {
            printf("Connection error: %s\n", r->errstr);
            redisFree(r);
        } else {
            printf("Connection error: can't allocate redis context\n");
        }
        pcap_close(handle);
        exit(4);
    }
}

void tx_frame() {
        unsigned char buf[8192] = {};
        unsigned int len_radiotap_hdr;

        // fill buf with radiotap header
        if (wait_for_ack) {
            len_radiotap_hdr = sizeof(RADIOTAP_ACK);
            memcpy(buf, RADIOTAP_ACK, len_radiotap_hdr);
        }
        else {
            len_radiotap_hdr = sizeof(RADIOTAP_NOACK);
            memcpy(buf, RADIOTAP_NOACK, len_radiotap_hdr);
        }

        my_pcap_open_live();
        my_redisConnect();

        reply = redisCommand(r, "SUBSCRIBE %s.tx_frame", mon_if);
        if (reply != NULL) {
            freeReplyObject(reply);
        } else {
            fprintf(stderr, "[-] couldn't subscribe to tx_frame queue\n");
            pcap_close(handle);
            exit(5);
        }

        while(redisGetReply(r,(void **)&reply) == REDIS_OK) {
            if (reply->type == REDIS_REPLY_ARRAY \
                    && reply->elements == 3 \
                    && reply->element[2]->type == REDIS_REPLY_STRING
                    && (len_radiotap_hdr + reply->element[2]->len) <= sizeof(buf)) {
                // TODO improve usage of constants
                memcpy((void *)&buf[len_radiotap_hdr], reply->element[2]->str, reply->element[2]->len);
                pcap_inject(handle, buf, reply->element[2]->len + len_radiotap_hdr);
            }
            else if (reply->type != REDIS_REPLY_ARRAY) {
                fprintf(stderr, "[-] expected redis array reply, but got type %u\n", reply->type);
            }
            else if (reply->elements != 3) {
                fprintf(stderr, "[-] expected redis array reply with 3 elements, but got %zu elements\n", reply->elements);
            }
            else if (reply->element[2]->type != REDIS_REPLY_STRING) {
                fprintf(stderr, "[-] expected redis array reply with 2nd element being string, but got type %d\n", reply->element[2]->type);
            }
            else if ((len_radiotap_hdr + reply->element[2]->len) <= sizeof(buf)) {
                fprintf(stderr, "[-] cannot handle frame of size %d\n", reply->element[2]->len);
            }

            freeReplyObject(reply);
        }
        pcap_close(handle);
}

void rx_frame(char *queue, char *filter) {
    struct bpf_program program;

    my_pcap_open_live();
    my_redisConnect();

    if (filter != NULL) {
        if (pcap_compile(handle, &program, filter, 1, PCAP_NETMASK_UNKNOWN) == -1) {
            fprintf(stderr, "[-] error calling pcap_compile\n");
            exit(6);
        }

        if (pcap_setfilter(handle, &program) == -1) {
            fprintf(stderr,"[-] error setting filter\n");
            exit(7);
        }
    }

    pcap_loop(handle, -1, publish_frame, (u_char *)queue);
}

int main(int argc, char *argv[]) {

    // cmd line parsing
    int c;
    while(true) {
        struct option long_options[] = {
            {"noack",      no_argument,       &wait_for_ack, 0},
            {"redis_host", required_argument, NULL,          'h'},
            {"redis_port", required_argument, NULL,          'p'},
            {"mon_if",     required_argument, NULL,          'm'},
            {0, 0, 0, 0}
        };

        int option_index = 0;

        c = getopt_long(argc, argv, "h:p:m:",long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 0:
                // nothing else to do for no_ack
                break;
            case 'h':
                redis_host = optarg;
                break;
            case 'm':
                mon_if = optarg;
                break;
            case 'p':
                redis_port = atoi(optarg);
                break;
            case '?':
                /* getopt_long already printed an error message. */
                printf("Usage: %s [OPTIONS]\n", argv[0]);
                printf("  -h, --redis_host <hostname> redis server hostname (default: 127.0.0.1)\n");
                printf("  -p, --redis_port <port>     redis server port (default: 6379)\n");
                printf("  -m, --mon_if <interface>    WLAN monitoring interface (default: mon0)\n");
                printf("      --no_ack                Don't wait for acknowledgment frames\n");

            default:
                exit(1);
        }
    }

    pid_t tx_frame_pid = fork();
    if (tx_frame_pid < 0) {
        fprintf(stderr, "[-] couldn't fork tx frame process\n");
        exit(1);
    }
    else if (tx_frame_pid == 0) {
        tx_frame();
        return 0;
    }

    int rx_cnt;
    for (rx_cnt = 0; queue_filter[rx_cnt].queue != NULL; rx_cnt++) {
        pid_t rx_pid = fork();
        if (rx_pid < 0) {
            fprintf(stderr, "[-] couldn't fork rx process\n");
            exit(1);
        }
        else if (rx_pid == 0) {
            rx_frame(queue_filter[rx_cnt].queue, queue_filter[rx_cnt].filter);
            return 0;
        }
    }

    waitpid(tx_frame_pid, NULL, 0);
    int i;
    for (i = 0; i < rx_cnt; i++) {
        waitpid(-1, NULL, 0);
    }

    return 0;
}
