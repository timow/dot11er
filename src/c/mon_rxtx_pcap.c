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

int wait_for_ack_flag = 1;

void publish_frame(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    reply = redisCommand(r, "PUBLISH %s.rx_frame %b", mon_if, packet, (size_t) header->len);
    // TODO add proper error handling
    // TODO remove RadioTap
    freeReplyObject(reply);
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
        // TODO close pcap session
        exit(4);
    }
}

void tx_frame() {
/*        unsigned char buf[8192] = {0x00,                   // version*/
/*               0x00,                   // padding*/
/*               0x0a, 0x00,             // length*/
/*               0x00, 0x80, 0x00, 0x00, // IEEE80211_RADIOTAP_TX_FLAGS*/
/*               0x08, 0x00,             // IEEE80211_RADIOTAP_F_TX_NOACK*/
/*        };*/
        unsigned char buf[8192] = {0x00,                   // version
               0x00,                   // padding
               0x08, 0x00,             // length
               0x00, 0x00, 0x00, 0x00, // no flags
        };

        my_pcap_open_live();
        my_redisConnect();

        reply = redisCommand(r, "SUBSCRIBE %s.tx_frame", mon_if);
        // TODO add proper error handling
        freeReplyObject(reply);

        while(redisGetReply(r,(void **)&reply) == REDIS_OK) {
            if (reply->type == REDIS_REPLY_ARRAY && reply->elements == 3) {
                // TODO assert str type for element[2]
                // TODO assert len suitable for buf
                // TODO improve usage of constants
                // TODO address pcap_inject being a bottleneck
/*                memcpy((void *)&buf[10], reply->element[2]->str, reply->element[2]->len);*/
/*                pcap_inject(handle, buf, reply->element[2]->len + 10);*/
                memcpy((void *)&buf[8], reply->element[2]->str, reply->element[2]->len);
                pcap_inject(handle, buf, reply->element[2]->len + 8);
            }
            else if (reply->type != REDIS_REPLY_ARRAY) {
                fprintf(stderr, "[-] except redis array reply, but got type %u\n", reply->type);
            }
            else {
                fprintf(stderr, "[-] except redis array reply with 3 elements, but got %zu elements\n", reply->elements);
            }

            freeReplyObject(reply);
        }
}

void rx_frame() {
    my_pcap_open_live();
    my_redisConnect();
    pcap_loop(handle, -1, publish_frame, NULL);
}

int main(int argc, char *argv[]) {

    // cmd line parsing
    int c;
    while(true) {
        struct option long_options[] = {
            {"no_ack",     no_argument,       &wait_for_ack_flag, 0},
            {"redis_host", required_argument, NULL,               'h'},
            {"redis_port", required_argument, NULL,               'p'},
            {"mon_if",     required_argument, NULL,               'm'},
            {0, 0, 0, 0}
        };

        int option_index = 0;

        c = getopt_long(argc, argv, "h:m:",long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
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
                return(1);
        }
    }

    pid_t tx_frame_pid = fork();

    if (tx_frame_pid < 0) {
        fprintf(stderr, "[-] couldn't fork tx frame process\n");
        return(2);
    }
    else if (tx_frame_pid == 0) {
        tx_frame();
    }
    else {
        rx_frame();
        waitpid(tx_frame_pid, NULL, 0);
    }

    return 0;
}
