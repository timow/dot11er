#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/wait.h>

#include <arpa/inet.h>

#include <pcap.h>
#include <hiredis/hiredis.h>

char *mon_if = NULL;
pcap_t *handle = NULL;

redisContext *r = NULL;
redisReply *reply;

void rx_frame(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    reply = redisCommand(r, "PUBLISH %s.rx_frame %b", mon_if, packet, (size_t) header->len);
    // TODO add proper error handling
    // TODO check whether pipelining allows to improve performance
    // TODO remove RadioTap
    freeReplyObject(reply);
}

void my_pcap_open_live(const char *device, char *errbuf) {
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "[-] couldn't open monitoring interface (%s)\n", errbuf);
        exit(2);
    }
}

void my_redisConnect(const char *ip, int port) {
    r = redisConnect(ip, port);
    if (r == NULL || r->err) {
        if (r) {
            printf("Connection error: %s\n", r->errstr);
            redisFree(r);
        } else {
            printf("Connection error: can't allocate redis context\n");
        }
        // TODO close pcap session
        exit(3);
    }
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];

    // TODO improve cmd line handling
    mon_if = (argc > 1) ? argv[1] : "mon0"; 
    const char *hostname = (argc > 2) ? argv[2] : "127.0.0.1";
    int port = (argc > 3) ? atoi(argv[3]) : 6379;

    // fork tx process
    pid_t tx_pid = fork();
    if (tx_pid < 0) {
        fprintf(stderr, "[-] couldn't fork tx process\n");
        return(1);
    }
    else if (tx_pid == 0) { // tx process
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

        my_pcap_open_live(mon_if, errbuf);
        my_redisConnect(hostname, port);

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
    else { // rx process
        my_pcap_open_live(mon_if, errbuf);
        my_redisConnect(hostname, port);
        pcap_loop(handle, -1, rx_frame, NULL);
        waitpid(tx_pid, NULL, 0);
    }

    return 0;
}
