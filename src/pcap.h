#pragma once

#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned char u_char;

typedef struct pcap pcap_t;

struct pcap_pkthdr {
    struct timeval ts;
    unsigned int caplen;
    unsigned int len;
};

struct pcap_addr {
    struct pcap_addr* next;
    struct sockaddr* addr;
    struct sockaddr* netmask;
    struct sockaddr* broadaddr;
    struct sockaddr* dstaddr;
};

typedef void (*pcap_handler)(u_char* user, const struct pcap_pkthdr* header, const u_char* bytes);

typedef struct pcap_if {
    struct pcap_if* next;
    char* name;
    char* description;
    struct pcap_addr* addresses;
    unsigned int flags;
} pcap_if_t;

typedef enum {
    PCAP_D_INOUT = 0,
    PCAP_D_IN,
    PCAP_D_OUT
} pcap_direction_t;

#define PCAP_ERRBUF_SIZE 256
#define PCAP_IF_LOOPBACK 0x00000001U
#define PCAP_IF_UP 0x00000002U
#define DLT_EN10MB 1

pcap_t* pcap_open_live(const char* device, int snaplen, int promisc, int to_ms, char* errbuf);
pcap_t* pcap_create(const char* source, char* errbuf);
int pcap_set_snaplen(pcap_t* p, int snaplen);
int pcap_set_promisc(pcap_t* p, int promisc);
int pcap_set_timeout(pcap_t* p, int to_ms);
int pcap_set_immediate_mode(pcap_t* p, int immediate_mode);
int pcap_activate(pcap_t* p);
int pcap_datalink(pcap_t* p);
const char* pcap_geterr(pcap_t* p);
void pcap_close(pcap_t* p);
int pcap_loop(pcap_t* p, int cnt, pcap_handler callback, u_char* user);
int pcap_dispatch(pcap_t* p, int cnt, pcap_handler callback, u_char* user);
int pcap_next_ex(pcap_t* p, struct pcap_pkthdr** header, const u_char** data);
int pcap_setnonblock(pcap_t* p, int nonblock, char* errbuf);
int pcap_setdirection(pcap_t* p, pcap_direction_t d);
int pcap_get_selectable_fd(pcap_t* p);
int pcap_breakloop(pcap_t* p);
int pcap_findalldevs(pcap_if_t** alldevs, char* errbuf);
void pcap_freealldevs(pcap_if_t* alldevs);

#ifdef __cplusplus
}
#endif