#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "ffrdp.h"

#ifdef CONFIG_ENABLE_AES256
#include <openssl/aes.h>
#endif

#ifdef WIN32
#include <winsock2.h>
#define usleep(t) Sleep((t) / 1000)
#define get_tick_count GetTickCount
#pragma warning(disable:4996) // disable warnings
#elif UNIX
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#define SOCKET int
#define closesocket close
#define stricmp strcasecmp
#define strtok_s strtok_r
static uint32_t get_tick_count()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}
#else
#include <systick.h>
#include <socket.h>
#include <utils.h>
#include <osi.h>
#define SOCKET int
#define closesocket close
#define stricmp strcasecmp
#define strtok_s strtok_r
#define free mem_Free
#define calloc mem_Malloc
#define malloc mem_Malloc
/*
 *  For clockId = CLOCK_REALTIME, clock_gettime() and clock_settime() use
 *  the BIOS Seconds module to get/set the time.  Before using clock_gettime()
 *  with clockId = CLOCK_REALTIME, the Seconds module must be initialized.
 *  This can be done by either calling clock_settime(CLOCK_REALTIME,...),
 *  or Seconds_set().
 *  For clockId = CLOCK_MONOTONIC, clock_gettime() returns a time based on
 *  ti.sysbios.knl.Clock ticks.
 */

static uint32_t local_clock = 0;

static void systick_handler(){
    local_clock ++;
}
static void systick_init(){
    SysTickIntRegister(systick_handler);
    SysTickPeriodSet(79999);//1ms
    SysTickIntEnable();
}
static uint32_t get_tick_count()
{
    return local_clock;
}

//add noblock attr to window size attr
#define SO_RCVBUF SL_SO_RCVBUF
#define SO_SNDBUF SL_SO_RCVBUF
void usleep(int pe){
    int cnt = (pe >> 1);
    for(int i = 0;i < cnt; i ++){
        //delay 2us
        UtilsDelay(21);
    }
}

//convet ip string to ip long
unsigned long inet_addr(const char *pIP)
{
  unsigned int uiTmp[4] = {0};
  unsigned long uiIp = 0;
  sscanf(pIP,"%u.%u.%u.%u",&(uiTmp[3]),&(uiTmp[2]),&(uiTmp[1]),&(uiTmp[0]));
  uiIp = ((uiTmp[0] << 24) | (uiTmp[1] << 16) | (uiTmp[2] << 8) | (uiTmp[3]));
  return uiIp;
}
#endif

#ifndef CC3200
#define FFRDP_MAX_MSS       (1500 - 8) // should align to 4 bytes and <= 1500 - 8
#define FFRDP_MIN_RTO        20
#define FFRDP_MAX_RTO        2000
#define FFRDP_MAX_WAITSND    256
#define FFRDP_QUERY_CYCLE    500
#define FFRDP_FLUSH_TIMEOUT  500
#define FFRDP_DEAD_TIMEOUT   5000
#define FFRDP_MIN_CWND_SIZE  1
#define FFRDP_DEF_CWND_SIZE  32
#define FFRDP_MAX_CWND_SIZE  64
#define FFRDP_RECVBUF_SIZE  (128 * (FFRDP_MAX_MSS + 0))
#define FFRDP_UDPSBUF_SIZE  (64  * (FFRDP_MAX_MSS + 6))
#define FFRDP_UDPRBUF_SIZE  (128 * (FFRDP_MAX_MSS + 6))
#define FFRDP_SELECT_SLEEP   0
#define FFRDP_SELECT_TIMEOUT 10000
#define FFRDP_USLEEP_TIMEOUT 1000
#else
#define FFRDP_MAX_MSS       (128) // should align to 4 bytes and <= 1500 - 8
#define FFRDP_MIN_RTO        20
#define FFRDP_MAX_RTO        2000
#define FFRDP_MAX_WAITSND    32
#define FFRDP_QUERY_CYCLE    500
#define FFRDP_FLUSH_TIMEOUT  500
#define FFRDP_DEAD_TIMEOUT   5000
#define FFRDP_MIN_CWND_SIZE  1
#define FFRDP_DEF_CWND_SIZE  32
#define FFRDP_MAX_CWND_SIZE  64
#define FFRDP_RECVBUF_SIZE  (4 * (FFRDP_MAX_MSS + 0))
#define FFRDP_UDPSBUF_SIZE  (2  * (FFRDP_MAX_MSS + 6))
#define FFRDP_UDPRBUF_SIZE  (4 * (FFRDP_MAX_MSS + 6))
#define FFRDP_SELECT_SLEEP   0
#define FFRDP_SELECT_TIMEOUT 10000
#define FFRDP_USLEEP_TIMEOUT 1000
#endif



#define MIN(a, b)               ((a) < (b) ? (a) : (b))
#define MAX(a, b)               ((a) > (b) ? (a) : (b))
#define GET_FRAME_SEQ(f)        (*(uint32_t*)(f)->data >> 8)
#define SET_FRAME_SEQ(f, seq)   do { *(uint32_t*)(f)->data = ((f)->data[0]) | (((seq) & 0xFFFFFF) << 8); } while (0)

enum {
    FFRDP_FRAME_TYPE_FULL,       // full  frame
    FFRDP_FRAME_TYPE_SHORT,      // short frame
    FFRDP_FRAME_TYPE_FEC2,       // fec2  frame
    FFRDP_FRAME_TYPE_FEC32 = 32, // fec32 frame
    FFRDP_FRAME_TYPE_ACK   = 33, // ack   frame
    FFRDP_FRAME_TYPE_QUERY = 34, // query frame
};

typedef struct tagFFRDP_FRAME_NODE {
    struct tagFFRDP_FRAME_NODE *next;
    struct tagFFRDP_FRAME_NODE *prev;
    uint16_t size; // frame size
    uint8_t *data; // frame data
    #define FLAG_FIRST_SEND     (1 << 0) // after frame first send, this flag will be set
    #define FLAG_TIMEOUT_RESEND (1 << 1) // data frame wait ack timeout and be resend
    #define FLAG_FAST_RESEND    (1 << 2) // data frame need fast resend when next update
    uint32_t flags;        // frame flags
    uint32_t tick_1sts;    // frame first time send tick
    uint32_t tick_send;    // frame send tick
    uint32_t tick_timeout; // frame ack timeout tick
} FFRDP_FRAME_NODE;

typedef struct {
    uint8_t  recv_buff[FFRDP_RECVBUF_SIZE];
    int32_t  recv_size, recv_head, recv_tail;
    #define FLAG_SERVER    (1 << 0)
    #define FLAG_CONNECTED (1 << 1)
    #define FLAG_FLUSH     (1 << 2)
    #define FLAG_TX_AES256 (1 << 3)
    #define FLAG_RX_AES256 (1 << 4)
    uint32_t flags;
    SOCKET   udp_fd;
    struct   sockaddr_in server_addr;
    struct   sockaddr_in client_addr;

    FFRDP_FRAME_NODE *send_list_head;
    FFRDP_FRAME_NODE *send_list_tail;
    FFRDP_FRAME_NODE *recv_list_head;
    FFRDP_FRAME_NODE *recv_list_tail;
    FFRDP_FRAME_NODE *cur_new_node;
    uint32_t          cur_new_size;
    uint32_t          cur_new_tick;
    uint32_t send_seq; // send seq
    uint32_t recv_seq; // send seq
    uint32_t wait_snd; // data frame number wait to send
    uint32_t rttm, rtts, rttd, rto;
    uint32_t rmss, smss, swnd, cwnd, ssthresh;
    uint32_t tick_recv_ack;
    uint32_t tick_send_query;
    uint32_t tick_ffrdp_dump;

    uint8_t  fec_txbuf[4 + FFRDP_MAX_MSS + 2];
    uint8_t  fec_rxbuf[4 + FFRDP_MAX_MSS + 2];
    uint8_t  fec_txredundancy, fec_rxredundancy;
    uint16_t fec_txseq;
    uint16_t fec_rxseq;
    uint16_t fec_rxcnt;
    uint32_t fec_rxmask;

#ifdef CONFIG_ENABLE_AES256
    AES_KEY  aes_encrypt_key;
    AES_KEY  aes_decrypt_key;
#endif

    uint32_t counter_send_bytes;
    uint32_t counter_recv_bytes;
    uint32_t counter_send_1sttime;
    uint32_t counter_send_failed;
    uint32_t counter_send_query;
    uint32_t counter_resend_fast;
    uint32_t counter_resend_rto;
    uint32_t counter_reach_maxrto;
    uint32_t counter_txfull , counter_rxfull ;
    uint32_t counter_txshort, counter_rxshort;
    uint32_t counter_fec_tx;
    uint32_t counter_fec_rx;
    uint32_t counter_fec_ok;
    uint32_t counter_fec_failed;
    uint32_t reserved;
} FFRDPCONTEXT;

static uint32_t ringbuf_write(uint8_t *rbuf, uint32_t maxsize, uint32_t tail, uint8_t *src, uint32_t len)
{
    uint8_t *buf1 = rbuf + tail;
    int      len1 = MIN(maxsize-tail, len);
    uint8_t *buf2 = rbuf;
    int      len2 = len  - len1;
    memcpy(buf1, src + 0   , len1);
    memcpy(buf2, src + len1, len2);
    return len2 ? len2 : tail + len1;
}

static uint32_t ringbuf_read(uint8_t *rbuf, uint32_t maxsize, uint32_t head, uint8_t *dst, uint32_t len)
{
    uint8_t *buf1 = rbuf + head;
    int      len1 = MIN(maxsize-head, len);
    uint8_t *buf2 = rbuf;
    int      len2 = len  - len1;
    if (dst) memcpy(dst + 0   , buf1, len1);
    if (dst) memcpy(dst + len1, buf2, len2);
    return len2 ? len2 : head + len1;
}

static int seq_distance(uint32_t seq1, uint32_t seq2) // calculate seq distance
{
    int c = seq1 - seq2;
    if      (c >=  0x7FFFFF) return c - 0x1000000;
    else if (c <= -0x7FFFFF) return c + 0x1000000;
    else return c;
}

static FFRDP_FRAME_NODE* frame_node_new(int type, int size) // create a new frame node
{
    FFRDP_FRAME_NODE *node = malloc(sizeof(FFRDP_FRAME_NODE) + 4 + size + (type <= FFRDP_FRAME_TYPE_SHORT ? 0 : 2));
    if (!node) return NULL;
    memset(node, 0, sizeof(FFRDP_FRAME_NODE));
    node->size    = 4 + size + (type <= FFRDP_FRAME_TYPE_SHORT ? 0 : 2);
    node->data    = (uint8_t*)node + sizeof(FFRDP_FRAME_NODE);
    node->data[0] = type;
    return node;
}

#ifdef CONFIG_ENABLE_AES256
static void frame_node_encrypt(FFRDP_FRAME_NODE *node, AES_KEY *key, int enc)
{
    uint8_t *pdata = node->data + 4, *pend = node->data + node->size - (node->data[0] <= FFRDP_FRAME_TYPE_SHORT ? 0 : 2) - AES_BLOCK_SIZE;
    while (pdata <= pend) {
        AES_ecb_encrypt(pdata, pdata, key, enc);
        pdata += AES_BLOCK_SIZE;
    }
}
#endif

static int frame_payload_size(FFRDP_FRAME_NODE *node) {
    return  node->size - 4 - (node->data[0] <= FFRDP_FRAME_TYPE_SHORT ? 0 : 2);
}

static void list_enqueue(FFRDP_FRAME_NODE **head, FFRDP_FRAME_NODE **tail, FFRDP_FRAME_NODE *node)
{
    FFRDP_FRAME_NODE *p;
    uint32_t seqnew, seqcur;
    int      dist;
    if (*head == NULL) {
        *head = node;
        *tail = node;
    } else {
        seqnew = GET_FRAME_SEQ(node);
        for (p=*tail; p; p=p->prev) {
            seqcur = GET_FRAME_SEQ(p);
            dist   = seq_distance(seqnew, seqcur);
            if (dist == 0) return;
            if (dist >  0) {
                //insert nodes after p;
                if (p->next) p->next->prev = node;
                else *tail = node;
                node->next = p->next;
                node->prev = p;
                p->next    = node;
                return;
            }
        }
        //seqnew is smaller than everyone else
        node->next = *head;
        node->next->prev = node;
        *head = node;
    }
}

static void list_remove(FFRDP_FRAME_NODE **head, FFRDP_FRAME_NODE **tail, FFRDP_FRAME_NODE *node)
{
    if (node->next) node->next->prev = node->prev;
    else *tail = node->prev;
    if (node->prev) node->prev->next = node->next;
    else *head = node->next;
    free(node);
}

static void list_free(FFRDP_FRAME_NODE **head, FFRDP_FRAME_NODE **tail)
{
    while (*head) list_remove(head, tail, *head);
}

static int ffrdp_sleep(FFRDPCONTEXT *ffrdp, int flag)
{
    if (ffrdp->flags & FLAG_FLUSH) { ffrdp->flags &= ~FLAG_FLUSH; return 0; }
    if (flag) {
        struct timeval tv;
        fd_set  rs;
        FD_ZERO(&rs);
        FD_SET(ffrdp->udp_fd, &rs);
        tv.tv_sec  = 0;
        tv.tv_usec = FFRDP_SELECT_TIMEOUT;
        if (select((int)ffrdp->udp_fd + 1, &rs, NULL, NULL, &tv) <= 0) return -1;
    } else usleep(FFRDP_USLEEP_TIMEOUT);
    return 0;
}

static int ffrdp_send_data_frame(FFRDPCONTEXT *ffrdp, FFRDP_FRAME_NODE *frame, struct sockaddr_in *dstaddr)
{
    _i16 ret = 0;
    switch (frame->size - ffrdp->smss) {
    case 6 : ffrdp->counter_fec_tx ++; *(uint16_t*)(frame->data + 4 + ffrdp->smss) = ffrdp->fec_txseq++; break; // tx fec frame
    case 4 : ffrdp->counter_txfull ++; break; // tx full  frame
    default: ffrdp->counter_txshort++; break; // tx short frame
    }
    if (sendto(ffrdp->udp_fd, frame->data, frame->size, 0, (struct sockaddr*)dstaddr, sizeof(struct sockaddr_in)) != frame->size) return -1;
    if (frame->size == 4 + ffrdp->smss + 2) { // fec frame
        uint32_t *psrc = (uint32_t*)frame->data, *pdst = (uint32_t*)ffrdp->fec_txbuf, i;
        for (i=0; i<(4+ffrdp->smss)/sizeof(uint32_t); i++) *pdst++ ^= *psrc++; // make xor fec frame
        if ((ffrdp->fec_txseq % ffrdp->fec_txredundancy) == ffrdp->fec_txredundancy - 1) {
            *(uint16_t*)(ffrdp->fec_txbuf + 4 + ffrdp->smss) = ffrdp->fec_txseq++; ffrdp->fec_txbuf[0] = ffrdp->fec_txredundancy;
            sendto(ffrdp->udp_fd, ffrdp->fec_txbuf, frame->size, 0, (struct sockaddr*)dstaddr, sizeof(struct sockaddr_in)); // send fec frame
            memset(ffrdp->fec_txbuf, 0, sizeof(ffrdp->fec_txbuf)); // clear tx_fecbuf
            ffrdp->counter_fec_tx++;
        }
    }
    return 0;
}

static int ffrdp_recv_data_frame(FFRDPCONTEXT *ffrdp, FFRDP_FRAME_NODE *frame)
{
    uint32_t fecseq, fecrdc, *psrc, *pdst, type, i;
    switch (frame->data[0]) {
    case FFRDP_FRAME_TYPE_SHORT: ffrdp->counter_rxshort++; return 0; // short frame
    case FFRDP_FRAME_TYPE_FULL : ffrdp->counter_rxfull ++; ffrdp->rmss = frame->size - 4; return 0; // full frame
    default:                     ffrdp->counter_fec_rx ++; ffrdp->rmss = frame->size - 6; break;    // fec  frame
    }
    fecseq = *(uint16_t*)(frame->data + frame->size - 2);
    fecrdc = frame->data[0];
    if (fecseq / fecrdc != ffrdp->fec_rxseq / fecrdc || ffrdp->fec_rxredundancy != fecrdc) { // group changed or fec_rxredundancy changed
        memcpy(ffrdp->fec_rxbuf, frame->data, frame->size);
        ffrdp->fec_rxseq = fecseq; ffrdp->fec_rxmask = 1 << (fecseq % fecrdc); ffrdp->fec_rxcnt = 1; ffrdp->fec_rxredundancy = fecrdc;
        return fecseq % fecrdc != fecrdc - 1 ? 0 : -1;
    } else ffrdp->fec_rxseq = fecseq; // group not changed
    if (fecseq % fecrdc == fecrdc - 1) { // it's redundance frame
        if (ffrdp->fec_rxcnt == fecrdc - 1) return -1;
        if (ffrdp->fec_rxcnt != fecrdc - 2) { ffrdp->counter_fec_failed++; return -1; }
        type = frame->data[0];
        psrc = (uint32_t*)ffrdp->fec_rxbuf; pdst = (uint32_t*)frame->data;
        for (i=0; i<(frame->size-2)/sizeof(uint32_t); i++) *pdst++ ^= *psrc++;
        frame->data[0] = type;
        ffrdp->counter_fec_ok ++;
    } else if (!(ffrdp->fec_rxmask & (1 << (fecseq % fecrdc)))) { // update fec_rxbuf
        psrc = (uint32_t*)frame->data; pdst = (uint32_t*)ffrdp->fec_rxbuf;
        for (i=0; i<(frame->size-2)/sizeof(uint32_t); i++) *pdst++ ^= *psrc++;
        ffrdp->fec_rxmask |= 1 << (fecseq % fecrdc); ffrdp->fec_rxcnt++;
    }
    return 0;
}

/*
    ip : 本地ip地址
    port : 本地端口
    txkey : 加密密钥
    rxkey : 解密密钥
    server : > 0 为server
    smss : 片最大长�?
    sfec : FEC纠错模式
*/


void* ffrdp_init(const char *ip,const int port, char *txkey, char *rxkey, int server, int smss, int sfec)
{
#ifdef WIN32
    WSADATA wsaData;
#endif
    unsigned long opt;
    FFRDPCONTEXT *ffrdp = malloc(sizeof(FFRDPCONTEXT));
    if (!ffrdp) return NULL;
#ifdef WIN32
    timeBeginPeriod(1);
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed !\n");
        return NULL;
    }
#elif CC3200
    systick_init();
#endif

    ffrdp->swnd     = FFRDP_DEF_CWND_SIZE;
    ffrdp->cwnd     = FFRDP_DEF_CWND_SIZE;
    ffrdp->ssthresh = FFRDP_DEF_CWND_SIZE;
    ffrdp->rtts     = (uint32_t) -1;
    ffrdp->rto      = FFRDP_MIN_RTO;
    ffrdp->rmss     = FFRDP_MAX_MSS;
     //limit the value of smss
    ffrdp->smss     = MAX(1, MIN(smss, FFRDP_MAX_MSS));
     //limit the value of sfec
    ffrdp->fec_txredundancy = MAX(0, MIN(sfec, FFRDP_FRAME_TYPE_FEC32));
    ffrdp->tick_ffrdp_dump  = get_tick_count();
    ffrdp->server_addr.sin_family      = AF_INET;
    ffrdp->server_addr.sin_port        = htons(port);
    ffrdp->server_addr.sin_addr.s_addr = inet_addr(ip);
    ffrdp->udp_fd = socket(AF_INET, SOCK_DGRAM, 0);

    ffrdp->send_list_head = NULL;
    ffrdp->cur_new_node = NULL;
    ffrdp->send_list_tail = NULL;
    ffrdp->recv_list_head = NULL;
    ffrdp->recv_list_tail = NULL;
    ffrdp->cur_new_size = 0;
    if (ffrdp->udp_fd < 0) {
        printf("failed to open socket !\n");
        goto failed;
    }

#ifdef WIN32
    // setup non-block io mode
    opt = 1; ioctlsocket(ffrdp->udp_fd, FIONBIO, &opt);
#elif UNIX
    // setup non-block io mode
    fcntl(ffrdp->udp_fd, F_SETFL, fcntl(ffrdp->udp_fd, F_GETFL, 0) | O_NONBLOCK);
#else
    //setup non-block io mode
    opt = 1;
    sl_SetSockOpt(ffrdp->udp_fd, SL_SOL_SOCKET, SL_SO_NONBLOCKING,&opt, sizeof(opt));
#endif
    opt = FFRDP_UDPSBUF_SIZE; setsockopt(ffrdp->udp_fd, SOL_SOCKET, SO_SNDBUF   , (char*)&opt, sizeof(int)); // setup udp send buffer size
    opt = FFRDP_UDPRBUF_SIZE; setsockopt(ffrdp->udp_fd, SOL_SOCKET, SO_RCVBUF   , (char*)&opt, sizeof(int)); // setup udp recv buffer size
#ifndef CC3200
    opt = 1;                  setsockopt(ffrdp->udp_fd, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(int)); // setup reuse addr
#endif

    if (server) {
        ffrdp->flags |= FLAG_SERVER;
        if (bind(ffrdp->udp_fd, (struct sockaddr*)&ffrdp->server_addr, sizeof(ffrdp->server_addr)) == -1) {
            printf("failed to bind !\n");
            goto failed;
        }
    }

    if (txkey) {
#ifdef CONFIG_ENABLE_AES256
        ffrdp->flags |= FLAG_TX_AES256;
        AES_set_encrypt_key((uint8_t*)txkey, 256, &ffrdp->aes_encrypt_key);
#endif
    }
    if (rxkey) {
#ifdef CONFIG_ENABLE_AES256
        ffrdp->flags |= FLAG_RX_AES256;
        AES_set_decrypt_key((uint8_t*)rxkey, 256, &ffrdp->aes_decrypt_key);
#endif
    }
    return ffrdp;

failed:
    if (ffrdp->udp_fd > 0) closesocket(ffrdp->udp_fd);
    free(ffrdp);
    return NULL;
}

void ffrdp_free(void *ctxt)
{
    FFRDPCONTEXT *ffrdp = (FFRDPCONTEXT*)ctxt;
    if (!ctxt) return;
    if (ffrdp->udp_fd > 0) closesocket(ffrdp->udp_fd);
    if (ffrdp->cur_new_node) free(ffrdp->cur_new_node);
    list_free(&ffrdp->send_list_head, &ffrdp->send_list_tail);
    list_free(&ffrdp->recv_list_head, &ffrdp->recv_list_tail);
    free(ffrdp);
#ifdef WIN32
    WSACleanup();
    timeEndPeriod(1);
#endif
}

int ffrdp_send(void *ctxt, char *buf, int len)
{
    FFRDPCONTEXT *ffrdp = (FFRDPCONTEXT*)ctxt;
    int           n = len, size;
    if (!ffrdp) {
        if (ffrdp) ffrdp->counter_send_failed++;
        printf("err: null eegRudp");
        return -1;
    }
    while (n > 0) {
        if (!ffrdp->cur_new_node) ffrdp->cur_new_node = frame_node_new(ffrdp->fec_txredundancy, ffrdp->smss);
        if (!ffrdp->cur_new_node) break;
        else SET_FRAME_SEQ(ffrdp->cur_new_node, ffrdp->send_seq);
        size = MIN(n, (unsigned int)(ffrdp->smss - ffrdp->cur_new_size));
        memcpy(ffrdp->cur_new_node->data + 4 + ffrdp->cur_new_size, buf, size);
        ffrdp->cur_new_size += size; buf += size; n -= size;
        if (ffrdp->cur_new_size == ffrdp->smss) {
#ifdef CONFIG_ENABLE_AES256
            if ((ffrdp->flags & FLAG_TX_AES256)) frame_node_encrypt(ffrdp->cur_new_node, &ffrdp->aes_encrypt_key, AES_ENCRYPT);
#endif
            list_enqueue(&ffrdp->send_list_head, &ffrdp->send_list_tail, ffrdp->cur_new_node);
            ffrdp->send_seq++; ffrdp->wait_snd++;
            ffrdp->cur_new_node = NULL;
            ffrdp->cur_new_size = 0;
        }else{
            ffrdp->cur_new_tick = get_tick_count();
        }
    }
    return len - n;
}

int ffrdp_recv(void *ctxt, char *buf, int len)
{
    FFRDPCONTEXT *ffrdp = (FFRDPCONTEXT*)ctxt;
    int           ret;
    if (!ctxt) return -1;
    ret = MIN(len, ffrdp->recv_size);
    if (ret > 0) {
        ffrdp->recv_head = ringbuf_read(ffrdp->recv_buff, sizeof(ffrdp->recv_buff), ffrdp->recv_head, (uint8_t*)buf, ret);
        ffrdp->recv_size-= ret; ffrdp->counter_recv_bytes += ret;
    }
    return ret;
}

int ffrdp_isdead(void *ctxt)
{
    FFRDPCONTEXT *ffrdp = (FFRDPCONTEXT*)ctxt;
    if (!ctxt) return -1;
    if (!ffrdp->send_list_head) return 0;
    if (ffrdp->send_list_head->flags & FLAG_FIRST_SEND) {
        return (int32_t)get_tick_count() - (int32_t)ffrdp->send_list_head->tick_1sts > FFRDP_DEAD_TIMEOUT;
    } else {
        return (int32_t)ffrdp->tick_send_query - (int32_t)ffrdp->tick_recv_ack > FFRDP_DEAD_TIMEOUT;
    }
}

static void ffrdp_recvdata_and_sendack(FFRDPCONTEXT *ffrdp, struct sockaddr_in *dstaddr)
{
    FFRDP_FRAME_NODE *p;
    int32_t dist, size, i;
    uint8_t data[8];
    while (ffrdp->recv_list_head) {
        dist = seq_distance(GET_FRAME_SEQ(ffrdp->recv_list_head), ffrdp->recv_seq);
        if (dist == 0 && (size = frame_payload_size(ffrdp->recv_list_head)) <= (int)(sizeof(ffrdp->recv_buff) - ffrdp->recv_size)) {
#ifdef CONFIG_ENABLE_AES256
            if ((ffrdp->flags & FLAG_RX_AES256)) frame_node_encrypt(ffrdp->recv_list_head, &ffrdp->aes_decrypt_key, AES_DECRYPT);
#endif
            ffrdp->recv_tail = ringbuf_write(ffrdp->recv_buff, sizeof(ffrdp->recv_buff), ffrdp->recv_tail, ffrdp->recv_list_head->data + 4, size);
            ffrdp->recv_size+= size;
            ffrdp->recv_seq++; ffrdp->recv_seq &= 0xFFFFFF;
            list_remove(&ffrdp->recv_list_head, &ffrdp->recv_list_tail, ffrdp->recv_list_head);
        } else break;
    }
//    for (recv_mack=0,i=0,p=ffrdp->recv_list_head; i<=24&&p; i++,p=p->next) {
//        dist = seq_distance(GET_FRAME_SEQ(p), ffrdp->recv_seq);
//        if (dist <= 24) recv_mack |= 1 << (dist - 1); // dist is obviously > 0
//    }
//    recv_wnd = (sizeof(ffrdp->recv_buff) - ffrdp->recv_size) / ffrdp->rmss;
//    recv_wnd = MIN(recv_wnd, 255);
//    *(uint32_t*)(data + 0) = (FFRDP_FRAME_TYPE_ACK << 0) | (ffrdp->recv_seq << 8);
//    *(uint32_t*)(data + 4) = (recv_mack <<  0);
//    *(uint32_t*)(data + 4)|= (recv_wnd  << 24);
//    sendto(ffrdp->udp_fd, data, sizeof(data), 0, (struct sockaddr*)dstaddr, sizeof(struct sockaddr_in)); // send ack frame
}

void ffrdp_update(void *ctxt)
{
    FFRDPCONTEXT       *ffrdp   = (FFRDPCONTEXT*)ctxt;
    FFRDP_FRAME_NODE   *node    = NULL, *p = NULL, *t = NULL;
    struct sockaddr_in *dstaddr = NULL, srcaddr;
#ifndef CC3200
    uint32_t addrlen = sizeof(srcaddr);
#else
    uint16_t addrlen = sizeof(srcaddr);
#endif
    int32_t  ret, got_data = 0,i;
    
    int32_t node_cnt = 0;
    
    if (!ctxt) return;
    //dstaddr  = ffrdp->flags & FLAG_SERVER ? &ffrdp->client_addr : &ffrdp->server_addr;
    dstaddr = &ffrdp->server_addr;
    //send_list_head 为最老数据
    for (i=0,p=ffrdp->send_list_head; i<(int32_t)ffrdp->cwnd&&p; i++) {
         ffrdp_send_data_frame(ffrdp, p, dstaddr);
         t = p; p = p->next; list_remove(&ffrdp->send_list_head, &ffrdp->send_list_tail, t); 
    }
    
    if (ffrdp_sleep(ffrdp, FFRDP_SELECT_SLEEP) != 0) return;
    for (node=NULL;;) { // receive data
        if (!node && !(node = frame_node_new(FFRDP_FRAME_TYPE_FEC2, ffrdp->smss))) break;  //判断是否是空
        if ((ret = recvfrom(ffrdp->udp_fd, node->data, node->size, 0, (struct sockaddr*)&srcaddr, &addrlen)) <= 0) break;
        if ((ffrdp->flags & FLAG_SERVER) && (ffrdp->flags & FLAG_CONNECTED) == 0) {
            if (ffrdp->flags & FLAG_CONNECTED) {
                if (memcmp(&srcaddr, &ffrdp->client_addr, sizeof(srcaddr)) != 0) continue;
            } else {
                ffrdp->flags |= FLAG_CONNECTED;
                memcpy(&ffrdp->client_addr, &srcaddr, sizeof(ffrdp->client_addr));
            }
        }

        if (node->data[0] <= FFRDP_FRAME_TYPE_FEC32) { // data frame
            node->size = ret; // frame size is the return size of recvfrom
            if (ffrdp_recv_data_frame(ffrdp, node) == 0) {
                list_enqueue(&ffrdp->recv_list_head, &ffrdp->recv_list_tail, node); node = NULL;
                got_data = 1;
            }
        }
    }
    if (node)  free(node);
    if (got_data) ffrdp_recvdata_and_sendack(ffrdp, dstaddr); // send ack frame
    //usleep(1000);
}

void ffrdp_flush(void *ctxt)
{
    FFRDPCONTEXT *ffrdp = (FFRDPCONTEXT*)ctxt;
    if (ffrdp) ffrdp->flags |= FLAG_FLUSH;
}

void ffrdp_dump(void *ctxt, int clearhistory)
{
    FFRDPCONTEXT *ffrdp = (FFRDPCONTEXT*)ctxt; int secs;
    if (!ctxt) return;
    secs = ((int32_t)get_tick_count() - (int32_t)ffrdp->tick_ffrdp_dump) / 1000;
    secs = secs ? secs : 1;
    printf("rttm: %u, rtts: %u, rttd: %u, rto: %u\n", ffrdp->rttm, ffrdp->rtts, ffrdp->rttd, ffrdp->rto);
    printf("total_send, total_recv: %.2fMB, %.2fMB\n"    , ffrdp->counter_send_bytes / (1024.0 * 1024), ffrdp->counter_recv_bytes / (1024.0 * 1024));
    printf("averg_send, averg_recv: %.2fKB/s, %.2fKB/s\n", ffrdp->counter_send_bytes / (1024.0 * secs), ffrdp->counter_recv_bytes / (1024.0 * secs));
    printf("recv_size           : %d\n"  , ffrdp->recv_size           );
    printf("flags               : %x\n"  , ffrdp->flags               );
    printf("send_seq            : %u\n"  , ffrdp->send_seq            );
    printf("recv_seq            : %u\n"  , ffrdp->recv_seq            );
    printf("wait_snd            : %u\n"  , ffrdp->wait_snd            );
    printf("rmss, smss          : %u, %u\n"    , ffrdp->rmss, ffrdp->smss);
    printf("swnd, cwnd, ssthresh: %u, %u, %u\n", ffrdp->swnd, ffrdp->cwnd, ffrdp->ssthresh);
    printf("fec_txredundancy    : %d\n"  , ffrdp->fec_txredundancy    );
    printf("fec_rxredundancy    : %d\n"  , ffrdp->fec_rxredundancy    );
    printf("fec_txseq           : %d\n"  , ffrdp->fec_txseq           );
    printf("fec_rxseq           : %d\n"  , ffrdp->fec_rxseq           );
    printf("fec_rxmask          : %08x\n", ffrdp->fec_rxmask          );
    printf("counter_send_1sttime: %u\n"  , ffrdp->counter_send_1sttime);
    printf("counter_send_failed : %u\n"  , ffrdp->counter_send_failed );
    printf("counter_send_query  : %u\n"  , ffrdp->counter_send_query  );
    printf("counter_resend_rto  : %u\n"  , ffrdp->counter_resend_rto  );
    printf("counter_resend_fast : %u\n"  , ffrdp->counter_resend_fast );
    printf("counter_resend_ratio: %.2f%%\n", 100.0 * (ffrdp->counter_resend_rto + ffrdp->counter_resend_fast) / MAX(ffrdp->counter_send_1sttime, 1));
    printf("counter_reach_maxrto: %u\n"  , ffrdp->counter_reach_maxrto);
    printf("counter_txfull      : %u\n"  , ffrdp->counter_txfull      );
    printf("counter_txshort     : %u\n"  , ffrdp->counter_txshort     );
    printf("counter_rxfull      : %u\n"  , ffrdp->counter_rxfull      );
    printf("counter_rxshort     : %u\n"  , ffrdp->counter_rxshort     );
    printf("counter_fec_tx      : %u\n"  , ffrdp->counter_fec_tx      );
    printf("counter_fec_rx      : %u\n"  , ffrdp->counter_fec_rx      );
    printf("counter_fec_ok      : %u\n"  , ffrdp->counter_fec_ok      );
    printf("counter_fec_failed  : %u\n\n", ffrdp->counter_fec_failed  );
    if (secs > 1 && clearhistory) {
        ffrdp->tick_ffrdp_dump = get_tick_count();
        memset(&ffrdp->counter_send_bytes, 0, (uint8_t*)&ffrdp->reserved - (uint8_t*)&ffrdp->counter_send_bytes);
    }
}
