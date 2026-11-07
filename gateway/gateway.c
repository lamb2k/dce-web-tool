/* Private per-lease Ethernet gateway. See README.md for trusted launcher ABI. */
#define _POSIX_C_SOURCE 200809L
#include <libslirp.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#define FRAME_MAX 1514
#define QUEUE_MAX 32
#define FLOW_MAX 32
#define FLOW_IDLE_MS 20000 /* Outlasts the game's 15 s drop timer. */
#define POLL_MAX 64
#define TLS_FLOWS 8
#define TLS_OPEN_QUIET_MS 180000
#define TLS_HELLO_MAX 8192
#define TLS_FRAMES 8
static const uint8_t guest_mac[6] = {0x0c,0x0a,0x0f,0x0e,0,0};
static volatile sig_atomic_t stopped;
typedef struct { uint8_t bytes[FRAME_MAX+2]; size_t n, sent; int64_t born; } Frame;
typedef struct { uint32_t ip; uint16_t port; int64_t seen; } Peer;
typedef struct { uint32_t ip; uint16_t port; int64_t expires; } CatalogPeer;
typedef struct { SlirpTimerCb cb; void *arg; int64_t at; int used; } Timer;
typedef struct {
    uint16_t port; uint32_t initial, next, server_next; int state, synacked;
    int64_t seen; size_t used; unsigned frames;
    uint8_t hello[TLS_HELLO_MAX]; Frame held[TLS_FRAMES];
} TlsFlow;
typedef struct {
    Slirp *slirp;
    struct in_addr guest, router, dest;
    unsigned port, forward, seconds;
    int native, host, join_only, failed;
    uint32_t relay_ip; unsigned relay_port;
    Frame queue[QUEUE_MAX]; unsigned head, count;
    Peer peers[FLOW_MAX]; Peer flows[FLOW_MAX]; Timer timers[8];
    struct pollfd fds[POLL_MAX]; int nfds;
    uint64_t accepted, refused, sent, dropped;
    int64_t rate_epoch; unsigned rate_count;
    char directory_host[254]; struct in_addr directory_ip,dns;
    TlsFlow tls[TLS_FLOWS];
    int control; uint32_t catalog_generation; CatalogPeer catalog[32];
} Gateway;
static uint16_t be16(const uint8_t *p) { return (uint16_t)((p[0]<<8)|p[1]); }
static uint32_t ip32(const uint8_t *p) { uint32_t v; memcpy(&v,p,4); return v; }
static uint32_t be32(const uint8_t *p) { return (uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|p[3]; }
static void put16(uint8_t *p,unsigned v) { p[0]=(uint8_t)(v>>8);p[1]=(uint8_t)v; }
static int64_t now_ns(void *unused) {
    struct timespec t; (void)unused; clock_gettime(CLOCK_MONOTONIC,&t);
    return (int64_t)t.tv_sec*1000000000+t.tv_nsec;
}
static int64_t now_ms(void) { return now_ns(NULL)/1000000; }
static unsigned sum_bytes(const uint8_t *p,size_t n,unsigned sum) {
    while(n>1) { sum+=be16(p); p+=2; n-=2; }
    if(n) sum+=(unsigned)*p<<8;
    while(sum>>16) sum=(sum&65535)+(sum>>16);
    return sum;
}
static int checksum_ok(const uint8_t *p,size_t n) { return sum_bytes(p,n,0)==65535; }
static int transport_checksum(const uint8_t *f,unsigned total) {
    return sum_bytes(f+34,total-20,sum_bytes(f+26,8,f[23]+total-20))==65535;
}
static int same(const void *a,const void *b,size_t n) { return memcmp(a,b,n)==0; }
/* HALO_GATEWAY_ROUTE_ALLOW, operator set, off unless set: "name=ip:port/t,=ip:port/u", at most
   ROUTE_MAX exact tuples a guest may reach from any source port. A name also answers in DNS.
   Nothing here comes from a guest or a browser. */
#define ROUTE_MAX 6
#define ROUTE_TCP_SYNS 8u         /* the route tries one broker, with retries */
#define ROUTE_TCP_BYTES (256u*1024u)
typedef struct { char name[64]; uint32_t ip; uint16_t port; uint8_t proto; } RouteAllow;
static RouteAllow route_allow[ROUTE_MAX]; static unsigned route_allow_count;
static int route_allowed(uint32_t ip,unsigned port,unsigned proto) {
    for(unsigned i=0;i<route_allow_count;i++)
        if(route_allow[i].ip==ip && route_allow[i].port==port && route_allow[i].proto==proto)return 1;
    return 0;
}
static int route_parse(const char *text) {
    char copy[512],*save=NULL;
    if(strlen(text)>=sizeof copy)return 0;
    strcpy(copy,text);
    for(char *item=strtok_r(copy,",",&save);item;item=strtok_r(NULL,",",&save)) {
        char *eq=strchr(item,'='),*colon,*slash;
        if(!eq || route_allow_count>=ROUTE_MAX)return 0;
        RouteAllow *r=&route_allow[route_allow_count];
        size_t len=(size_t)(eq-item);
        if(len>=sizeof r->name)return 0;
        memcpy(r->name,item,len);r->name[len]=0;
        for(size_t i=0;i<len;i++)if(!((item[i]>='a' && item[i]<='z') || (item[i]>='0' && item[i]<='9') ||
            item[i]=='-' || item[i]=='.'))return 0;
        colon=strchr(eq+1,':');slash=colon?strchr(colon,'/'):NULL;
        if(!colon || !slash)return 0;
        *colon=0;*slash=0;
        struct in_addr a;
        if(inet_pton(AF_INET,eq+1,&a)!=1)return 0;
        uint32_t h=ntohl(a.s_addr);
        if((h>>24)==0 || (h>>24)==127 || (h>>24)>=224 || (h&0xffff0000)==0xa9fe0000 || (h&0xffff0000)==0x0a4d0000)return 0;
        char *end;long port=strtol(colon+1,&end,10);
        if(*end || port<1 || port>65535)return 0;
        if(strcmp(slash+1,"t") && strcmp(slash+1,"u"))return 0;
        r->ip=a.s_addr;r->port=(uint16_t)port;r->proto=slash[1]=='t'?6:17;
        route_allow_count++;
    }
    return route_allow_count>0;
}
static int peer_allowed(Gateway *g,uint32_t ip,unsigned port) {
    for(unsigned i=0;i<FLOW_MAX;i++)
        if(g->peers[i].ip==ip && g->peers[i].port==port &&
           now_ms()-g->peers[i].seen<30000) return 1;
    return 0;
}
static int catalog_allowed(Gateway *g,uint32_t ip,unsigned port) {
    int64_t now=now_ms();
    for(unsigned i=0;i<32;i++)if(g->catalog[i].ip==ip && g->catalog[i].port==port &&
        g->catalog[i].expires>now)return 1;
    return 0;
}
/* The catalog gates new flows only. A tuple that answered stays open while it keeps answering. */
static int flow_live(Gateway *g,uint32_t ip,unsigned port) {
    int64_t now=now_ms();
    for(unsigned i=0;i<FLOW_MAX;i++)if(g->flows[i].ip==ip && g->flows[i].port==port &&
        now-g->flows[i].seen<FLOW_IDLE_MS)return 1;
    return 0;
}
static void note_reply(Gateway *g,const uint8_t *f,size_t n) {
    if(g->control<0 || n<42 || be16(f+12)!=0x800 || f[14]!=0x45 || f[23]!=17 || be16(f+36)!=5151)return;
    uint32_t ip=ip32(f+26);unsigned port=be16(f+34);int64_t now=now_ms();
    if(!catalog_allowed(g,ip,port) && !flow_live(g,ip,port))return;
    Peer *slot=NULL;
    for(unsigned i=0;i<FLOW_MAX;i++) {
        if(g->flows[i].ip==ip && g->flows[i].port==port){slot=&g->flows[i];break;}
        if(!slot && (!g->flows[i].ip || now-g->flows[i].seen>=FLOW_IDLE_MS))slot=&g->flows[i];
    }
    if(slot)*slot=(Peer){ip,(uint16_t)port,now}; /* Full of live flows: nothing evicted. */
}
static int control_snapshot(Gateway *g,const uint8_t *b,size_t n) {
    if(n<6 || b[0]!=1 || b[1]>32 || n!=6+(size_t)b[1]*8 || be32(b+2)<=g->catalog_generation)return 0;
    CatalogPeer next[32]={0};int64_t now=now_ms();
    for(unsigned i=0;i<b[1];i++) {
        const uint8_t *entry=b+6+i*8;uint32_t host=be32(entry);unsigned ttl=be16(entry+6);
        if(be16(entry+4)<1024 || !ttl || ttl>90 || (host>>24)==0 || (host>>24)==127 ||
           (host>>24)>=224 || (host&0xffff0000)==0xa9fe0000 || (host&0xffff0000)==0x0a4d0000)return 0;
        next[i]=(CatalogPeer){ip32(entry),be16(entry+4),now+ttl*1000};
        for(unsigned j=0;j<i;j++)if(next[i].ip==next[j].ip && next[i].port==next[j].port)return 0;
    }
    memcpy(g->catalog,next,sizeof next);g->catalog_generation=be32(b+2);return 1;
}
static void learn_peer(Gateway *g,const uint8_t *f,size_t n) {
    /* Only libslirp-produced inbound UDP to the configured host socket. */
    if(!g->host || n<42 || be16(f+12)!=0x800 || f[14]!=0x45 ||
       f[23]!=17 || ip32(f+30)!=g->guest.s_addr || be16(f+36)!=5150) return;
    uint32_t ip=ip32(f+26); unsigned port=be16(f+34), slot=0;
    for(unsigned i=0;i<FLOW_MAX;i++) {
        if(g->peers[i].ip==ip && g->peers[i].port==port) {slot=i; break;}
        if(g->peers[i].seen<g->peers[slot].seen) slot=i;
    }
    g->peers[slot]=(Peer){ip,(uint16_t)port,now_ms()};
}
static int allowed(Gateway *g,const uint8_t *f,size_t n) {
    if(n<14 || n>FRAME_MAX || !same(f+6,guest_mac,6)) return 0;
    unsigned type=be16(f+12);
    if(type==0x806) {
        if(n<42 || be16(f+14)!=1 || be16(f+16)!=0x800 ||
           f[18]!=6 || f[19]!=4 || !same(f+22,guest_mac,6)) return 0;
        unsigned op=be16(f+20); uint32_t src=ip32(f+28), dst=ip32(f+38);
        if(op!=1 && op!=2) return 0;
        return (src==g->guest.s_addr || (op==1 && src==0)) &&
               (dst==g->router.s_addr || dst==g->guest.s_addr ||
                (g->directory_host[0] && dst==g->dns.s_addr));
    }
    if(type!=0x800 || n<42 || f[14]!=0x45 || !checksum_ok(f+14,20)) return 0;
    unsigned total=be16(f+16), proto=f[23];
    if(total<28 || total>n-14 || (be16(f+20)&0xbfff)) return 0;
    /* Reject fragments/options before looking at ports. Permit DF only. */
    uint32_t src=ip32(f+26), dst=ip32(f+30);
    unsigned sport=be16(f+34), dport=be16(f+36);
    if(proto==17) {
        if(be16(f+38)!=total-20 || be16(f+38)<8) return 0;
        if(be16(f+40) && !transport_checksum(f,total))return 0;
        if(sport==68 && dport==67) {
            /* BOOTP/DHCP request, same lease MAC; no generic UDP exception. */
            if(total<268 || !(src==0 || src==g->guest.s_addr) ||
               !(dst==INADDR_BROADCAST || dst==g->router.s_addr)) return 0;
            const uint8_t *b=f+42;
            return b[0]==1 && b[1]==1 && b[2]==6 &&
                   same(b+28,guest_mac,6) && ip32(b+24)==0 &&
                   b[236]==99 && b[237]==130 && b[238]==83 && b[239]==99;
        }
    } else if(proto==6) {
        if(total<40 || (f[46]>>4)<5 || (unsigned)(f[46]>>4)*4>total-20 ||
           !transport_checksum(f,total)) return 0;
    } else return 0;
    if(src!=g->guest.s_addr || sport==0 || dport==0) return 0;
    if(g->directory_host[0]) {
        if(proto==17 && dst==g->dns.s_addr && dport==53)return 2;
        if(proto==6 && dst==g->directory_ip.s_addr && dport==443)return 3;
    }
    if(route_allowed(dst,dport,proto)) {
        /* A broker is someone else's service and sees this server's address: each guest
           gets few connections and few bytes, for the whole lease. */
        if(proto==6) {
            static unsigned route_syns; static size_t route_bytes;
            if((f[47]&0x12)==0x02 && ++route_syns>ROUTE_TCP_SYNS)return 0;
            route_bytes+=n;
            if(route_bytes>ROUTE_TCP_BYTES)return 0;
        }
        return 1;
    }
    if(proto==17 && sport==5151 && (catalog_allowed(g,dst,dport) || flow_live(g,dst,dport)))return 1;
    /* Operator-set relay hello port, for a browser host's game socket only. */
    if(g->host && proto==17 && sport==5150 && g->relay_port && dst==g->relay_ip && dport==g->relay_port)return 1;
    /* Signed catalog tuples above are a join-only lease's whole world. */
    if(g->join_only) return 0;
    if(g->host) return proto==17 && sport==5150 && peer_allowed(g,dst,dport);
    return dst==g->dest.s_addr && dport==g->port && (proto==17 || g->native);
}
static int incoming_allowed(Gateway *g,const uint8_t *f,size_t n) {
    if(g->control>=0 && n>=42 && be16(f+12)==0x800 && f[14]==0x45 && f[23]==17) {
        uint32_t src=ip32(f+26);unsigned sport=be16(f+34),dport=be16(f+36);
        int known=(sport==67 && dport==68) ||
            (g->directory_host[0] && src==g->dns.s_addr && sport==53) ||
            (g->native && src==g->dest.s_addr && sport==g->port) ||
            (!g->native && !g->host && !g->join_only && src==g->dest.s_addr && sport==g->port) ||
            route_allowed(src,sport,17) ||
            (g->host && dport==5150) || (dport==5151 && (catalog_allowed(g,src,sport) || flow_live(g,src,sport)));
        if(!known)return 0;
    }
    return 1;
}
static slirp_ssize_t send_packet(const void *buf,size_t n,void *opaque) {
    Gateway *g=opaque;
    if(n<14 || n>FRAME_MAX || g->count==QUEUE_MAX) {g->dropped++; return (slirp_ssize_t)n;}
    const uint8_t *f=buf;
    if((be16(f+12)!=0x806 && be16(f+12)!=0x800) || !incoming_allowed(g,f,n)) {
        g->dropped++;return (slirp_ssize_t)n;
    }
    if(g->directory_host[0] && n>=54 && be16(f+12)==0x800 && f[14]==0x45 &&
       f[23]==6 && ip32(f+26)==g->directory_ip.s_addr && ip32(f+30)==g->guest.s_addr &&
       be16(f+34)==443 && f[47]==0x12) {
        for(unsigned i=0;i<TLS_FLOWS;i++) {
            TlsFlow *flow=&g->tls[i];
            if(flow->state==1 && flow->port==be16(f+36) && be32(f+42)==flow->initial+1) {
                flow->server_next=be32(f+38)+1;flow->synacked=1;
            }
        }
    }
    learn_peer(g,f,n);
    note_reply(g,f,n);
    Frame *q=&g->queue[(g->head+g->count)%QUEUE_MAX];
    q->bytes[0]=(uint8_t)(n>>8); q->bytes[1]=(uint8_t)n;
    memcpy(q->bytes+2,buf,n); q->n=n+2; q->sent=0; q->born=now_ms(); g->count++;
    return (slirp_ssize_t)n;
}
/* Answer one exact configured A/IN name locally. Never pass DNS to a resolver. */
static int directory_dns(Gateway *g,const uint8_t *f) {
    const uint8_t *q=f+42; unsigned length=be16(f+38)-8;
    if(length<17 || length>512 || (be16(q+2)&~0x0100) || be16(q+4)!=1 ||
       be16(q+6) || be16(q+8) || be16(q+10))return 0;
    size_t pos=12,used=0; char host[254];
    while(pos<length && q[pos]) {
        unsigned label=q[pos++];
        if(label>63 || pos+label>=length || used+label+1>=sizeof host)return 0;
        if(used)host[used++]='.';
        for(unsigned i=0;i<label;i++) {
            unsigned c=q[pos++];
            if(c>='A' && c<='Z')c+='a'-'A';
            if(!((c>='a' && c<='z') || (c>='0' && c<='9') || c=='-'))return 0;
            host[used++]=(char)c;
        }
    }
    host[used]=0;
    if(pos>=length || q[pos++]!=0 || pos+4!=length || be16(q+pos)!=1 ||
       be16(q+pos+2)!=1)return 0;
    uint32_t answer_ip=g->directory_ip.s_addr;
    if(strcmp(host,g->directory_host)) {
        unsigned i;
        for(i=0;i<route_allow_count;i++)if(route_allow[i].name[0] && !strcmp(host,route_allow[i].name))break;
        if(i==route_allow_count)return 0;
        answer_ip=route_allow[i].ip;
    }
    uint8_t out[14+20+8+512+16]={0};
    memcpy(out,guest_mac,6); out[6]=0x52;out[7]=0x55;memcpy(out+8,&g->dns.s_addr,4);
    put16(out+12,0x800);out[14]=0x45;out[22]=64;out[23]=17;
    unsigned dnslen=length+16,total=20+8+dnslen;
    put16(out+16,total);memcpy(out+26,&g->dns.s_addr,4);memcpy(out+30,&g->guest.s_addr,4);
    put16(out+24,~sum_bytes(out+14,20,0));put16(out+34,53);put16(out+36,be16(f+34));put16(out+38,8+dnslen);
    uint8_t *answer=out+42;memcpy(answer,q,length);put16(answer+2,0x8080|(be16(q+2)&0x100));put16(answer+6,1);
    uint8_t *rr=answer+length;put16(rr,0xc00c);put16(rr+2,1);put16(rr+4,1);
    rr[9]=30;put16(rr+10,4);memcpy(rr+12,&answer_ip,4);
    send_packet(out,14+total,g);return 1;
}
/* Strict single-record ClientHello. Bounds checked before every variable field. */
static int hello_name(const uint8_t *b,size_t n,const char *expected) {
    if(n<5)return 0;
    size_t record=be16(b+3)+5;
    if(b[0]!=22 || b[1]!=3 || b[2]>3 || record>TLS_HELLO_MAX || record<9)return -1;
    if(n<record)return 0;
    size_t hlen=(size_t)b[6]<<16|(size_t)b[7]<<8|b[8];
    if(b[5]!=1 || hlen+9!=record || record<44)return -1;
    size_t p=43; unsigned session=b[p++];
    if(session>32 || p+session+2>record)return -1;
    p+=session;unsigned ciphers=be16(b+p);p+=2;
    if(ciphers<2 || ciphers%2 || p+ciphers+1>record)return -1;
    p+=ciphers;unsigned compression=b[p++];
    if(!compression || p+compression+2>record)return -1;
    p+=compression;unsigned extensions=be16(b+p);p+=2;
    if(p+extensions!=record)return -1;
    int found=0;
    while(p<record) {
        if(p+4>record)return -1;
        unsigned kind=be16(b+p),len=be16(b+p+2);p+=4;
        if(p+len>record)return -1;
        if(kind==0) {
            if(found || len<5 || be16(b+p)!=len-2 || b[p+2]!=0 ||
               be16(b+p+3)!=len-5 || strlen(expected)!=len-5 ||
               !same(b+p+5,expected,len-5))return -1;
            found=1;
        }
        p+=len;
    }
    return found?1:-1;
}
static int directory_tls(Gateway *g,const uint8_t *f,size_t n) {
    unsigned sport=be16(f+34),flags=f[47],header=(f[46]>>4)*4;
    size_t payload=be16(f+16)-20-header; uint32_t seq=be32(f+38);
    TlsFlow *flow=NULL;int64_t now=now_ms();
    for(unsigned i=0;i<TLS_FLOWS;i++) {
        /* An admitted flow stays while the guest does its SH-4 crypto, which can be quiet for longer than 30 s.
           Forgetting it refused every later frame while TCP kept retransmitting. */
        if(g->tls[i].state && now-g->tls[i].seen>(g->tls[i].state==2?TLS_OPEN_QUIET_MS:30000))g->tls[i].state=0;
        if(g->tls[i].state && g->tls[i].port==sport)flow=&g->tls[i];
    }
    if(flags&2) {
        if(payload || flags&(1|4|16))return 0;
        if(!flow)for(unsigned i=0;i<TLS_FLOWS;i++)if(!g->tls[i].state){flow=&g->tls[i];break;}
        /* Table full: only an admitted flow quiet for 30 s may give up its slot, oldest first. */
        if(!flow)for(unsigned i=0;i<TLS_FLOWS;i++)if(now-g->tls[i].seen>30000 && (!flow || g->tls[i].seen<flow->seen))flow=&g->tls[i];
        if(!flow)return 0;
        if(flow->port!=sport || flow->initial!=seq || !flow->state) {
            memset(flow,0,sizeof *flow);flow->port=(uint16_t)sport;flow->initial=seq;flow->next=seq+1;flow->state=1;
        }
        flow->seen=now;slirp_input(g->slirp,f,(int)n);return 1;
    }
    if(!flow)return 0;
    flow->seen=now;
    if(flags&4 || ((flags&1) && !payload)) {flow->state=0;slirp_input(g->slirp,f,(int)n);return 1;}
    if(flow->state<0)return 0;
    if(!payload || flow->state==2) {slirp_input(g->slirp,f,(int)n);return 1;}
    /* First app bytes must be a packet the established TCP stack can accept;
       otherwise an invalid ACK/option/checksum could falsely open the SNI gate. */
    if(!flow->synacked || be32(f+42)!=flow->server_next || header!=20 ||
       (flags!=0x10 && flags!=0x18) || f[22]<=1 || (f[46]&15))return 0;
    if(seq!=flow->next)return 0; /* No speculative out-of-order parsing. TCP retransmits. */
    if(flow->used+payload>TLS_HELLO_MAX || flow->frames==TLS_FRAMES || flags&1) {flow->state=-1;return 0;}
    memcpy(flow->hello+flow->used,f+34+header,payload);flow->used+=payload;flow->next+=(uint32_t)payload;
    Frame *held=&flow->held[flow->frames++];memcpy(held->bytes,f,n);held->n=n;
    int valid=hello_name(flow->hello,flow->used,g->directory_host);
    if(valid<0){flow->state=-1;return 0;}
    if(valid) {
        flow->state=2;
        for(unsigned i=0;i<flow->frames;i++)slirp_input(g->slirp,flow->held[i].bytes,(int)flow->held[i].n);
        flow->frames=0;flow->used=0;
    }
    return 1;
}
static void guest_error(const char *msg,void *opaque) { (void)msg; ((Gateway*)opaque)->refused++; }
static void notify(void *opaque) { (void)opaque; }
static void *timer_new(SlirpTimerCb cb,void *arg,void *opaque) {
    Gateway *g=opaque;
    for(unsigned i=0;i<8;i++) if(!g->timers[i].used) {
        g->timers[i]=(Timer){cb,arg,-1,1}; return &g->timers[i];
    }
    g->failed=1; return NULL;
}
static void timer_free(void *timer,void *opaque) { (void)opaque; if(timer) ((Timer*)timer)->used=0; }
static void timer_mod(void *timer,int64_t at,void *opaque) { (void)opaque; if(timer) ((Timer*)timer)->at=at; }
static void reg_socket(slirp_os_socket fd,void *opaque) { (void)fd; (void)opaque; }
static int add_poll(slirp_os_socket fd,int events,void *opaque) {
    Gateway *g=opaque;
    if(g->nfds>=POLL_MAX) {g->failed=1; return -1;}
    short e=0; if(events&SLIRP_POLL_IN)e|=POLLIN; if(events&SLIRP_POLL_OUT)e|=POLLOUT;
    if(events&SLIRP_POLL_PRI)e|=POLLPRI;
    int i=g->nfds++; g->fds[i]=(struct pollfd){fd,e,0}; return i;
}
static int get_events(int i,void *opaque) {
    Gateway *g=opaque; if(i<0 || i>=g->nfds)return 0;
    int e=g->fds[i].revents,r=0;
    if(e&POLLIN)r|=SLIRP_POLL_IN;
    if(e&POLLOUT)r|=SLIRP_POLL_OUT;
    if(e&POLLPRI)r|=SLIRP_POLL_PRI;
    if(e&POLLERR)r|=SLIRP_POLL_ERR;
    if(e&POLLHUP)r|=SLIRP_POLL_HUP;
    return r;
}
static void on_signal(int sig) { (void)sig; stopped=1; }
static unsigned number(const char *s,unsigned max) {
    char *end; errno=0; unsigned long v=strtoul(s,&end,10);
    if(errno || !*s || *end || v==0 || v>max) {fprintf(stderr,"invalid numeric option\n"); exit(2);}
    return (unsigned)v;
}
int main(int argc,char **argv) {
    /* Trusted launcher only: mode lease destination port lifetime. */
    if(argc!=6 && argc!=8) {
        fprintf(stderr,"usage: gateway host|peer|guest|native LEASE DEST PORT SECONDS [DIRECTORY_HOST DIRECTORY_IP]\n"); return 2;
    }
    Gateway g={.control=-1}; unsigned lease=number(argv[2],250);
    g.host=!strcmp(argv[1],"host"); g.native=!strcmp(argv[1],"native");
    g.join_only=!strcmp(argv[1],"guest");
    if(!g.host && !g.native && !g.join_only && strcmp(argv[1],"peer"))return 2;
    if(g.join_only && argc!=8)return 2;
    g.port=number(argv[4],65535); g.seconds=number(argv[5],3600);
    if(inet_pton(AF_INET,argv[3],&g.dest)!=1)return 2;
    char s[32]; SlirpConfig cfg={0}; cfg.version=6; cfg.in_enabled=true;
    snprintf(s,sizeof s,"10.77.%u.0",lease); inet_pton(AF_INET,s,&cfg.vnetwork);
    inet_pton(AF_INET,"255.255.255.0",&cfg.vnetmask);
    snprintf(s,sizeof s,"10.77.%u.2",lease); inet_pton(AF_INET,s,&g.router);
    snprintf(s,sizeof s,"10.77.%u.15",lease); inet_pton(AF_INET,s,&g.guest);
    if(argc>=8) {
        size_t len=strlen(argv[6]);if(len<3 || len>=sizeof g.directory_host)return 2;
        for(size_t i=0;i<len;i++)if(!((argv[6][i]>='a' && argv[6][i]<='z') ||
            (argv[6][i]>='0' && argv[6][i]<='9') || argv[6][i]=='-' || argv[6][i]=='.'))return 2;
        strcpy(g.directory_host,argv[6]);
        if(inet_pton(AF_INET,argv[7],&g.directory_ip)!=1)return 2;
        uint32_t dir=ntohl(g.directory_ip.s_addr);
        if((dir>>24)==0 || (dir>>24)==127 || (dir>>24)>=224 ||
           (dir&0xffff0000)==0xa9fe0000 || (dir&0xffff0000)==0x0a4d0000)return 2;
        snprintf(s,sizeof s,"10.77.%u.3",lease);inet_pton(AF_INET,s,&g.dns);
        cfg.vnameserver=g.dns;
    }
    if(g.host && g.dest.s_addr!=g.router.s_addr)return 2;
    /* Native destinations must be operator-selected unicast, never magic host aliases. */
    uint32_t d=ntohl(g.dest.s_addr);
    if((g.native || (!g.host && g.dest.s_addr!=g.router.s_addr)) && ((d>>24)==0 || (d>>24)==127 || (d>>24)>=224 ||
       (d&0xffff0000)==0xa9fe0000 || (d&0xffff0000)==0x0a4d0000))return 2;
    cfg.vhost=g.router; cfg.vdhcp_start=g.guest; cfg.if_mtu=1500; cfg.if_mru=1500;
    cfg.disable_dns=true; cfg.disable_host_loopback=g.native || g.join_only || (!g.host && g.dest.s_addr!=g.router.s_addr); cfg.enable_emu=false;
    struct rlimit mem={64*1024*1024,64*1024*1024},files={64,64};
    if(setrlimit(RLIMIT_AS,&mem) || setrlimit(RLIMIT_NOFILE,&files))return 2;
    const char *control_fd=getenv("HALO_GATEWAY_CONTROL_FD");
    if(control_fd) {
        g.control=(int)number(control_fd,63);
        if(g.control<3 || fcntl(g.control,F_SETFL,O_NONBLOCK)<0)return 2;
    }
    if(g.join_only && g.control<0)return 2;
    const char *route=getenv("HALO_GATEWAY_ROUTE_ALLOW");
    if(route && !route_parse(route))return 2;
    const char *relay=getenv("HALO_GATEWAY_RELAY");
    if(relay) {
        char text[32];const char *colon=strchr(relay,':');struct in_addr address;
        if(!colon || (size_t)(colon-relay)>=sizeof text)return 2;
        memcpy(text,relay,(size_t)(colon-relay));text[colon-relay]=0;
        if(inet_pton(AF_INET,text,&address)!=1)return 2;
        uint32_t r=ntohl(address.s_addr);
        if((r>>24)==0 || (r>>24)==127 || (r>>24)>=224 || (r&0xffff0000)==0xa9fe0000 || (r&0xffff0000)==0x0a4d0000)return 2;
        g.relay_ip=address.s_addr;g.relay_port=number(colon+1,65535);
    }
    signal(SIGPIPE,SIG_IGN); signal(SIGTERM,on_signal); signal(SIGINT,on_signal);
    SlirpCb cb={.send_packet=send_packet,.guest_error=guest_error,.clock_get_ns=now_ns,
        .timer_new=timer_new,.timer_free=timer_free,.timer_mod=timer_mod,.notify=notify,
        .register_poll_socket=reg_socket,.unregister_poll_socket=reg_socket};
    g.slirp=slirp_new(&cfg,&cb,&g); if(!g.slirp)return 3;
    struct in_addr loop; inet_pton(AF_INET,"127.0.0.1",&loop);
    /* Through the relay a host needs no inbound port. A forward would pin its source to loopback and hide the relay's address from the game. */
    if(g.host && !g.relay_port) {
        const char *bind_ip=getenv("HALO_GATEWAY_HOST_BIND_IP");
        if(bind_ip) {
            if(inet_pton(AF_INET,bind_ip,&loop)!=1){slirp_cleanup(g.slirp);return 2;}
            uint32_t bind=ntohl(loop.s_addr);
            if((bind>>24)==0 || (bind>>24)>=224 || ((bind>>24)==127 && bind!=0x7f000001) ||
               (bind&0xffff0000)==0xa9fe0000){slirp_cleanup(g.slirp);return 2;}
        }
        if(slirp_add_hostfwd(g.slirp,1,loop,(int)g.port,g.guest,5150)) {
            slirp_cleanup(g.slirp); fprintf(stderr,"host-forward bind failed\n"); return 3;
        }
        g.forward=g.port;
    }
    if(fcntl(0,F_SETFL,O_NONBLOCK)<0 || fcntl(1,F_SETFL,O_NONBLOCK)<0)g.failed=1;
    fprintf(stderr,"READY slirp=%s lease=%u mode=%s port=%u\n",slirp_version_string(),lease,argv[1],g.port);
    uint8_t input[FRAME_MAX+2]; size_t have=0,need=2;
    uint8_t control_input[264];size_t control_have=0,control_need=2;int64_t control_at=0;
    int64_t end=now_ms()+g.seconds*1000, partial_at=0;
    while(!stopped && !g.failed && now_ms()<end) {
        g.nfds=g.control>=0?3:2; g.fds[0]=(struct pollfd){0,POLLIN,0};
        g.fds[1]=(struct pollfd){1,g.count?POLLOUT:0,0};
        if(g.control>=0)g.fds[2]=(struct pollfd){g.control,POLLIN,0};
        uint32_t timeout=20; slirp_pollfds_fill_socket(g.slirp,&timeout,add_poll,&g);
        if(g.failed)break;
        int r=poll(g.fds,(nfds_t)g.nfds,(int)timeout);
        if(r<0 && errno==EINTR)continue;
        if(r<0){g.failed=1;break;}
        slirp_pollfds_poll(g.slirp,0,get_events,&g);
        int64_t now=now_ms();
        if(control_have && now-control_at>1000){g.failed=1;break;}
        if(g.control>=0 && g.fds[2].revents&(POLLIN|POLLHUP|POLLERR)) {
            ssize_t count=read(g.control,control_input+control_have,control_need-control_have);
            if(count==0){g.failed=1;break;}
            if(count<0 && errno!=EAGAIN && errno!=EINTR){g.failed=1;break;}
            if(count>0) {
                if(!control_have)control_at=now;
                control_have+=(size_t)count;
                if(control_have==2 && control_need==2) {
                    unsigned len=be16(control_input);
                    if(len<6 || len>262){g.failed=1;break;}
                    control_need=len+2;
                } else if(control_have==control_need) {
                    if(!control_snapshot(&g,control_input+2,control_need-2)){g.failed=1;break;}
                    control_have=0;control_need=2;
                }
            }
        }
        for(unsigned i=0;i<8;i++) if(g.timers[i].used && g.timers[i].at>=0 && g.timers[i].at<=now) {
            g.timers[i].at=-1; g.timers[i].cb(g.timers[i].arg);
        }
        if(have && now-partial_at>1000){g.failed=1;break;}
        if(g.fds[0].revents&(POLLIN|POLLHUP|POLLERR)) {
            ssize_t n=read(0,input+have,need-have);
            if(n==0){stopped=1;break;}
            if(n<0 && errno!=EAGAIN && errno!=EINTR){g.failed=1;break;}
            if(n>0) {
                if(!have)partial_at=now;
                have+=(size_t)n;
                if(have==2 && need==2) {
                    unsigned len=be16(input); if(len<14 || len>FRAME_MAX){g.failed=1;break;}
                    need=len+2;
                } else if(have==need) {
                    if(now-g.rate_epoch>=1000){g.rate_epoch=now;g.rate_count=0;}
                    if(++g.rate_count>1000){g.failed=1;break;}
                    int action=allowed(&g,input+2,need-2),ok=0;
                    if(action==1){slirp_input(g.slirp,input+2,(int)need-2);ok=1;}
                    else if(action==2)ok=directory_dns(&g,input+2);
                    else if(action==3)ok=directory_tls(&g,input+2,need-2);
                    if(ok)g.accepted++;else g.refused++;
                    have=0;need=2;
                }
            }
        }
        if(g.count) {
            Frame *q=&g.queue[g.head];
            if(!incoming_allowed(&g,q->bytes+2,q->n-2)) {
                if(q->sent){g.failed=1;break;}
                g.head=(g.head+1)%QUEUE_MAX;g.count--;g.dropped++;continue;
            }
            /* Once a prefix is written, cannot drop remainder without corrupting IPC. */
            if(now-q->born>1000) {
                if(q->sent){g.failed=1;break;}
                g.head=(g.head+1)%QUEUE_MAX;g.count--;g.dropped++;
            } else if(g.fds[1].revents&POLLOUT) {
                ssize_t n=write(1,q->bytes+q->sent,q->n-q->sent);
                if(n<0 && errno!=EAGAIN && errno!=EINTR){g.failed=1;break;}
                if(n>0)q->sent+=(size_t)n;
                if(q->sent==q->n){g.head=(g.head+1)%QUEUE_MAX;g.count--;g.sent++;}
            }
        }
    }
    if(g.forward)slirp_remove_hostfwd(g.slirp,1,loop,(int)g.forward);
    slirp_cleanup(g.slirp);
    if(g.control>=0)close(g.control);
    struct rusage usage; getrusage(RUSAGE_SELF,&usage);
    fprintf(stderr,"STOP accepted=%llu refused=%llu sent=%llu dropped=%llu maxrss_kib=%ld failed=%d\n",
        (unsigned long long)g.accepted,(unsigned long long)g.refused,
        (unsigned long long)g.sent,(unsigned long long)g.dropped,usage.ru_maxrss,g.failed);
    return g.failed?4:0;
}
