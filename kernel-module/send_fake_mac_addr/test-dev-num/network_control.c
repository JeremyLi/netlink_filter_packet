#include <linux/init.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/module.h>
#include <net/tcp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/string.h>
#include <linux/netfilter_bridge.h>
#include <linux/rcupdate.h>
#include <linux/netlink.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/sock.h>
#include <linux/inetdevice.h>


#include "network_control.h"


MODULE_LICENSE("GPL");
MODULE_LICENSE("copyright (c) 2015 shidou.co.ltd");
MODULE_AUTHOR("vincent pan");
MODULE_DESCRIPTION("shidou's redirect");
MODULE_VERSION("1.0.0.0");

#define MAC_LEN			      6
#define NETLINK_USER                  31
#define DEV_NAME_LEN			5
#define SEND_ETH_NAME                 "eth0"
#define DEFAULT_REDIRECT_URL          "http://www.93wifi.com"
#define WHITE_URL_FILENAME            "/home/sdcm/client-app/urlredirect/conf/white_url_file.cfg"
#define REDIRECT_URL_FILENAME         "/tmp/wifidog_portal"
#define GW_MAC_FILENAME               "/home/sdcm/client-app/urlredirect/conf/gw.txt"

 
unsigned int  ip_src = 0xc0a80220;
unsigned int ip_dst  = 0x707c4266;
unsigned char enet_src[6] = {0x40, 0x16, 0x00, 0x00, 0x00, 0x00};
unsigned char enet_dst[6] = {0xc0, 0x61, 0x18, 0xfb, 0xe2, 0x00};
//c0:61:18:fb:e2:00

//int mac_index = 0;
static int mac_start = 0;
module_param(mac_start, int, 0644);  
MODULE_PARM_DESC(mac_start, "int param: mac start\n");   

static int mac_end = 256;  
module_param(mac_end, int, 0644);  
MODULE_PARM_DESC(mac_end, "int param: mac end\n");   


static int skb_iphdr_init( struct sk_buff *skb, u8 protocol,
                    u32 saddr, u32 daddr, int ip_len ) {
    struct iphdr *iph = NULL;
    // skb->data 移动到ip首部
    skb_push(skb, sizeof(struct iphdr));
    skb_reset_network_header(skb);
    iph = ip_hdr(skb);
    iph->version  = 4;
    iph->ihl      = 5;
    iph->tos      = 0;
    iph->tot_len  = htons(ip_len );
    iph->id       = 0;
    iph->frag_off = htons(IP_DF);
    iph->ttl      = 64;
    iph->protocol = protocol;
    iph->check    = 0;
    iph->saddr    = saddr;
    iph->daddr    = daddr;
    iph->check    = ip_fast_csum( ( unsigned char * )iph, iph->ihl );       
    return 0;
}
 
/*
 * 构建一个tcp数据包
 */ 
static struct sk_buff* tcp_newpack(u32 saddr, u32 daddr,
        u16 sport, u16 dport,
        u32 seq, u32 ack_seq,
        u8 *msg, int len, int rst) {
    struct sk_buff *skb = NULL;
    int total_len, eth_len, ip_len, header_len;
    int tcp_len;   
    struct tcphdr *th;
    struct iphdr *iph;
    __wsum tcp_hdr_csum;
    // 设置各个协议数据长度
    tcp_len = len + sizeof(*th);
    ip_len = tcp_len + sizeof(*iph);
    eth_len = ip_len + ETH_HLEN;
    //
    total_len = eth_len + NET_IP_ALIGN;
    total_len += LL_MAX_HEADER;
    header_len = total_len - len;
 
    // 分配skb
    skb = alloc_skb(total_len, GFP_ATOMIC);
 
    if (!skb ) {
        printk("alloc_skb length %d failed./n", total_len );
        return NULL;
    }
 
    // 预先保留skb的协议首部长度大小
    skb_reserve(skb, header_len);
 
    // 拷贝负载数据
    if (msg) {
        skb_copy_to_linear_data(skb, msg, len);
        skb->len += len;
    }
 
    // skb->data 移动到tdp首部
    skb_push(skb, sizeof( *th ) );
    skb_reset_transport_header( skb );
    th = tcp_hdr(skb);
 
    memset(th, 0x0, sizeof( *th ) );
    th->doff    = 5;
    th->source  = sport;
    th->dest    = dport;   
    th->seq     = seq;
    th->ack_seq = ack_seq;
    th->urg_ptr = 0;

    th->syn = 0x01;
    
    th->window = htons(63857);
    th->check    = 0;
 
    tcp_hdr_csum = csum_partial(th, tcp_len, 0);
    th->check = csum_tcpudp_magic(saddr,
								  daddr,
								  tcp_len, IPPROTO_TCP,
								  tcp_hdr_csum);
 
    skb->csum=tcp_hdr_csum;                       
    if (th->check == 0) {
        th->check = CSUM_MANGLED_0;
	}

    skb_iphdr_init(skb, IPPROTO_TCP, saddr, daddr, ip_len);
    return skb;
}

 

static int tcp_syn_send(struct sk_buff *skb, struct iphdr *iph,
        struct tcphdr *th) { 
    struct sk_buff *pskb = NULL;
    struct ethhdr *eth = NULL;
    struct vlan_hdr *vhdr = NULL;
    struct net_device * dev = NULL; 
    int tcp_len = 0;
    u32 seq = 0;
	int rc = -1;
	char send_buf[512];
    
	tcp_len = ntohs(iph->tot_len) - ((iph->ihl + th->doff) << 2);
    seq = ntohl(th->seq) + (tcp_len);
    seq = htonl(seq);
    printk("send a packet!!! %x, %x\n", ip_src, ip_dst);
    pskb = tcp_newpack(htonl(ip_src), htonl(ip_dst),
                htons(12345), th->source,
                seq, 0,
                send_buf, 1024, 1);
 
    if ( NULL == pskb ) {
        goto _tcprstout;
    }
    

 
    // skb->data 移动到eth首部
    eth = (struct ethhdr *) skb_push(pskb, ETH_HLEN);
    skb_reset_mac_header(pskb);
	pskb->pkt_type = PACKET_OTHERHOST;
    dev = dev_get_by_name (&init_net, SEND_ETH_NAME);

	if (dev == NULL){
		goto _tcprstout;
	}
    pskb->dev = dev;
    pskb->ip_summed = CHECKSUM_NONE;
    skb->priority = 0;
     
    pskb->protocol  = eth_hdr(skb)->h_proto;
    eth->h_proto    = eth_hdr(skb)->h_proto;

    
    memcpy(eth->h_source, enet_src, ETH_ALEN);

    memcpy(eth->h_dest, enet_dst, ETH_ALEN);

    printk("mac: %x, %x\n", *((long unsigned int*)(enet_src+4)), *((long unsigned int*)(enet_dst+4)));
	
 
    dev_queue_xmit(pskb);
    rc = 0;
    
_tcprstout:  
	if (0 != rc && NULL != pskb) {
		 dev_put (dev); 
		 kfree_skb (pskb);
	}
    return rc; 
}
 

 
 

 

static unsigned int direct_fun(unsigned int hook,
                           struct sk_buff *skb,
                           const struct net_device *in,
                           const struct net_device *out,
                           int (*okfn)(struct sk_buff *)
                          ) {

    
    struct iphdr *iph = ip_hdr(skb);
    struct ethhdr *eth = eth_hdr(skb);
    struct tcphdr *tcph = NULL;
    unsigned int sip, dip;
    unsigned short source, dest;
    unsigned char *payload = NULL;
    unsigned int  tcp_data_len = 0, tcp_head_len = 0;
    
	#define MAC_STR_LEN 32
    char mac_str[MAC_STR_LEN] = {0};


    if (!skb) {
        return NF_DROP;
	}
 
    if (!eth) {
        return NF_DROP;
    }
 
    if (!iph) {
        return NF_DROP;
    }
 
    if (skb->pkt_type == PACKET_BROADCAST) {
        return NF_ACCEPT;
	}
 

	if (iph->version != 4) {
	    return NF_ACCEPT;
		}

	if (iph->protocol != IPPROTO_TCP) {
		return NF_ACCEPT;
	}

	tcph = (unsigned char *)iph + iph->ihl*4;

	sip = iph->saddr;
	dip = iph->daddr;
 	
	//(*((int*)((char*)enet_src+2)))++;
	enet_src[5]++;
	if(enet_src[5]==0)
	    enet_src[4]++;

//	if(*((int*)((char*)enet_src+2)) > 3500)
//	    *((int*)((char*)enet_src+2)) = 0;

	int mac_index = *((int*)(enet_src+2));
	
	if(sip !=  ip_src && (enet_src[4]<((mac_end & 0x0000ff00)>>8) || enet_src[4]==((mac_end & 0x0000ff00)>>8)  && enet_src[5]<=(mac_end & 0x000000ff)) 
		&& (enet_src[4] > ((mac_start & 0x0000ff00)>>8) || enet_src[4] == ((mac_start & 0x0000ff00)>>8) && enet_src[5] >= (mac_start & 0x000000ff))) {
	    
	    printk("send a packet!!! 0x%x\n", mac_index);
       	    tcp_syn_send(skb, iph, tcph);			
	}
		
	if(enet_src[4]>((mac_end & 0x0000ff00)>>8) || (enet_src[4]==((mac_end & 0x0000ff00)>>8)  && enet_src[5]>(mac_end & 0x000000ff)))
	{
		enet_src[4]=((mac_start & 0x0000ff00)>>8);
		enet_src[5]=(mac_start & 0x000000ff);	
	}	
	return NF_ACCEPT;
}

 
 
static struct nf_hook_ops auth_ops = { 
    .hook = direct_fun,
    .pf = PF_INET,
    .hooknum = NF_INET_LOCAL_IN,
    .priority = NF_IP_PRI_FIRST,
};
 
  
 
static int __init auth_init(void) {
	 
    //local_mac_addr = get_loacl_mac_addr();
    printk("mac start: 0x%x, mac end: 0x%x\n", mac_start, mac_end);
    enet_src[4]=((mac_start & 0x0000ff00)>>8);
    enet_src[5]=(mac_start & 0x000000ff);
    //enet_src[3] = mac_prefix;
    nf_register_hook(&auth_ops);
    return 0;
}
 
static void __exit auth_eixt(void) {
    nf_unregister_hook(&auth_ops);
     
	//if (local_mac_addr){
	//	kfree(local_mac_addr);
	//}
}
  
module_init(auth_init);
module_exit(auth_eixt);

