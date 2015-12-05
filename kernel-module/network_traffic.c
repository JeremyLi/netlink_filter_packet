#include <linux/version.h>
#include <linux/init.h>
#include <linux/ctype.h>
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
#include <net/sock.h>
#include <linux/netdevice.h>
#include <linux/mutex.h>



#include "nf_info_list.h"
// #include "file_io_module.h"


MODULE_LICENSE("GPL");
MODULE_LICENSE("copyright (c) 2015 shidou.co.ltd");
MODULE_AUTHOR("Jeremy Li");
MODULE_DESCRIPTION("shidou's capture");
MODULE_VERSION("1.0.0.0");

#define MONITOR_DEV_FILE_NAME "/home/sdcm/conf/model"
#define FILE_NAME_MAX_LEN   16

#define NETLINK_DEV_NUM 30
#define ACTION_SUMMARY   0
#define ACTION_CLEAR_NEW 1
#define ACTION_CLEAR_ALL 2
#define ACTION_ONLINE    3

#define INFO_SUMMARY     0
#define INFO_ONLINE      1
// struct sock *nl_sk = NULL;
// struct sk_buff * skb = NULL;
// struct nlmsghdr * nlh = NULL;
// int err;
static u32 pid;
static struct semaphore receive_sem;
static struct sock *nlfd;

static char* ignore_if="eth2";
static char seq_buf[MAC_BUF_LEN];
static rwlock_t buf_lock;
static int  content_len = 0;
// static struct net dev_num_net;
static unsigned int pid;
// static int  current_start = 0;
// static int  current_end = 0;
// static char online_buf[MAC_BUF_LEN];

module_param(ignore_if, charp, 0644);  
MODULE_PARM_DESC(ignore_if, "int param: ignore interface\n"); 
/*
 * This function makes lazy skb cloning in hope that most of packets
 * are discarded by BPF.
 *
 * Note tricky part: we DO mangle shared skb! skb->data, skb->len
 * and skb->cb are mangled. It works because (and until) packets
 * falling here are owned by current CPU. Output packets are cloned
 * by dev_queue_xmit_nit(), input packets are processed by net_bh
 * sequencially, so that if we return skb to original state on exit,
 * we will not harm anyone.
 * This is borrow from af_packet.c
 */
static int packet_rcv(struct sk_buff *skb, struct net_device *dev,
                      struct packet_type *pt, struct net_device *orig_dev){
    if (skb->pkt_type == PACKET_LOOPBACK
            || skb->pkt_type == PACKET_BROADCAST
            || skb->pkt_type == PACKET_HOST 
            || skb->pkt_type == PACKET_MULTICAST)
        goto drop;
// printk("skb->pkt_type = %x, skb->protocol=%x, %x, %x\n", skb->pkt_type, ntohs(skb->protocol), ETH_P_PPP_MP, ETH_P_IP);
    if((skb->protocol != htons(ETH_P_8021Q))
            && (skb->protocol != htons(ETH_P_IP)))
        goto drop;

//    if (skb->pkt_type != PACKET_OTHERHOST) {
//        goto drop;
//    }

    // printk("dev->name: %s\n", dev->name);
    if (!strncmp(dev->name, ignore_if, strlen(dev->name)) || strncmp(dev->name, "lo", 2) == 0)
        goto drop;
    
    struct iphdr* iph = ip_hdr(skb);
//    if ((skb->protocol==htons(ETH_P_8021Q) || skb->protocol==htons(ETH_P_IP)) && skb->len>=sizeof(struct ethhdr)) {
//        if (skb->protocol==htons(ETH_P_8021Q)){
//            iph = (struct iphdr *)((u8*)iph+4);
//        }
 //   }
    if(iph->protocol != IPPROTO_TCP)
       goto drop;

    struct ethhdr* ehdr = eth_hdr(skb);
    struct mac_addr tmp_mac;
    struct mac_addr zero_mac;
    memset(zero_mac.mac, 0, 6);
    // printk("macsrc: %02x-%02x-%02x-%02x-%02x-%02x, ipsrc: %x\n", ehdr->h_source[0], ehdr->h_source[1], ehdr->h_source[2], 
    //     ehdr->h_source[3], ehdr->h_source[4], ehdr->h_source[5], iph->saddr);
    memcpy(tmp_mac.mac, ehdr->h_source, 6);

    if(memcmp(zero_mac.mac, tmp_mac.mac, 6) == 0) {
       //goto drop;
    }
    struct timeval tv;
    do_gettimeofday(&tv);
    
    struct nf_conntrack_info* item = has_nf_info(&tmp_mac);
    if (item) {
        // printk("==========update dev timestamp...\n");
        nf_info_update(item, tv.tv_sec);
        spin_unlock_bh(&item->lock);
    }else{
        printk("++++++++++new dev...\n");
        nf_info_add(&tmp_mac, tv.tv_sec);
    }
    
drop:
    consume_skb(skb);
    return 0;
}

// static int dev_enter_promiscuity(const char* name)
// {
//     struct net_device *dev = dev_get_by_name(&init_net, name);
//     if (dev != NULL) {
//         if(dev->flags & IFF_PROMISC) {
//             // hm_debug("HTTP_MANGER: dev %s! already in promisc mode\n", name);
//             return 0;
//         }

//         rtnl_lock();
//         dev_set_promiscuity(dev, 1);
//         rtnl_unlock();
//         dev_put(dev);
//         return 0;
//     } else {
//         // hm_debug("HTTP_MANGER: cannot find dev %s!\n", name);
//         return -1;
//     }

//     return 0;
// }

// static int dev_exit_promiscuity(const char* name)
// {
//     struct net_device *dev = dev_get_by_name(&init_net, name);
//     if (dev != NULL) {
//         if(!(dev->flags & IFF_PROMISC)) {
//             // hm_debug("HTTP_MANGER: dev %s! already exit promisc mode\n", name);
//             return 0;
//         }

//         //rtnl_lock is need, or Call Stack
//         rtnl_lock();
//         dev_set_promiscuity(dev, -1);
//         rtnl_unlock();
//         dev_put(dev);
//         return 0;
//     } else {
//         // hm_debug("HTTP_MANGER: cannot find dev %s!\n", name);
//         return -1;
//     }

//     return 0;
// }

static struct packet_type tcp_packet_type __read_mostly = {
    .type = cpu_to_be16(ETH_P_ALL),
    .func = packet_rcv,
};

int hm_conntrack_create(void){
    dev_add_pack(&tcp_packet_type);
    // dev_enter_promiscuity("br0");

    return 0;
}

void hm_conntrack_destroy(void){
    // dev_exit_promiscuity("br0");
    dev_remove_pack(&tcp_packet_type);
}

static int send_to_user(int flags)
{
    int ret;
    int size;
    unsigned char *old_tail;
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    char* packet;

    struct timeval tv;
    do_gettimeofday(&tv);
    write_lock_bh(&buf_lock);
    if(flags == INFO_SUMMARY)
        content_len = nf_info_summary(tv.tv_sec, seq_buf);
    else
        content_len = nf_info_online_devs(seq_buf);
    seq_buf[content_len] = '\0';

    printk("send to user: %d, len: %d, %s\n", pid, content_len, seq_buf);

    // write_unlock_bh(&buf_lock);
    // size = NLMSG_SPACE(content_len);
    // /*开辟一个新的套接字缓存*/
    // skb = alloc_skb(size, GFP_ATOMIC);
    skb = nlmsg_new(content_len, 0);
    old_tail = skb->tail;
    /*填写数据报相关信息*/
    nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, content_len, 0);
    packet = nlmsg_data(nlh);
    // memset(packet, 0, content_len);
    /*传输到用户空间的数据*/
    // read_lock_bh(&buf_lock);
    strncpy(packet, seq_buf, content_len);
    // read_unlock_bh(&buf_lock);
    write_unlock_bh(&buf_lock);

    /*计算经过字节对其后的数据实际长度*/
    nlh->nlmsg_len = (unsigned char *)(skb->tail) - old_tail;
    // NETLINK_CB(skb).groups = 0; /* not in mcast group */
    NETLINK_CB(skb).pid = 0;      /* from kernel */
    // NETLINK_CB(skb).dst_pid = pid;
    NETLINK_CB(skb).dst_group = 0;
    // NETLINK_CREDS(skb)->pid = 0;
    ret = netlink_unicast(nlfd, skb, pid, MSG_DONTWAIT); /*发送数据*/
    return ret;
nlmsg_failure: /*若发送失败，则撤销套接字缓存*/
    if(skb)
    kfree_skb(skb);
    return -1;
}

static void kernel_receive (struct sk_buff *__skb)
{
    if(__skb == NULL) return;

    // spin_lock_bh(&buf_lock);

    
    // int len = skb->len;
    if(down_trylock(&receive_sem))
        return;
    struct sk_buff* skb = skb_get(__skb);

    struct nlmsghdr *nlh = nlmsg_hdr(skb);
    printk("nlh->nlmsg_type: %d, nlh->nlmsg_pid: %d\n", nlh->nlmsg_type, nlh->nlmsg_pid);
    // while (NLMSG_OK(nlh, len)) {
        pid = nlh->nlmsg_pid;
        if(nlh->nlmsg_type == ACTION_SUMMARY){
            send_to_user(INFO_SUMMARY);
        }else if (nlh->nlmsg_type == ACTION_CLEAR_NEW){
             printk("clear new.....\n");
             struct timeval tv;
             do_gettimeofday(&tv);
             nf_info_offline_devs(tv.tv_sec);
        }else if(nlh->nlmsg_type == ACTION_CLEAR_ALL){
            printk("clear all.....\n");
            nf_info_destory();
        }else if(nlh->nlmsg_type == ACTION_ONLINE){
        // nf_info_destory();
            printk("get online.....\n");

            send_to_user(INFO_ONLINE);
        }
        // nlh = NLMSG_NEXT(nlh, len);
    // }
    // spin_unlock_bh(&buf_lock);
    kfree_skb(skb);
    up(&receive_sem);

}




static int __init traffic_init(void) {
	int ret = 0;


    printk("init traffic, ignore interface: %s\n", ignore_if);

    nf_info_init();
    hm_conntrack_create();
    rwlock_init(&buf_lock);
    sema_init(&receive_sem, 1);
    nlfd = netlink_kernel_create(&init_net, NETLINK_DEV_NUM, 0, kernel_receive, NULL, THIS_MODULE);

    printk("fd: %d\n", nlfd);

    return ret;
}
 
static void __exit traffic_eixt(void) {
    printk("uninit traffic\n");
    
    sock_release(nlfd->sk_socket);

    hm_conntrack_destroy();
    nf_info_destory();

}
  
module_init(traffic_init);
module_exit(traffic_eixt);

