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


#include "nf_info_list.h"
// #include "file_io_module.h"


MODULE_LICENSE("GPL");
MODULE_LICENSE("copyright (c) 2015 shidou.co.ltd");
MODULE_AUTHOR("Jeremy Li");
MODULE_DESCRIPTION("shidou's capture");
MODULE_VERSION("1.0.0.0");

#define MONITOR_DEV_FILE_NAME "/home/sdcm/conf/model"
#define FILE_NAME_MAX_LEN   16

static char* ignore_if="eth2";
static char seq_buf[MAC_BUF_LEN];
static spinlock_t buf_lock;
static int  content_len = 0;
static int  current_start = 0;
static int  current_end = 0;
static char online_buf[MAC_BUF_LEN];

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

static int dev_enter_promiscuity(const char* name)
{
    struct net_device *dev = dev_get_by_name(&init_net, name);
    if (dev != NULL) {
        if(dev->flags & IFF_PROMISC) {
            // hm_debug("HTTP_MANGER: dev %s! already in promisc mode\n", name);
            return 0;
        }

        rtnl_lock();
        dev_set_promiscuity(dev, 1);
        rtnl_unlock();
        dev_put(dev);
        return 0;
    } else {
        // hm_debug("HTTP_MANGER: cannot find dev %s!\n", name);
        return -1;
    }

    return 0;
}

static int dev_exit_promiscuity(const char* name)
{
    struct net_device *dev = dev_get_by_name(&init_net, name);
    if (dev != NULL) {
        if(!(dev->flags & IFF_PROMISC)) {
            // hm_debug("HTTP_MANGER: dev %s! already exit promisc mode\n", name);
            return 0;
        }

        //rtnl_lock is need, or Call Stack
        rtnl_lock();
        dev_set_promiscuity(dev, -1);
        rtnl_unlock();
        dev_put(dev);
        return 0;
    } else {
        // hm_debug("HTTP_MANGER: cannot find dev %s!\n", name);
        return -1;
    }

    return 0;
}

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


void* shidou_new_devs_seq_start(struct seq_file *seq, loff_t * pos){
    loff_t index = *pos;
    if(index == 0){

        current_start = 0;
        current_end = 0;
        struct timeval tv;
        do_gettimeofday(&tv);
        spin_lock_bh(&buf_lock);
        content_len = nf_info_summary(tv.tv_sec, seq_buf);
      // next_fortune += len;
        seq_buf[content_len] = '\0';
        spin_unlock_bh(&buf_lock);
        // return pos;
        printk("content_len: %d, current_end: %d, start: %d\n", content_len, current_end, index);

        return &current_end;
    }else if (current_end <= content_len) {
        // *pos += 2048 - 1; 
        printk("content_len: %d, current_end: %d, start: %d\n", content_len, current_end, index);
        return &current_end;
    }
    // *pos = 0;
    printk("content_len: %d, current_end: %d, start: %d\n", content_len, current_end, index);
    return NULL;
}

void *shidou_new_devs_seq_next(struct seq_file *seq, void *p, loff_t * pos)
{
        spin_lock_bh(&buf_lock);
        
        // char* buf_index = seq_buf + *pos;
        (*pos)++;

        printk("content_len: %d, next: %d\n", content_len, current_start);

        if (content_len - current_end >= 2048) {
            // current_off = 2048;
            // *pos  += 2048;
            // current_end += 2048;
            spin_unlock_bh(&buf_lock);
            return &current_end;
        }else{
            // current_off = content_len - *pos;
            // *pos = content_len;
            // current_end = content_len;
            spin_unlock_bh(&buf_lock);
            return NULL;
        }
}

void shidou_new_devs_seq_stop(struct seq_file *m, void *p)
{
}


int shidou_new_devs_seq_show(struct seq_file *m, void *p)
{
        if(p == NULL) return -1;
        spin_lock_bh(&buf_lock);
        // char* buf_index = (char*) p;
        // unsigned int i = *(loff_t *)p;
        // current_start = current_end;
        if (content_len - current_end >= 2048){
            current_end += 2048;
        }else{
            current_end = content_len;
        }
        printk("show: %d--->%d\n", current_start, current_end);

        char tmp = seq_buf[current_end];
        seq_buf[current_end] = '\0';
        seq_puts(m, seq_buf + current_start);
        seq_buf[current_end] = tmp;
        // if (current_end == content_len){
        //     seq_buf[current_end] = '\0';
        // }

        current_start = current_end;

        spin_unlock_bh(&buf_lock);
        return 0;
}

static struct seq_operations shidou_new_devs_seq_ops = {
    .start = shidou_new_devs_seq_start,
    .next  = shidou_new_devs_seq_next,
    .stop  = shidou_new_devs_seq_stop,
    .show  = shidou_new_devs_seq_show
};

int shidou_new_devs_open(struct inode *inode, struct file *file){
        return seq_open(file, &shidou_new_devs_seq_ops);
}

ssize_t shidou_new_devs_write(struct file *file, const char __user *buf,
                             size_t count, loff_t *ppos)
{
    char command[16] = {0};
    int len = count;
    if (len > 15)
    {
        len = 15;
    }
    copy_from_user(command, buf, len);  
    command[len] = '\0';

    struct timeval tv;
    do_gettimeofday(&tv);
    printk("command: %s\n", command);
    if (strncmp(command, "clearAll", 8) == 0){
        // printk("clearAll\n");
        nf_info_destory();
    }else if (strncmp(command, "clearNew", 8) == 0)
    {
        // printk("clearNew\n");
        nf_info_offline_devs(tv.tv_sec);
    }
    return count;
}
 

static const struct file_operations shidou_proc_fops = {
 .owner = THIS_MODULE,
 .open  = shidou_new_devs_open,
 .read  = seq_read,
 .write  = shidou_new_devs_write,
 .llseek  = seq_lseek,
 .release = seq_release,
};

int shidou_online_devs_show(struct seq_file *seq, void *v){
    int len;

    len = nf_info_online_devs(online_buf);
  // next_fortune += len;
    online_buf[len] = '\0';
    seq_puts(seq, online_buf);
    return 0;
}

int shidou_online_devs_open(struct inode *inode, struct file *file){
    return single_open(file, shidou_online_devs_show, NULL);
}
static const struct file_operations shidou_online_proc_fops = {
 .owner = THIS_MODULE,
 .open  = shidou_online_devs_open,
 .read  = seq_read,
 .write  = seq_write,
 .llseek  = seq_lseek,
 .release = single_release,
};

static int __init traffic_init(void) {
	int ret = 0;

    // int len = 0;
    // char model[FILE_NAME_MAX_LEN]={0};

    // struct file*  _file = klib_fopen(MONITOR_DEV_FILE_NAME, O_RDONLY, S_IRUSR);

    // if ( _file == NULL ) {
    //     return -1;
    // }
        
    // memset(model, 0x00, FILE_NAME_MAX_LEN);
    // len  = klib_fgets(model, FILE_NAME_MAX_LEN - 1, _file);

    // if ( len <= 0 ) {
    //     return -1;
    // }

    // klib_fclose(_file);

    // if (model[len-1] == '\n') {
    //     model[len-1] = '\0';
    // }

    // devname[0] = 'e';
    // devname[1] = 't';
    // devname[2] = 'h';
    // if (strncmp(model, "gateway", 7) == 0) {
    //     devname[3] = '0';
    // }else{
    //     devname[3] = '2';
    // }

    // devname[4] = '\0';
    printk("init traffic, ignore interface: %s\n", ignore_if);

    nf_info_init();
    hm_conntrack_create();
    spin_lock_init(&buf_lock);

    static struct proc_dir_entry *proc_entry;
    proc_entry = proc_create( "shidou_new_devs", 0666, NULL, &shidou_proc_fops);
    if (proc_entry == NULL) {
      ret = -ENOMEM;
      printk(KERN_INFO "shidou_new_dev: Couldn't create proc entry\n");
    }

    static struct proc_dir_entry *online_proc_entry;
    online_proc_entry = proc_create( "shidou_online_devs", 0444, NULL, &shidou_online_proc_fops);
    if (online_proc_entry == NULL) {
      ret = -ENOMEM;
      printk(KERN_INFO "shidou_new_dev: Couldn't create proc entry\n");
    }

    return ret;
}
 
static void __exit traffic_eixt(void) {
    printk("uninit traffic\n");

    remove_proc_entry("shidou_new_devs", NULL);
    remove_proc_entry("shidou_online_devs", NULL);

    hm_conntrack_destroy();
    nf_info_destory();


    // vfree(cookie_pot);
    printk(KERN_INFO "shidou_new_dev: Module unloaded.\n");
}
  
module_init(traffic_init);
module_exit(traffic_eixt);

