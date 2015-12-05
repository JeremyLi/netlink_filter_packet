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



MODULE_LICENSE("GPL");
MODULE_LICENSE("copyright (c) 2015 shidou.co.ltd");
MODULE_AUTHOR("Jeremy Li");
MODULE_DESCRIPTION("shidou's capture");
MODULE_VERSION("1.0.0.0");

#define MONITOR_DEV_FILE_NAME "/home/sdcm/conf/model"
#define FILE_NAME_MAX_LEN   16

static long count=10000;

module_param(count, long, 0644);  
MODULE_PARM_DESC(count, "int param: ignore interface\n"); 
 
static int __init traffic_init(void) {
    int ret = 0;
    long value = 1;
    long i=0, j=0;
    printk("init traffic, count count: %d\n", count);

    for(i=0; i<count; i++){
        for(j=0; j<count; j++){
            value += i*j + i/j;
            printk("value = %l\n", value);
        }
    }

    return ret;
}
 
static void __exit traffic_eixt(void) {
    printk("uninit traffic\n");
    
}
  
module_init(traffic_init);
module_exit(traffic_eixt);

