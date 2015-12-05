#ifndef NF_INFO_LIST_HEAD
#define NF_INFO_LIST_HEAD
#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/ktime.h>
#include <asm/atomic.h>
#include <linux/types.h>
// #include <linux/rcupdate.h>
// #include <linux/rculist.h>
#define DENYHASHSZ        2048
#define TIMEOUT           60
#define INTERVAL_TIME     10

#define IS_NEW_ADDED	  1
#define IS_ONLINE	      2
#define IS_OFFLINE        3
#define MAC_BUF_LEN       8192

struct mac_addr {
	unsigned char mac[6];
}__attribute__((aligned(1)));

 
struct nf_conntrack_info {
	struct hlist_node hlist;
	struct mac_addr mac_addr;
	// struct rcu_head rcu;
	time_t uptime;
	atomic_t state;
	// void *ext;
	atomic_t report_completed;
	spinlock_t lock;
}__attribute__((aligned(1)));


int mac_addr_equal(const struct mac_addr* s, const struct mac_addr* d);

void info_free(struct nf_conntrack_info* info);

void nf_info_init(void);

struct nf_conntrack_info* has_nf_info(struct mac_addr* mac);

int nf_info_add(struct mac_addr* mac, time_t uptime);

int nf_info_summary(time_t uptime, char* summary);
// unsigned long nf_info_del(struct ip_port* ip);

void nf_info_destory(void);

// void info_free_rcu(struct rcu_head * head);

void nf_info_update(struct nf_conntrack_info*info, time_t uptime) ;

int nf_info_online_devs(char* online_devs);

int nf_info_offline_devs(time_t uptime);

#endif
