#include "nf_info_list.h"

#define INIT_RCU_HEAD(ptr)  do {(ptr)->next = NULL; (ptr)->func = NULL;} while (0) 

static spinlock_t info_lock;
static struct hlist_head hash_info[DENYHASHSZ];
static char* format = "{\"dev_count\":%d,\"new_devs\":[%s]}";
static char buf[MAC_BUF_LEN]={0};
static atomic_t dev_count;
static int open_count = 0;
// static int report_completed = 1;

void nf_info_init(void) {
	int bucket;
	/* initialize hash table */
	for (bucket = 0; bucket < DENYHASHSZ; bucket++) {
		INIT_HLIST_HEAD(&hash_info[bucket]);
    }
	spin_lock_init(&info_lock);
	atomic_set(&dev_count, 0);
}

struct nf_conntrack_info* has_nf_info(struct mac_addr* mac) {
    struct nf_conntrack_info *item;
	struct hlist_head *head;
    struct hlist_node *node;
	// struct ip_port_bucket ipbucket;
	int bucket;

	if (mac == NULL) {
		return NULL;
	}

    bucket = jhash(mac, sizeof(struct mac_addr), 0) % DENYHASHSZ;

    spin_lock_bh(&info_lock);
    head = &hash_info[bucket];
	if (head == NULL) { 
		spin_unlock_bh(&info_lock);
		return NULL;
	}

	// rcu_read_lock_bh();
	hlist_for_each_entry(item, node, head, hlist) {
		if (item) {
			if (mac_addr_equal(&(item->mac_addr), mac) == 0) {
				// item->uptime = uptime;
				// atomic_set(&item->state, IS_ONLINE);
				// atomic_add(1, &dev_count);
				// rcu_read_unlock_bh();
				spin_unlock_bh(&info_lock);
				spin_lock_bh(&item->lock);
				return item;
			} 
		}
	}
	// rcu_read_unlock_bh();
	spin_unlock_bh(&info_lock);
	return NULL;
}

int nf_info_add(struct mac_addr* mac, time_t uptime) {
	int bucket;
	// int ctinfo;
	// struct ip_port_bucket ipbucket;
    struct nf_conntrack_info* item = NULL;

	if (mac == NULL) {
		return -1;
	}

	item = kzalloc(sizeof(struct nf_conntrack_info), GFP_ATOMIC);

    if(!item) {
        printk(KERN_ERR "kmalloc mem error!\n");
        return -1;
    }
	 
	atomic_set(&item->state, IS_NEW_ADDED);
	atomic_set(&item->report_completed, 0);
	item->uptime = uptime;
	memcpy(item->mac_addr.mac, mac->mac, 6);
	atomic_add(1, &dev_count);

    bucket = jhash(mac, sizeof(struct mac_addr), 0) % DENYHASHSZ;
    INIT_HLIST_NODE(&item->hlist);
	spin_lock_init(&item->lock);
	spin_lock_bh(&info_lock);
    hlist_add_head(&item->hlist, &hash_info[bucket]);
	spin_unlock_bh(&info_lock);

	return 0;
}


void nf_info_destory(void){
	int bucket;

	spin_lock_bh(&info_lock);
	for (bucket = 0; bucket < DENYHASHSZ; bucket++) {
        struct nf_conntrack_info *item;
		struct hlist_head *head;
	    struct hlist_node *node, *tmp;

        head = &hash_info[bucket];
        if (head == NULL) { 
			continue;
		}
		hlist_for_each_entry_safe(item, node, tmp, head, hlist) {
			if (item) {
				hlist_del(node);
				info_free(item);
			}
		}
    }
    atomic_set(&dev_count, 0);
    spin_unlock_bh(&info_lock);
}

 
void nf_info_update(struct nf_conntrack_info* item, time_t uptime) {
	item->uptime = uptime;
	if (atomic_read(&item->state) == IS_OFFLINE)
	{
		atomic_add(1, &dev_count);
		atomic_set(&item->state, IS_ONLINE);
	}
}

int mac_addr_equal(const struct mac_addr* s, const struct mac_addr* d){
	if (s == NULL || d == NULL){
		return -1;
	}

	return memcmp(s->mac, d->mac, 6);
}

void info_free(struct nf_conntrack_info * info){
	if (info == NULL) {
		return;
	}

	if (info) {
		kfree(info);
	}
}

int nf_info_summary(time_t uptime, char* summary){
	int bucket;
	int count = 0;
	int allcount = 0;
	printk("-------------------->summary called, open_count: %d\n", ++open_count);
	char mac_addr[32]={0};
	char* buf_index = buf;
	spin_lock_bh(&info_lock);
	buf[0] = '\0';

	for (bucket = 0; bucket < DENYHASHSZ; bucket++) {
        struct nf_conntrack_info *item;
		struct hlist_head *head;
	    struct hlist_node *node;
	    // printk("in bucket for loop\n");
        head = &hash_info[bucket];
		hlist_for_each_entry(item, node, head, hlist) {
			if (item) {
				spin_lock_bh(&item->lock);
				// printk("in hlist for loop, state: %d, report_completed: %d, all count: %d\n", atomic_read(&item->state), atomic_read(&item->report_completed), ++allcount);
				if (atomic_read(&item->state) == IS_NEW_ADDED && atomic_read(&item->report_completed) == 0) {
					if (buf_index - buf + 20 + 28 + 10 < MAC_BUF_LEN) { // add format str length
						sprintf(mac_addr,"%02x-%02x-%02x-%02x-%02x-%02x", item->mac_addr.mac[0], item->mac_addr.mac[1],
						item->mac_addr.mac[2], item->mac_addr.mac[3], item->mac_addr.mac[4], item->mac_addr.mac[5]);
						// printk("new_devs: %s, count: %d\n", mac_addr, ++count);
				        sprintf(buf_index, "\"%s\",", mac_addr);
				        buf_index += (17 + 3); //strlen(buf) + 4; //17 + 4
				        atomic_set(&item->report_completed, 1);
					}else{
						spin_unlock_bh(&item->lock);
						printk("-------------------------------->break hlist for loop, len: %d\n", buf_index - buf);
						goto summary;
					}
				}
				spin_unlock_bh(&item->lock);
			}
		}
    }

summary:
    if (buf[0] != '\0'){
    	buf_index -= 1;
    }
    buf_index[0] = '\0';

    int len = sprintf(summary, format, atomic_read(&dev_count), buf);

    // printk("buf: %s, summary: %s\n", buf, summary);

    spin_unlock_bh(&info_lock);


    return len;
}

int nf_info_online_devs(char* online_devs){
	int bucket;
	int count = 0;
	/* initialize hash table */
	char mac_addr[32]={0};
	char* buf_index = online_devs;
	spin_lock_bh(&info_lock);
	online_devs[0] = '\0';
	for (bucket = 0; bucket < DENYHASHSZ; bucket++) {
        struct nf_conntrack_info *item;
		struct hlist_head *head;
	    struct hlist_node *node;

        head = &hash_info[bucket];
		hlist_for_each_entry(item, node, head, hlist) {
			if (item) {
				spin_lock_bh(&item->lock);
				if (atomic_read(&item->state) != IS_OFFLINE && count + 18 < MAC_BUF_LEN) {
					sprintf(mac_addr,"%02x-%02x-%02x-%02x-%02x-%02x", item->mac_addr.mac[0], item->mac_addr.mac[1],
					 item->mac_addr.mac[2], item->mac_addr.mac[3], item->mac_addr.mac[4], item->mac_addr.mac[5]);
					// buf[2] = buf[5] = buf[8] = buf[11] = buf[14] = '-';
					printk("online_devs: %s\n", mac_addr);
			        sprintf(buf_index, "%s\n", mac_addr);
			        buf_index += (17 + 1); //strlen(buf) + 4; //17 + 4
			        count += 18;
				}
				// else{
				// 	spin_unlock_bh(&item->lock);
				// 	break;
				// }
				spin_unlock_bh(&item->lock);

			}
		}
    }

    buf_index[0] = '\0';

    spin_unlock_bh(&info_lock);
    return count;
}


int nf_info_offline_devs(time_t uptime){
	int bucket;
	/* initialize hash table */
	// char mac_addr[32]={0};
	spin_lock_bh(&info_lock);
	buf[0] = '\0';
	for (bucket = 0; bucket < DENYHASHSZ; bucket++) {
        struct nf_conntrack_info *item;
		struct hlist_head *head;
	    struct hlist_node *node;

        head = &hash_info[bucket];
		hlist_for_each_entry(item, node, head, hlist) {
			if (item) {
				spin_lock_bh(&item->lock);
				if (atomic_read(&item->state) == IS_NEW_ADDED && atomic_read(&item->report_completed) == 1) {
					// set state
					if (item->uptime + TIMEOUT > uptime) {
						atomic_set(&item->state, IS_ONLINE);
					}else{
						atomic_set(&item->state, IS_OFFLINE);
						atomic_sub(1, &dev_count);
						printk("-----------offline dev...\n");
					}
				}else if (atomic_read(&item->state) == IS_ONLINE)	{
					if (item->uptime + TIMEOUT < uptime)
					{
						atomic_set(&item->state, IS_OFFLINE);
						atomic_sub(1, &dev_count);
				        printk("-----------offline dev...\n");
					}
				}
				spin_unlock_bh(&item->lock);

			}
		}
    }

    spin_unlock_bh(&info_lock);


    return 0;
}
