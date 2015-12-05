//Author:     Li Leigang(lileigang@shidou.com)
//Created:    2015-11-05
#pragma once

#include <iostream>
#include <vector>
#include <pcap.h>
#include <boost/thread/mutex.hpp>
#include <boost/thread/thread.hpp> 
#include <boost/shared_ptr.hpp>
#include <sys/time.h>
#include <linux/netlink.h>


#include "InfoReporter.h"
#include "RedisSet.h"
#define NETLINK_DEV_NUM 30
#define BUF_LENGTH 8192
char buf[BUF_LENGTH]={0};
// char action[16]={0};

#define ACTION_SUMMARY   0
#define ACTION_CLEAR_NEW 1
#define ACTION_CLEAR_ALL 2
#define ACTION_ONLINE    3



using namespace std;

class MacAddr
{
public:
    MacAddr(uint8_t addr[6]);
    ~MacAddr();
    string toAscii();
    int compaire(MacAddr& o){return memcmp(this->mac_addr, o.mac_addr, 6);}
    // int compaire(char* o){char buf[32]={0}; this->toAscii(buf); return strcmp(buf, o);}
    void updateTimestamp();
    int timeDiff(struct timeval cur);
private:
    uint8_t mac_addr[6];
    struct timeval timestamp;
};


class NetTrafficInfoCollector
{
public:
     NetTrafficInfoCollector(int interval, string redis_addr);
    ~NetTrafficInfoCollector();

    void setInterval(int interval) { this->report_interval = interval; }
    void setRedisKey(string key);

    void startCollectorAndReporter();


private:

    RedisSet* mac_addr_redis_set;

    int report_interval;
    string redis_set_key;
    InfoReporter* info_reporter;
};
