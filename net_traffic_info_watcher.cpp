//Author:     Li Leigang(lileigang@shidou.com)
//Created:    2015-11-06

#include <iostream>
#include <signal.h>
#include <json/json.h>
#include "Util.h"
#include "QuickLogger.h"
#include "NetTrafficInfoCollector.h"

extern NetTrafficInfoCollector* net_traffic_ptr;



void sig_handler(int signum)  
{  
    cout<<"receive signal: "<<signum<<endl;
    if (net_traffic_ptr != NULL)
     {
         net_traffic_ptr->getOnlineDevs();
     } 
}  

int main(int argc, char* argv[]) {

	if (argc != 2) {
        fprintf(stderr, "usage:system_info_watcher configPath\n");
        exit(1);
    }

    signal(10, sig_handler);

    std::string configFile         = std::string(argv[1]);
    std::cout<<configFile<<std::endl;
    Json::Value config;
    Util::loadJson(configFile, config);
    int port                       = config.isMember("info_report_port") ? config["info_report_port"].asInt() : 1024;
    int interval                   = config.isMember("info_report_interval") ? config["info_report_interval"].asInt() : 60;
    string key 					   = config.isMember("redis_key") ? config["redis_key"].asString() : "shidou-gateway-new-added-mac-set-key";
    string redis 				   = config.isMember("redis_server_addr") ? config["redis_server_addr"].asString() : "127.0.0.1:6379";

    net_traffic_ptr = new NetTrafficInfoCollector(interval, redis);
    // net_traffic.setInterval(interval);
    // cout<<"-------------->net_traffic: "<<net_traffic<<endl;

    net_traffic_ptr->setRedisKey(key);
    net_traffic_ptr->startCollectorAndReporter();
    return 0;
}
