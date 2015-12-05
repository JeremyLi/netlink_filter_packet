//Author:     Huang Minglong(loong4life@gmail)
//Created:    2013-05-15
#include <iostream>
#include <vector>
#include "InfoReporter.h"
#include "Util.h"
#include "QuickLogger.h"
#include "SystemInfoCollector.h"
#include "CommandExecutor.h"

static std::string deviceModel;

std::string generateMessage(SystemInfoItem& item) {
    Json::Value value;
    value["message"] = item.message;
    value["quantity"] = (int)(item.quantity);
    value["proportion"] = (float)item.proportion;

    std::cout << value.toStyledString() << std::endl;

    item.message ="";
    item.quantity = 0;
    item.proportion = 0;

    Json::FastWriter writer;
    return writer.write(value);
}

void* timeConsumingWorker(void* arg) {
    int* data = reinterpret_cast<int*>(arg);
    int interval = *data;
    delete data;
    std::string cacheIP = "";
    int MAX_CACHE_IP_TIME = 120; //30 minutes 
    int cacheIPTime = 0;
    time_t currentTime;
    SystemInfoItem item;
    InfoReporter* infoReporter = InfoReporter::getInstance();
    

    while (true) {
        currentTime = time(NULL);

        if (cacheIPTime > MAX_CACHE_IP_TIME || cacheIP.length() <= 0) {
            cacheIPTime = 0;
            SystemInfoCollector::getOnetAddr(item);
            if (item.message.length() > 0) {
                cacheIP = item.message;
            }
        } else {
            cacheIPTime++;
            item.message = cacheIP;
        }
        infoReporter->collect("onet_addr", generateMessage(item));
        LOGI("onet collect time: %d", time(NULL) - currentTime);

        if (deviceModel != "shadewitch" && deviceModel != "shadewitch-o") {
            SystemInfoCollector::getSquidMedianSvcTime(item);
            infoReporter->collect("squid_5min", generateMessage(item));
            LOGI("squid collect time: %d", time(NULL) - currentTime);
        }

        sleep(interval);
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "usage:system_info_watcher configPath\n");
        exit(1);
    }

    std::string configFile         = std::string(argv[1]);
    std::cout<<configFile<<std::endl;
    Json::Value config;
    Util::loadJson(configFile, config);
    int port                       = config.isMember("info_report_port") ? config["info_report_port"].asInt() : 1024;
    int interval                   = config.isMember("info_report_interval") ? config["info_report_interval"].asInt() : 60;

    deviceModel = Util::trim(CommandExecutor::execute("check-model.sh"));

    std::cout<<"port-->"<<port<<", interval-->"<<interval<<std::endl;
    InfoReporter* infoReporter = InfoReporter::getInstance();
    infoReporter->setName("systems");
    infoReporter->setInterval(interval);

    SystemInfoItem item;
    SystemInfoItem in;
    SystemInfoItem out;

    time_t lastTime  = time(NULL);
    time_t currentTime = time(NULL);

    infoReporter->setInterval(interval);

    //create time consuming working
    pthread_t timeComsumingWork;
    int rc = pthread_create(&timeComsumingWork, NULL, timeConsumingWorker, (void *)(new int(interval)));
    if (rc) {
        LOGE("error to create thread, exit");
        exit(-1);
    }
    pthread_detach(timeComsumingWork);

    while (true) {
        SystemInfoCollector::getCpuUsage(item);
        infoReporter->collect("cpu_usage", generateMessage(item));

        SystemInfoCollector::getMemFree(item);
        infoReporter->collect("mem_free", generateMessage(item));

        SystemInfoCollector::getDiskFree(item);
        infoReporter->collect("disk_free", generateMessage(item));

        SystemInfoCollector::getInetAddr(item);
        infoReporter->collect("inet_addr", generateMessage(item));

        currentTime = time(NULL);
        time_t diffTime = currentTime - lastTime;
        SystemInfoCollector::getNetworkStatus(in, out, diffTime);
        infoReporter->collect("network_in", generateMessage(in));
        infoReporter->collect("network_out", generateMessage(out));
        lastTime = currentTime;

        SystemInfoCollector::getSoftwareSignature(item);
        infoReporter->collect("software_signature", generateMessage(item));

        SystemInfoCollector::getWebSignature(item);
        infoReporter->collect("web_signature", generateMessage(item));

        SystemInfoCollector::getSystemUpTime(item);
        infoReporter->collect("uptime", generateMessage(item));

        SystemInfoCollector::getLoadAverage(item);
        infoReporter->collect("load_avg", generateMessage(item));

        SystemInfoItem read_item, written_item;
        if (SystemInfoCollector::getDiskIO(read_item, written_item)) {
        	infoReporter->collect("disk_read", generateMessage(read_item));
        	infoReporter->collect("disk_write", generateMessage(written_item));
        } else {
        	std::cout<<"get disk io speed failed....."<<std::endl;
        }

        SystemInfoCollector::getTCPConnectionNum(item);
        infoReporter->collect("tcp_num", generateMessage(item));

        if (deviceModel == "shadewitch-o") {
            SystemInfoCollector::getBypassStatus(item);
            infoReporter->collect("bypass", generateMessage(item));
        }

        if (deviceModel == "shadewitch" || deviceModel == "shadewitch-o") {
            SystemInfoCollector::getShadewitchStatus(item);
            infoReporter->collect("shadewitch", generateMessage(item));
        }
        
        SystemInfoCollector::getConnectedDeviceNum(item);
        infoReporter->collect("con_device_num", generateMessage(item));

        sleep(interval);
    }

    return 0;
}
