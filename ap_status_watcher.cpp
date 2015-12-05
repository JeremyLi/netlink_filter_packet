//Author:    Huang Minglong(loong4life@gmail)
//Created:  2013-11-01
#include <iostream>
#include <string>
#include <vector>
#include "Util.h"
#include "CommandExecutor.h"
#include "InfoReporter.h"

#include "ap_manager.h"

int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "usage:ap_status_watcher configPath\n");
        exit(1);
    }

    std::string configFile = std::string(argv[1]);
    Json::Value config;
    Util::loadJson(configFile, config);

    std::string baseIp              = config["base_ip"].asString();
    int segmentBegin                = config["segment_begin"].asInt();
    int segmentEnd                  = config["segment_end"].asInt();
    int checkInterval               = config["check_interval"].asInt();
    std::string apKeyPath           = config["ap_key_path"].asString();
    std::string apConnectUsername   = config["ap_connect_username"].asString();
    int apConnectPort               = config["ap_connect_port"].asInt();
    int apConnectTimeout            = config["ap_connect_timeout"].asInt();
    std::string apActivateCmd       = config["ap_activate_cmd"].asString();

    if (baseIp.size() < 0) {
        fprintf(stderr, "config file maybe wrong, please check\n");
        exit(1);
    }

    if (!APManagerInst::instance().init(checkInterval, baseIp, segmentBegin, segmentEnd)) {
    	std::cout<<"init ap manager failed......."<<std::endl;

    	exit(1);
    }

    APManagerInst::instance().initApActivation(apKeyPath, apConnectUsername, apConnectPort,
        apConnectTimeout, apActivateCmd);

    while (true) {
    	std::vector<std::string>& tokens = APManagerInst::instance().scanAP();
    	if (tokens.size() > 0) {
    		APManagerInst::instance().handleScannedOnlineAP(tokens);
    	}

        sleep(checkInterval);
    }

    APManagerInst::instance().release();

    return 0;
}
