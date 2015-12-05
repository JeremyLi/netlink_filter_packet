//Author:     Huang Minglong(loong4life@gmail)
//Created:    2013-05-15
#include <iostream>
#include <vector>
#include "InfoReporter.h"
#include "Util.h"
#include "SystemInfoCollector.h"
#include "QuickLogger.h"
#include "ConfigHelper.h"
#include "CommandExecutor.h"

enum ModelType {
    ModelGateway,
    ModelShadow,
    ModelShadewitch,
    ModelShadewitchO,
    ModelDefault
};

bool isInList(std::string name, std::vector<std::string> list) {
    return std::find(list.begin(), list.end(), name)!=list.end();
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "usage:module_info_watcher configPath\n");
        exit(1);
    }

    std::string configFile         = std::string(argv[1]);
    Json::Value config;
    Util::loadJson(configFile, config);
    int port                         = config.isMember("info_report_port") ? config["info_report_port"].asInt() : 1024;
    int interval                     = config.isMember("info_report_interval") ? config["info_report_interval"].asInt() : 60;
    Json::Value commonModules        = config["common_modules"];
    Json::Value modulesRestartAction = config["modules_restart_action"];
    bool isModulesRestartEnabled     = config["modules_restart_enabled"].asBool();
    Json::Value gatewayRelatedModules = config["device_related_modules"]["gateway_related"];
    Json::Value defaultRelatedModules = config["device_related_modules"]["default_related"];
    Json::Value shadowRelatedModules = config["device_related_modules"]["shadow_related"];
    Json::Value shadewitchRelatedModules = config["device_related_modules"]["shadewitch_related"];
    Json::Value shadewitchORelatedModules = config["device_related_modules"]["shadewitch-o_related"];
    Json::Value x86RelatedModules     = config["device_related_modules"]["x86_related"];
    Json::Value armRelatedModules     = config["device_related_modules"]["arm_related"];
    std::string checkModelCmd = config["check_model_cmd"].asString();
    std::string bypassEnablePath = config["bypass_enable_path"].asString();
    std::string shadewitchEnablePath = config["shadewitch_enable_path"].asString();
    std::string wifidogEnablePath = config["wifidog_enable_path"].asString();

    Json::Value modulesSwitch;
    Util::loadJson(ConfigHelper::getModulesFilePath(), modulesSwitch);
    bool disableWlan            = false;
    bool disableBypass          = false;
    bool disableShadewitch      = false;
    bool disableWifidog         = false;

    if (!modulesSwitch.isNull()) {
        disableWlan = modulesSwitch["wlan"].asString()=="off" ? true : false;
    }

    std::string bypassEnableContent;
    if (!Util::fileGetContents(bypassEnablePath, bypassEnableContent) || Util::trim(bypassEnableContent) != "1") {
        disableBypass = true;
    }

    std::string shadewitchEnableContent;
    Util::fileGetContents(shadewitchEnablePath, shadewitchEnableContent);
    if (Util::trim(shadewitchEnableContent) == "0") {
        disableShadewitch = true;
    }

    std::string wifidogEnableContent;
    Util::fileGetContents(wifidogEnablePath, wifidogEnableContent);
    if (Util::trim(wifidogEnableContent) == "0") {
        disableWifidog = true;
    }
    
    std::string deviceModel = Util::trim(CommandExecutor::execute(checkModelCmd));
    ModelType modelType = ModelDefault;

    if (deviceModel == "gateway") modelType = ModelGateway;
    if (deviceModel == "shadow") modelType = ModelShadow;
    if (deviceModel == "shadewitch") modelType = ModelShadewitch;
    if (deviceModel == "shadewitch-o") modelType = ModelShadewitchO;
    
    LOGI("device model is %s", deviceModel.c_str());

    InfoReporter* infoReporter = InfoReporter::getInstance();
    infoReporter->setName("modules");
    infoReporter->setInterval(interval);

    std::vector<std::string> ignoreModules;
    std::vector<std::string> watchModules;

    for (Json::ValueIterator it = commonModules.begin(); it != commonModules.end(); it++) {
        watchModules.push_back((*it).asString());
    }

    if (modelType == ModelDefault) {
        for (int i = 0; i < defaultRelatedModules.size(); i++) {
            watchModules.push_back(defaultRelatedModules[i].asString());
        }
    } else if (modelType == ModelGateway) {
        for (int i = 0; i < gatewayRelatedModules.size(); i++) {
            watchModules.push_back(gatewayRelatedModules[i].asString());
        }
    } else if (modelType == ModelShadow) { 
        for (int i = 0; i < shadowRelatedModules.size(); i++) {
            watchModules.push_back(shadowRelatedModules[i].asString());
        }
    } else if (modelType == ModelShadewitch) {
        for (int i = 0; i < shadewitchRelatedModules.size(); i++) {
            watchModules.push_back(shadewitchRelatedModules[i].asString());
        }

        if (disableShadewitch) {
            LOGI("Shadewitch is disabled");
            ignoreModules.push_back("shadewitch");
        }
    } else if (modelType == ModelShadewitchO) {
        for (int i = 0; i < shadewitchORelatedModules.size(); i++) {
            watchModules.push_back(shadewitchORelatedModules[i].asString());
        }

        if (disableBypass) {
            LOGI("Bypass is disabled");
            ignoreModules.push_back("bypass_watchdog");
        }

        if (disableShadewitch) {
            LOGI("Shadewitch is disabled");
            ignoreModules.push_back("shadewitch");
        }
    }

    if (disableWifidog) {
        LOGI("Wifidog is disabled");
        ignoreModules.push_back("wifidog");
    }

#ifdef __ARM_EABI__
    //arm platform, so ignore x86 related modules
    for (int i = 0; i < x86RelatedModules.size(); i++) {
        ignoreModules.push_back(x86RelatedModules[i].asString());
    }
#else
    //x86 platform, so ignore arm related modules
    for (int i = 0; i < armRelatedModules.size(); i++) {
        ignoreModules.push_back(armRelatedModules[i].asString());
    }   
#endif

    while (true) {
        sleep(interval-1);
        
        //check if moudle is alive
        std::vector<std::string>::const_iterator it = watchModules.begin();
        bool hasChecked = false;

        for (; it != watchModules.end(); it++) {
            std::string moduleName = (*it);

            if (!isInList(moduleName, ignoreModules)) {
                std::string moduleStatus = SystemInfoCollector::getModuleStatus(moduleName);

                std::string message = "{\"status\":\"" + moduleStatus + "\",\"message\":\"\"}";
                if (moduleName == "net_traffic_info_watcher") {
                    if (moduleStatus == "off") {
                        moduleName = "net_traffic";
                        message = "{\"status\":\"off\",\"message\":\"\"}";
                    }else {
                        continue;
                    }
                }
                infoReporter->collect(moduleName, message);

                if (isModulesRestartEnabled && moduleStatus == "off") {
                    //restart the service
                    if (modulesRestartAction.isMember(moduleName)) {
                        std::string action = modulesRestartAction[moduleName].asString();
                        LOGI("restart %s", moduleName.c_str());
                        system(action.c_str());
                    }
                }
            }
        }
    }

    return 0;
}
