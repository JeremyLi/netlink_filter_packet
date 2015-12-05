//Author:     Huang Minglong(loong4life@gmail)
//Created:    2013-05-15
#include <vector>
#include <boost/lexical_cast.hpp>
#include <boost/bind.hpp>
#include <boost/thread/thread.hpp>
#include <boost/filesystem.hpp>

#include "SystemInfoCollector.h"
#include "CommandExecutor.h"
#include "Util.h"
#include "CurlHttpClient.h"
#include "ConfigHelper.h"

extern "C" {
#include "iostat.h"
}

long SystemInfoCollector::lastCpuIdle     = 0;
long SystemInfoCollector::lastCpuTotal    = 0;
long long SystemInfoCollector::lastNetIn  = 0;
long long SystemInfoCollector::lastNetOut = 0;
std::string SystemInfoCollector::lastInterface = "eth0";
std::string SystemInfoCollector::currentInterface = "eth0";

boost::mutex SystemInfoCollector::disk_io_mutex;
std::map< std::string, DiskIOInfo* > SystemInfoCollector::disk_io_info_map;
int SystemInfoCollector::interval = 3;

std::string SystemInfoCollector::getCpuUsage(SystemInfoItem& item) {
    std::string result =  CommandExecutor::execute("sed -n 's/^cpu \\+//p' /proc/stat");
    
    char sep = ' ';
    std::vector<int> cpuTimes;
    for(size_t p=0, q=0; p!=result.npos; p=q) {
        cpuTimes.push_back(Util::stringToInt(result.substr(p+(p!=0), (q=result.find(sep, p+1))-p-(p!=0))));
    }

    long idle = cpuTimes[3];
    long total = 0;

    for (int i=0; i<cpuTimes.size(); i++) {
        total += cpuTimes[i];
    }

    long idleDiff = idle - lastCpuIdle;
    long totalDiff = total - lastCpuTotal;

    int usage = (1000 * (totalDiff - idleDiff) / totalDiff + 5) / 10;

    lastCpuIdle = idle;
    lastCpuTotal = total;

    item.message = Util::intToString(usage)+"%";
    item.quantity = usage;
    item.proportion = usage;

    return item.message;
}

std::string SystemInfoCollector::getMemFree(SystemInfoItem& item) {
    std::string freeMemory = CommandExecutor::execute("free -m | sed -n -e '3p' | grep -Po '\\d+$'");
    std::string totalMemory = CommandExecutor::execute("free -m | sed -n -e '2p' | awk '{print $2}'");

    std::string result = Util::trim(freeMemory) + " MB";

    item.message = result;
    item.quantity = Util::stringToInt(freeMemory);
    item.proportion = (item.quantity*100) / Util::stringToInt(totalMemory);

    return result;
}

std::string SystemInfoCollector::getDiskFree(SystemInfoItem& item) {
    std::string result = CommandExecutor::execute("df -m /home | awk 'END {print $4}'");
    int usage = Util::stringToInt(CommandExecutor::execute("df -m /home | awk 'END {print $5}' | sed 's#%##g'"));
    result = Util::trim(result);

    item.message = result + " MB";
    item.quantity = Util::stringToInt(result);
    item.proportion = 100 - usage;

    return result;
}

std::string SystemInfoCollector::getInetAddr(SystemInfoItem& item) {
    std::string eth0IP = Util::trim(CommandExecutor::execute("ifconfig eth0 | grep inet | awk '{print $2}' | cut -d ':' -f 2 | head -1"));
    std::string ppp0IP = Util::trim(CommandExecutor::execute("ifconfig ppp0 | grep inet | awk '{print $2}' | cut -d ':' -f 2 | head -1"));
    std::string br0IP = Util::trim(CommandExecutor::execute("ifconfig br0 | grep inet | awk '{print $2}' | cut -d ':' -f 2 | head -1"));
    std::string result = "";

    if (eth0IP.length() > 0 || ppp0IP.length() > 0) {
        currentInterface = "eth0";
        result = eth0IP;
    } else if (br0IP.length() > 0) {
        currentInterface = "br0";
        result = br0IP;
    }
    
    item.message = result;
    return result;
}

std::string SystemInfoCollector::getOnetAddr(SystemInfoItem& item) {
    std::string externalIPUri = ConfigHelper::getUri("external_ip");

    CurlHttpClient* curlHttpClient = new CurlHttpClient();
    curlHttpClient->doGet(externalIPUri);
    std::string result = curlHttpClient->getContent();
    result = Util::trim(result);
    delete curlHttpClient;

    item.message = result;

    return result;
}

std::string SystemInfoCollector::getModuleStatus(std::string name) {
    std::string command = "ps aux | grep -w " + name + " | grep -v 'grep'";

    if (name == "shadewitch") {
        command = "lsmod | grep " + name;
    }

    std::string result = CommandExecutor::execute(command);
    result = Util::trim(result);
    
    return (result.size() > 0 ? "working" : "off");
}

int SystemInfoCollector::getModuleRunningNum(std::string name) {
    std::string result = CommandExecutor::execute("ps aux | grep -w " + name + " | grep -v 'grep' | wc -l");
    return Util::stringToInt(Util::trim(result));
}

std::string SystemInfoCollector::getNetworkStatus(SystemInfoItem& inItem, SystemInfoItem& outItem,  time_t diffTime) {
    std::string interface = currentInterface;

    if (currentInterface != lastInterface) {
        lastNetIn = 0;
        lastNetOut = 0;
        lastInterface = currentInterface;
    }

    if (currentInterface == "br0") {
        interface = "eth2";
    }

    std::string inCmdStr  = "cat /proc/net/dev | grep -e " + interface + " | awk '{print $2}'";
    std::string outCmdStr = "cat /proc/net/dev | grep -e  " + interface + " | awk '{print $10}'";

    long long in = Util::stringToInt(CommandExecutor::execute(inCmdStr));
    long long out = Util::stringToInt(CommandExecutor::execute(outCmdStr));

    if (lastNetIn == 0 && lastNetOut == 0) {
        lastNetIn = in;
        lastNetOut = out;
    }

    if (diffTime <= 0) {
        diffTime = 30;
    }

    long long diffIn  = (in - lastNetIn + 512 ) / (1024 * diffTime);
    long long diffOut = (out - lastNetOut + 512) / (1024 * diffTime);

    inItem.message = Util::intToString(diffIn) + " KB/s";
    inItem.quantity = diffIn;

    outItem.message = Util::intToString(diffOut) + " KB/s";
    outItem.quantity = diffOut;

    lastNetIn  = in;
    lastNetOut = out;

    std::string result = Util::stringFormat("IN: %d KB/s OUT: %d KB/s", diffIn, diffOut);

    return result;
}

bool SystemInfoCollector::hasCamera() {
    std::string result = CommandExecutor::execute("ls /dev/video0 2>/dev/null");
    return result.size() > 0;
}

bool SystemInfoCollector::hasWlan() {
    std::string result = CommandExecutor::execute("ifconfig | grep \"wlan\" | grep \"Ethernet\"");
    return result.size() > 0;
}

std::string SystemInfoCollector::getSoftwareSignature(SystemInfoItem& item) {
    std::string result;
    Util::fileGetContents(ConfigHelper::getSoftwareSignatureFilePath(), result);
    item.message = result;

    return result;
}

std::string SystemInfoCollector::getSystemUpTime(SystemInfoItem& item) {
    std::string result = Util::trim(CommandExecutor::execute("cat /proc/uptime | cut -d '.' -f 1"));
    item.message = result;

    return result;
}

std::string SystemInfoCollector::getLoadAverage(SystemInfoItem& item) {
    std::string loadAverage = Util::trim(CommandExecutor::execute("uptime | grep -o 'load average:.*' | awk '{print $3}' | sed 's#,##g'"));
    std::string coreCount = Util::trim(CommandExecutor::execute("nproc"));

    item.message = "cores:" + coreCount + ",1m:" + loadAverage;
    item.quantity = Util::stringToInt(coreCount);
    item.proportion = boost::lexical_cast<float>(loadAverage);

    return item.message;
}

std::string SystemInfoCollector::getBypassStatus(SystemInfoItem& item) {
    std::string bypass_status;
    Util::fileGetContents("/tmp/bypass_status", bypass_status);
    bypass_status = Util::trim(bypass_status);
    
    if (bypass_status.length() <= 0) {
        bypass_status = "0";
    }

    item.message = bypass_status;
    item.quantity = Util::stringToInt(bypass_status);
    item.proportion = item.quantity;

    return item.message;
}

std::string SystemInfoCollector::getShadewitchStatus(SystemInfoItem& item) {
    std::string shadewtich_status = Util::trim(CommandExecutor::execute("lsmod | grep shadewitch"));

    if (shadewtich_status.length() > 0) {
        shadewtich_status = "1";
    } else {
        shadewtich_status = "0";
    }

    item.message = shadewtich_status;
    item.quantity = Util::stringToInt(shadewtich_status);
    item.proportion = item.quantity;

    return item.message;
}

std::string SystemInfoCollector::getConnectedDeviceNum(SystemInfoItem& item) {
    std::string deviceCount = Util::trim(CommandExecutor::execute("arp -i br0 -n | grep -v arp | grep -v incomplete | grep -v Address | wc -l"));

    item.message = deviceCount;
    item.quantity = Util::stringToInt(deviceCount);
    item.proportion = item.quantity;

    return item.message;
}

/*
 * parameter: void
 * return value: true: success, false: failed.
 * description: init disk io information.
 */
void SystemInfoCollector::setInterval(const int n) {
	interval = n;
}

/*
 * parameter：read speed, write speed
	return value：bool true: success, false: failed
	description：get current disk io speed(read,write).
 */
bool SystemInfoCollector::getDiskIO(SystemInfoItem& item_read, SystemInfoItem& item_written) {
	bool ret_value = false;

	//std::cout<<"SystemInfoCollector::getDiskIO-->"<<std::endl;

	static bool is_disk_io_initialized = false;

	if (!is_disk_io_initialized) {
		boost::thread t(boost::bind(&SystemInfoCollector::diskIOSpeedGetter));

		is_disk_io_initialized = true;
	} else {
		boost::mutex::scoped_lock scoped_lock(disk_io_mutex);

		std::map< std::string, DiskIOInfo* >::iterator it = disk_io_info_map.find(DiskIOInfo::getKey());
		if (it != disk_io_info_map.end()) {
			DiskIOInfo* dio = it->second;
			char buf[512];

			snprintf(buf, sizeof(buf), "read: %.1f kbps",
										dio->current_read_speed);
			item_read.message = buf;
			item_read.quantity = (long long)dio->current_read_speed;
			item_read.proportion = 0.0;

			snprintf(buf, sizeof(buf), "write: %.1f kbps",
										dio->current_write_speed);
			item_written.message = buf;
			item_written.quantity = (long long)dio->current_write_speed;
			item_written.proportion = 0.0;

			ret_value = true;
		}
	}

	//std::cout<<"SystemInfoCollector::getDiskIO-->end"<<std::endl;

	return ret_value;
}

/*
*parameter: device name; read speed; write speed;
*return value:void
*description: current statistic system disk io speed info notify.
*/
void SystemInfoCollector::disk_iostat_cb(const int count, const double read_speed, const double write_speed) {
	//printf("SystemInfoCollector::disk_iostat_cb----------------->\r\n");

	if (read_speed >= 0 && write_speed >= 0) {
	//	printf("disk_iostat_cb: read speed-->%f, write speed-->%f\r\n",
		//		read_speed, write_speed);

		DiskIOInfo* dio = new DiskIOInfo();
		if (dio) {
			boost::mutex::scoped_lock scoped_lock(disk_io_mutex);

			dio->current_read_speed = read_speed;
			dio->current_write_speed = write_speed;
			dio->count = count;

			std::map< std::string, DiskIOInfo* >::iterator it = disk_io_info_map.find(dio->getKey());
			if (it != disk_io_info_map.end()) {
				DiskIOInfo* previous_dio = it->second;

				if (previous_dio) {
					delete previous_dio;
					previous_dio = NULL;
				}

				disk_io_info_map.erase(it);
			}
			disk_io_info_map[dio->getKey()] = dio;
		}
	} else {
		printf("argument is not valid...............\r\n");
	}

	//printf("SystemInfoCollector::disk_iostat_cb----------------->end\r\n");
}

/*
 * parameter：dynamic get disk io speed.
return value：void
description：execute command “iostat -kd 3”,read result data and parse read & write speed and store to memory for
read.if iostat command doesn’t exist and internet is available, using apt-get tool to install it.
 */
void SystemInfoCollector::diskIOSpeedGetter(void) {
	//printf("SystemInfoCollector::diskIOSpeedGetter----------------->\r\n");

	start_iostat(interval, disk_iostat_cb);

	//printf("SystemInfoCollector::diskIOSpeedGetter----------------->end\r\n");
}

std::string SystemInfoCollector::getSquidMedianSvcTime(SystemInfoItem& item) {
    std::string clientAppHomePath = std::string(getenv("CLIENT_APP_HOME"));
    std::string squidClientPath = clientAppHomePath + "/squid/bin/squidclient";
    std::string medianSvcTime = Util::trim(CommandExecutor::execute(squidClientPath + " mgr:5min | grep -e 'client_http.all_median_svc_time' -e 'dns.median_svc_time' -e 'cpu_usage' | awk '{print $3}'"));
    
    std::istringstream iss(medianSvcTime);

    std::string line;
    int i = 0;
    std::string title[] = {"http", "dns", "cpu"};
    std::string msg = "";
    while (std::getline(iss, line)) {
        msg += title[i] + "=" + line + ",";
        i++;
    }

    item.message = msg;
    item.quantity = 0;
    item.proportion = 0.0;

    return item.message;    
}

std::string SystemInfoCollector::getWebSignature(SystemInfoItem& item) {
    std::string result;
    Util::fileGetContents(ConfigHelper::getWebSignatureFilePath(), result);
    item.message = Util::trim(result);

    return result;
}

std::string SystemInfoCollector::getTCPConnectionNum(SystemInfoItem& item) {
    std::string result = CommandExecutor::execute("netstat -s | grep \"connections established\" | awk '{print $1}'");
    result = Util::trim(result);
    item.message = result;
    return result;
}
