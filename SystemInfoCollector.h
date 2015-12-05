//Author:     Huang Minglong(loong4life@gmail)
//Created:    2013-05-15
#ifndef __SYSTEM_INFO_COLLECTOR__H__
#define __SYSTEM_INFO_COLLECTOR__H__
#include <iostream>
#include <map>

#include <boost/thread/mutex.hpp>

class SystemInfoItem
{
public:
    std::string message;
    long long quantity;
    float proportion;
};

class DiskIOInfo {
public:
	DiskIOInfo()
	{

	}

	static std::string getKey(void) {
		return "disk_io";
	}

	double current_read_speed;
	double current_write_speed;
	int count;
};

class SystemInfoCollector
{
public:
    static std::string getCpuUsage(SystemInfoItem& item);

    static std::string getMemFree(SystemInfoItem& item);

    static std::string getDiskFree(SystemInfoItem& item);

    static std::string getInetAddr(SystemInfoItem& item);

    static std::string getOnetAddr(SystemInfoItem& item);

    static std::string getModuleStatus(std::string name);

    static int getModuleRunningNum(std::string name);

    static std::string getNetworkStatus(SystemInfoItem& in, SystemInfoItem& out,  time_t diffTime);

    static std::string getLoadAverage(SystemInfoItem& item);

    static std::string getSquidMedianSvcTime(SystemInfoItem& item);

    static bool hasCamera();

    static bool hasWlan();

    static std::string getSoftwareSignature(SystemInfoItem& item);

    static std::string getWebSignature(SystemInfoItem& item);

    static std::string getSystemUpTime(SystemInfoItem& item);

    static std::string getTCPConnectionNum(SystemInfoItem& item);

    static std::string getBypassStatus(SystemInfoItem& item);

    static std::string getShadewitchStatus(SystemInfoItem& item);

    static std::string getConnectedDeviceNum(SystemInfoItem& item);

    /*
     * parameter：read speed, write speed
		return value：bool true: success, false: failed
		description：get current disk io speed(read,write).
     */
    static bool getDiskIO(SystemInfoItem& item_read, SystemInfoItem& item_written);

    static void setInterval(const int interval);

private:
    /*
    *parameter: device name; read speed; write speed;
    *return value:void
    *description: current statistic system disk io speed info notify.
    */
    static void disk_iostat_cb(const int count, const double read_speed, const double write_speed);

    /*
     * parameter：dynamic get disk io speed.
return value：void
description：execute command “iostat -kd 3”,read result data and parse read & write speed and store to memory for
read.if iostat command doesn’t exist and internet is available, using apt-get tool to install it.
     */
    static void diskIOSpeedGetter(void);

    static long lastCpuTotal;
    static long lastCpuIdle;
    static long long lastNetIn;
    static long long lastNetOut;
    static std::string lastInterface;
    static std::string currentInterface;

    static boost::mutex disk_io_mutex;
    static std::map< std::string, DiskIOInfo* > disk_io_info_map;
    static int interval;
};

#endif /* __SYSTEM_INFO_COLLECTOR__H__ */
