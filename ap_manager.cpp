#include <time.h>
#include <stdarg.h>
#include <stdio.h>
#include <pthread.h>
#include <signal.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <bits/ioctls.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

#include <arpa/inet.h>
#include <errno.h>

#include <boost/bind.hpp>
#include <boost/thread/thread.hpp>

#include "Util.h"
#include "CommandExecutor.h"

#include "ap_manager.h"

std::string APManager::ap_key_path="";
std::string APManager::ap_connect_username="";
int APManager::ap_connect_port=2222;
int APManager::ap_connect_timeout=2;
std::string APManager::ap_activate_cmd="";

APManager::APManager(void)
	: detector_counter(0), info_reporter(NULL) {

}

APManager::~APManager(void) {

}

bool APManager::init(const int interval, std::string& base_ip, const int segment_begin, const int segment_end) {
	bool ret_value = false;

	this->base_ip = base_ip;
	this->segment_begin = segment_begin;
	this->segment_end = segment_end;

	info_reporter = InfoReporter::getInstance();
	if (info_reporter) {
		info_reporter->setName("ap_status_watcher");
		info_reporter->setInterval(interval);
		info_reporter->collectStatus("working", "");

		ret_value = true;
	}

	return ret_value;
}

void APManager::initApActivation(const std::string& apKeyPath, const std::string& apConnectUsername, 
		int apConnectPort, int apConnectTimeout, const std::string& apActivateCmd) {
	this->ap_key_path = apKeyPath;
	this->ap_connect_username = apConnectUsername;
	this->ap_connect_port = apConnectPort;
	this->ap_connect_timeout = apConnectTimeout;
	this->ap_activate_cmd = apActivateCmd;
	std::cout << "ap_connect_username: " << ap_connect_username << std::endl;

	//make ap private key file correct permission
	system(("chmod 600 " + apKeyPath).c_str());
}

/**
 * release ap manager.
 */
void APManager::release(void) {

}

/**
*scan ap.
*/
std::vector<std::string>& APManager::scanAP(void) {
	std::cout<<"scanAP-------------->"<<std::endl;

	std::string script = "nmap -sP " + base_ip + "0/24 | grep \"" + base_ip +"\" | cut -d '.' -f 4 | grep -o \"[0-9]*\"";

	std::cout<<"script-->"<<script<<std::endl;

	std::string pingResult = Util::trim(CommandExecutor::execute(script));

	std::cout<<"pingResult-->\n"<<pingResult<<std::endl;

	tokens.clear();
	if (pingResult.size() > 0) {
		std::istringstream iss(pingResult);

		copy(std::istream_iterator<std::string>(iss),
			std::istream_iterator<std::string>(),
			std::back_inserter<std::vector<std::string> >(tokens));
	}

	std::cout<<"scanAP-------------->end"<<std::endl;

	return tokens;
}

/**
*process current online ap list.
*update cached ap table.
*/
void APManager::handleScannedOnlineAP(std::vector< std::string >& onlien_ap_list) {
	std::vector<std::string>::iterator it = onlien_ap_list.begin();

	std::string ip = "";
	time_t time_stamp = time(NULL);

	boost::mutex::scoped_lock scoped_lock(ap_mutex);

	for (it; it != onlien_ap_list.end(); ++it) {
		int ip_segment = Util::stringToInt(*it);

		if (ip_segment >= segment_begin && ip_segment <= segment_end) {
			ip = base_ip + Util::intToString(ip_segment);

			//search from maintained ap table, if not exist, add it, else update onlne status.
			std::map< std::string, boost::shared_ptr< AP > >::iterator it =
					maintained_ap_table.find(ip);
			if (it != maintained_ap_table.end()) {
				//exist.update online status.
				it->second->is_online = true;
				it->second->time_stamp = time_stamp;

				std::cout<<"repeted ap--->"<<it->second->ip<<std::endl;
			} else {
				//not exist.add it.
				boost::shared_ptr< AP > ap(new AP());
				ap->ip = ip;
				ap->time_stamp = time_stamp;

				maintained_ap_table[ip] = ap;

				std::cout<<"new ap--->"<<ap->ip<<std::endl;
			}
		}
	}

	//mark offline ap.
	std::map< std::string, boost::shared_ptr< AP > >::iterator it_ap = maintained_ap_table.begin();
	for (it_ap; it_ap != maintained_ap_table.end(); ++it_ap) {
		if (it_ap->second->time_stamp != time_stamp) {
			it_ap->second->is_online = false;

			if (!(it_ap->second->is_detecting)) {
				//start offline ap detector.
				boost::thread t(boost::bind(&APManager::detectOfflineAP, this, it_ap->second->ip));

				it_ap->second->is_detecting = true;

				++detector_counter;

				std::cout<<"ap--->"<<it_ap->second->ip<<" offline......"<<std::endl;
			}
		}
	}

	if (detector_counter <= 0) {
		//start report.
		this->reportWorkingAP();
	} else {
		//delay report.

	}
}

/**
*detect offline ap.
*threaded.
*/
void APManager::detectOfflineAP(std::string ip) {
	std::cout<<"offline ap detector: ip-->"<<ip<<std::endl;

	int i, host_online_flag = 0;
	for (i = 0; i < 5; ++i) {
		std::string cmd = "ping " + ip + " -c 1 -W 3";

		std::cout<<"cmd-->"<<cmd<<std::endl;
		std::string result = CommandExecutor::execute(cmd);
		if (result.size() > 0) {
			std::cout<<"result-->"<<result<<std::endl;

			int index = result.find("ttl=");
			std::cout<<"index-->"<<index<<std::endl;
			if (index >= 0) {
				index = result.find("time=");
				std::cout<<"index-->"<<index<<std::endl;
				if (index >= 0) {
					host_online_flag = 1;
				}
			}
		}

		if (host_online_flag) {
			break ;
		}
	}

	if (!host_online_flag) {
		boost::mutex::scoped_lock scoped_lock(ap_mutex);

		//ap offline confirmed.
		std::map< std::string, boost::shared_ptr< AP > >::iterator it =
								maintained_ap_table.find(ip);
		if (it != maintained_ap_table.end()) {
			//exist.update online status.
			std::cout<<"remove offline ap "<<it->second->ip<<std::endl;

			maintained_ap_table.erase(it);
		}

		--detector_counter;
		if (detector_counter <= 0) {
			reportWorkingAP();
		}
	} else {
		boost::mutex::scoped_lock scoped_lock(ap_mutex);

		//ap is online.
		std::map< std::string, boost::shared_ptr< AP > >::iterator it =
								maintained_ap_table.find(ip);
		if (it != maintained_ap_table.end()) {
			//exist.update online status.
			std::cout<<"resume offline ap "<<it->second->ip<<std::endl;

			it->second->is_online = true;
			it->second->is_detecting = false;
			it->second->ap_bounded_try_times = AP_BOUNDED_TRY_TIMES;
		}

		--detector_counter;
		if (detector_counter <= 0) {
			reportWorkingAP();
		}
	}
}

void APManager::activateBoundedAPWorker(boost::shared_ptr< AP > ap_info) {
	std::cout << "activating " << ap_info->ip << std::endl;
	std::string cmd = Util::stringFormat("ssh -p %d -i %s -o ConnectTimeout=%d -o UserKnownHostsFile=/tmp/ssh_known_hosts -o StrictHostKeyChecking=no %s@%s '%s'",
						ap_connect_port, ap_key_path.c_str(), ap_connect_timeout,
						ap_connect_username.c_str(), ap_info->ip.c_str(), ap_activate_cmd.c_str());
	std::cout << "activate cmd: " << cmd << std::endl;
	int result = system(cmd.c_str());

	std::cout << "activate " << ap_info->ip << " result: " << result << std::endl;

	if (result != 0) {
		ap_info->ap_bounded_try_times--;
	}
}

void APManager::activateBoundedAP(void) {
	std::map< std::string, boost::shared_ptr< AP > >::iterator it = maintained_ap_table.begin();

	for (it; it != maintained_ap_table.end(); ++it) {
		std::cout << "ap " << it->second->ip << " bounded try times: " << it->second->ap_bounded_try_times << std::endl;
		if (it->second->ap_bounded_try_times > 0) {
			boost::thread t(boost::bind(&APManager::activateBoundedAPWorker, this, it->second));
		}
	}
}

/**
*report online ap to public internet server.
*/
bool APManager::reportWorkingAP(void) {
	bool ret_value = false;

	int counter = 0;

	std::string apStatusStr;

	std::map< std::string, boost::shared_ptr< AP > >::iterator it = maintained_ap_table.begin();
	for (it; it != maintained_ap_table.end(); ++it) {
		if (it->second->is_online) {
			std::string ip = it->second->ip;

			int index = ip.find_last_of(".");

			if (index >= 0) {
				++index;

				std::cout<<"add online ap "<<ip.substr(index)<<" for reporter....."<<std::endl;

				apStatusStr += ip.substr(index) + ":";

				++counter;
			}
		}
	}

	if (counter <= 0) {
		std::cout<<"no ap available for report............"<<std::endl;

		info_reporter->collectStatus("working", "-1");
	} else {
		info_reporter->collectStatus("working", apStatusStr);
		ret_value = true;
	}

	activateBoundedAP();

	return ret_value;
}
