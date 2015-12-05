#ifndef __INFO_WATCHER_AP_MANAGER_H__
#define __INFO_WATCHER_AP_MANAGER_H__

#include <map>
#include <vector>

#include <boost/shared_ptr.hpp>
#include <boost/thread/detail/singleton.hpp>
#include <boost/thread/mutex.hpp>

#include "InfoReporter.h"

/*
*ap manager.
*/
class APManager {
public:
	APManager(void);
	virtual ~APManager(void);

	class AP {
	public:
		AP(void)
			: ip(""), is_online(true), is_detecting(false), time_stamp(0), ap_bounded_try_times(3) {

		}
		~AP(void) {

		}

		std::string ip;
		bool is_online;
		bool is_detecting;
		time_t time_stamp;
		int ap_bounded_try_times; //是否绑定类型AP
	};


	/**
	 * init ap manager.
	 */
	bool init(const int interval, std::string& base_ip, const int segment_begin, const int segment_end);

	void initApActivation(const std::string& apKeyPath, const std::string& apConnectUsername, 
		int apConnectPort, int apConnectTimeout, const std::string& apActivateCmd);

	/**
	*scan ap.
	*/
	std::vector<std::string>& scanAP(void);

	/**
	*process current online ap list.
	*update cached ap table.
	*/
	void handleScannedOnlineAP(std::vector<std::string>& online_ap_list);

	/**
	 * release ap manager.
	 */
	void release(void);


private:

	/**
	*detect offline ap.
	*threaded.
	*/
	void detectOfflineAP(std::string ip);

	//激活绑定类型的AP
	void activateBoundedAPWorker(boost::shared_ptr< AP > ap_info);

	void activateBoundedAP(void);

/**
	*report online ap to public internet server.
	*/
	bool reportWorkingAP(void);

	//for sync operations on ap table, detector_counter.
	boost::mutex ap_mutex;

	//ap ip address[172.16.1.200], status[true:online | false:offline]
	std::map< std::string, boost::shared_ptr< AP > > maintained_ap_table;

	/**
	*how many offline ap detectors are working at present.
	* only report online ap list to server when it’s 0.
	*/
	int detector_counter;

	InfoReporter* info_reporter;

	std::string base_ip;
	int segment_begin;
	int segment_end;
	static std::string ap_key_path;
	static std::string ap_connect_username;
	static int ap_connect_port;
	static int ap_connect_timeout;
	static std::string ap_activate_cmd;

	std::vector<std::string> tokens;

	const static int AP_BOUNDED_TRY_TIMES = 3;
};/*class APManager {*/

typedef boost::detail::thread::singleton< APManager > APManagerInst;

#endif/*__INFO_WATCHER_AP_MANAGER_H__*/
