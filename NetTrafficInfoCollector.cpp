#include <string.h>
#include <json/json.h>
#include "boost/date_time/posix_time/posix_time.hpp"
#include "Util.h"
#include "QuickLogger.h"
#include "RedisSet.h"
#include "NetTrafficInfoCollector.h"
#include "tcp_ip.h"



MacAddr::MacAddr(uint8_t* addr) {
	memcpy(this->mac_addr, addr, 6);
}

MacAddr::~MacAddr() {

}

string MacAddr::toAscii() {
	// if (buf == NULL) return;
	string buf="";
	char dict[] = "0123456789abcdef";
	for (int i = 0; i < 6; ++i)
	{
		int index = this->mac_addr[i] >> 4;
		buf += dict[index];
		index = this->mac_addr[i] & 0x0f;
		buf += dict[index];
		if(i < 5)
			buf += '-';
	}

	return buf;
}

void MacAddr::updateTimestamp() {
	gettimeofday(&this->timestamp, NULL);
}

int MacAddr::timeDiff(struct timeval cur) {
	return cur.tv_sec - this->timestamp.tv_sec;
}


NetTrafficInfoCollector::NetTrafficInfoCollector(int interval, string addr) {
	std::size_t pos = addr.find(":");
	string redis_addr = addr.substr(0, pos);
	string port = addr.substr(pos+1);
	
	this->mac_addr_redis_set = new RedisSet(string("shidou-gateway-new-added-mac-set-key"), redis_addr, atoi(port.c_str()));

	this->report_interval = interval;

	this->info_reporter = InfoReporter::getInstance();
	this->info_reporter->setName("net_traffic");
    this->info_reporter->setInterval(interval);

}


NetTrafficInfoCollector::~NetTrafficInfoCollector() {
	
	if (this->mac_addr_redis_set != NULL) delete this->mac_addr_redis_set;
}


void NetTrafficInfoCollector::setRedisKey(string key){
	if (this->mac_addr_redis_set != NULL)
	{
		this->mac_addr_redis_set->setKey(key);
	}

	this->redis_set_key = key;
}


void NetTrafficInfoCollector::startCollectorAndReporter(){
	boost::posix_time::ptime last = boost::posix_time::second_clock::local_time(); 

	struct sockaddr_nl local;
	struct sockaddr_nl kpeer;
	struct nlmsghdr* nlhdr;
	int kpeerlen;
 	// int sendlen = 0;
	int rcvlen = 0;
	struct in_addr addr;
	int skfd;
	struct iovec iov;
	// int sock_fd;
	struct msghdr msg;

	skfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_DEV_NUM);
	if (skfd < 0) {
		printf("can not create a netlink socket\n");
		exit(0);
	}

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_pid = getpid();
	printf("pid: %d\n", local.nl_pid);
	local.nl_groups = 0;
	if (bind(skfd, (struct sockaddr*)&local, sizeof(local)) != 0) {
		printf("bind() error\n");
		return ;
	}

	// signal(SIGINT, sig_int);
	nlhdr = (struct nlmsghdr *)malloc(NLMSG_SPACE(BUF_LENGTH));
	
	while(true){

		// sleep(this->report_interval);
		// sleep(5);
		Json::Value message;

		std::string new_devs_str("");

		memset(&kpeer, 0, sizeof(kpeer));
		kpeer.nl_family = AF_NETLINK;
		kpeer.nl_pid = 0;
		kpeer.nl_groups = 0;


		memset(nlhdr, 0, NLMSG_SPACE(0));
		nlhdr->nlmsg_len = NLMSG_SPACE(0);
		nlhdr->nlmsg_flags = 0;
		nlhdr->nlmsg_type = ACTION_SUMMARY;
		nlhdr->nlmsg_pid = local.nl_pid;


		iov.iov_base = (void *)nlhdr;
        iov.iov_len = nlhdr->nlmsg_len;
        msg.msg_name = (void *)&kpeer;
        msg.msg_namelen = sizeof(kpeer);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

		//设置socket为非阻塞模式  
	    // int flags = fcntl(skfd, F_GETFL, 0);  
	    // fcntl(skfd, F_SETFL, flags|O_NONBLOCK);
		LOGI("send read action...\n");
		// sendto(skfd, &nlhdr, nlhdr.nlmsg_len, 0, (struct sockaddr*)&kpeer, sizeof(kpeer));
		sendmsg(skfd, &msg, 0);

		nlhdr->nlmsg_len = NLMSG_SPACE(BUF_LENGTH);
		iov.iov_len = nlhdr->nlmsg_len;

		int select_ret = 0;
		struct timeval tv;
	    fd_set readfds;
	    tv.tv_sec = 5;
	    tv.tv_usec = 0;
	    FD_ZERO(&readfds);
	    FD_SET(skfd, &readfds);
	    select_ret = select(skfd+1,&readfds,NULL, NULL, &tv);
	    if (select_ret > 0){
		    do{
				kpeerlen = sizeof(struct sockaddr_nl);
				LOGI("before recvfrom...\n");
				// rcvlen = recvfrom(skfd, buf, sizeof(buf),
				// 	0, (struct sockaddr*)&kpeer, (socklen_t*)&kpeerlen);
				rcvlen = recvmsg(skfd, &msg, 0);
				if(rcvlen == -1) {
					LOGI("recvfrom kernel error!!!\n");
					break;
				}

				// buf[rcvlen] = '\0';
				char* packet = (char*)NLMSG_DATA(nlhdr);
				packet[nlhdr->nlmsg_len - sizeof(*nlhdr)] = '\0';
				LOGI("after recvfrom...%d, %d, %d, %s\n", sizeof(struct nlmsghdr), rcvlen, nlhdr->nlmsg_len, packet);
				new_devs_str += packet;
				// new_devs_str.append((char*)NLMSG_DATA(nlhdr));
		 
			}while(rcvlen == sizeof(buf));

			// string new_devs_str = CommandExecutor::execute("cat /proc/shidou_new_devs");
			// CommandExecutor::execute("echo clearNew > /proc/shidou_new_devs");

			// memset(&kpeer, 0, sizeof(kpeer));
			// kpeer.nl_family = AF_NETLINK;
			// kpeer.nl_pid = 0;
			// kpeer.nl_groups = 0;

			memset(nlhdr, 0, NLMSG_SPACE(0));
			nlhdr->nlmsg_len = NLMSG_SPACE(0);
			nlhdr->nlmsg_flags = 0;
			nlhdr->nlmsg_type = ACTION_CLEAR_NEW;
			nlhdr->nlmsg_pid = local.nl_pid;
			iov.iov_len = nlhdr->nlmsg_len;
			LOGI("send clear new devs...nlmsg_type: %d\n", nlhdr->nlmsg_type);
			// sendto(skfd, nlhdr, nlhdr->nlmsg_len, 0, (struct sockaddr*)&kpeer, sizeof(kpeer));
			sendmsg(skfd, &msg, 0);
			// return;

	    }else{
	    	new_devs_str = "{}";
	    }

	    cout<<__FILE__<<"@"<<__LINE__<<":"<<__func__<<", new_devs_str: "<<new_devs_str<<endl;
    	Json::Reader reader;
    	Json::Value	 macs;
    	reader.parse(new_devs_str, macs, false);

		message["dev_count"] = macs["dev_count"];
		cout<<"dev_count: "<<message["dev_count"]<<endl;

		Json::Value new_macs;
		new_macs.resize(0);
		Json::Value members = macs["new_devs"];
		for (Json::Value::iterator iter = members.begin(); iter != members.end(); iter++){
			string addr_str = (*iter).asString();
			if (!this->mac_addr_redis_set->isMember(addr_str)) {
				cout<<"new dev: "<<addr_str<<endl;
				LOGI("+++++++++++new dev: %s\n", addr_str.c_str());
		 
				this->mac_addr_redis_set->addMember(addr_str);
			
				cout<<"append mac: "<<addr_str<<endl;
				new_macs.append(addr_str);
			}
		}

		Json::FastWriter w;
		message["new_devs"] = new_macs;

		info_reporter->collect("status", "working");
		string message_str = w.write(message);
		info_reporter->collect("message", message_str);
		cout<<"write message: "<<message_str<<endl;
		LOGI("report net_traffic message: %s\n", message_str.c_str());
		
		// cout<<__FILE__<<"@"<<__LINE__<<":"<<__func__<<endl;
		boost::posix_time::ptime now = boost::posix_time::second_clock::local_time();  
		boost::posix_time::time_period tp(last, now);
		tm tm_struct = boost::posix_time::to_tm(last);
		tm_struct.tm_hour = 23;
		tm_struct.tm_min = 59;
		tm_struct.tm_sec = 59;
		boost::posix_time::ptime reset_time = boost::posix_time::ptime_from_tm(tm_struct);
		cout<<"report time: "<<last<<" : "<<now<<" : "<<reset_time<<endl;
		if (tp.contains(reset_time))
		{
			this->mac_addr_redis_set->clear();
			memset(nlhdr, 0, NLMSG_SPACE(1024));
			nlhdr->nlmsg_len = NLMSG_SPACE(1024);
			nlhdr->nlmsg_flags = 0;
			nlhdr->nlmsg_type = ACTION_CLEAR_ALL;
			nlhdr->nlmsg_pid = local.nl_pid;

			// sendto(skfd, nlhdr, nlhdr->nlmsg_len, 0, (struct sockaddr*)&kpeer, sizeof(kpeer));
			sendmsg(skfd, &msg, 0);
			cout<<"call delete........."<<endl;
			LOGI("clear mac addr set...\n");
		}

		last = now;

		if (select_ret > 0)
		{
			sleep(5);
		}

	}

}
