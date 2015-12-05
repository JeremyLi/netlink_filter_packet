//Author:     Li Leigang(lileigang@shidou.com)
//Created:    2015-11-16
#pragma once
#include "hiredis/hiredis.h"

// using namespace std;

class RedisSet
{
public:
	RedisSet(std::string key = "", std::string addr = "127.0.0.1", int port = 6379);
	~RedisSet();

	bool isMember(std::string mac);
	bool addMember(std::string value);
	bool delMember(std::string value);
	bool clear();
	void setKey(std::string key);
private:
	redisContext * context;
	std::string addr;
	int port;
	std::string key;
};
