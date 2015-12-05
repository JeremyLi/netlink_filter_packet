//Author:     Li Leigang(lileigang@shidou.com)
//Created:    2015-11-16
#include <iostream>
#include "RedisSet.h"

using namespace std;

RedisSet::RedisSet(string key, string addr, int port){
	this->key = key;
	this->addr = addr;
	this->port = port;
	cout<<__FILE__<<"@"<<__LINE__<<":"<<__func__<<"-->"<<this->key<<", "<<this->addr<<":"<<this->port<<endl;
	this->context = redisConnect(this->addr.c_str(), this->port);

	if(this->context == NULL) 
		cout<<"connect to redis server error!"<<endl;
}

RedisSet::~RedisSet(){
	if (this->context != NULL) {
		redisFree(this->context);
	}
}


bool RedisSet::isMember(string mac){
	if(context == NULL) return false;
	redisReply* reply = (redisReply*)redisCommand(this->context, "sismember %s %s", this->key.c_str(), mac.c_str());
	if (reply->type == REDIS_REPLY_INTEGER) {
		if (reply->integer == 1)
		{
			freeReplyObject(reply);
			return true;
		}else if (reply->integer == 0)
		{
			freeReplyObject(reply);
			return false;
		}
 	}

 	cout<<"redis sismember execute failed!"<<endl;
 	if (reply != NULL)
 	{
 		freeReplyObject(reply);
 	}
	return false;
}


bool RedisSet::addMember(string value){
	if(context == NULL) return false;
	redisReply* reply = (redisReply*)redisCommand(this->context, "sadd %s %s", this->key.c_str(), value.c_str());
	if (reply->type == REDIS_REPLY_INTEGER) {
		if (reply->integer == 1)
		{
			freeReplyObject(reply);
			return true;
		}
 	}

 	cout<<"redis sadd execute failed!"<<endl;
 	if (reply != NULL)
 	{
 		freeReplyObject(reply);
 	}
	return false;
}

bool RedisSet::delMember(string value){
	if(context == NULL) return false;
	redisReply* reply = (redisReply*)redisCommand(this->context, "srem %s %s", this->key.c_str(), value.c_str());
	if (reply->type == REDIS_REPLY_INTEGER) {
		if (reply->integer == 1)
		{
			freeReplyObject(reply);
			return true;
		}
 	}

 	cout<<"redis sdel execute failed!"<<endl;
	if (reply != NULL)
 	{
 		freeReplyObject(reply);
 	}
	return false;
}

bool RedisSet::clear(){
	if(context == NULL) return false;
	redisReply* reply = (redisReply*)redisCommand(this->context, "del %s", this->key.c_str());
	if (reply->type == REDIS_REPLY_INTEGER) {
		if (reply->integer == 1)
		{
			freeReplyObject(reply);
			return true;
		}
 	}

 	cout<<"redis del execute failed!"<<endl;
 	if (reply != NULL)
 	{
 		freeReplyObject(reply);
 	}
	return false;
}
void RedisSet::setKey(string key){
	this->key = key;
}
