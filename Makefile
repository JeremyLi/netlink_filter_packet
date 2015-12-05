.PHONY: all clean gen

INCLUDES=-I . \
		 -I ${SVN_HOME}/${THIRD_PATH}/tags/apr-1.4.6/include/apr-1 \
		 -I ${SVN_HOME}/${THIRD_PATH}/tags/apr-util-1.5.1/include/apr-1 \
		 -I ${SVN_HOME}/${THIRD_PATH}/tags/curl-7.27.0/include \
		 -I ${SVN_HOME}/${THIRD_PATH}/tags/jsoncpp-0.5.0/include \
		 -I ${SVN_HOME}/${THIRD_PATH}/tags/log4cplus-1.1.0.2/include \
		 -I ${SVN_HOME}/${THIRD_PATH}/tags/boost-1.51.0/include \
		 -I ${SVN_HOME}/${THIRD_PATH}/tags/thrift-0.9.0/cpp/include \
		 -I ../../common/include \
		 -I ../lib/iostat-2.2	\
		 -I ${SVN_HOME}/${THIRD_PATH}/tags/libpcap-1.7.4/include	\
		 -I ${SVN_HOME}/${THIRD_PATH}/tags/redis-c-client-0.11.0/include

LIBS=-L ${SVN_HOME}/${THIRD_PATH}/tags/jsoncpp-0.5.0/lib -ljson \
	 -L ${SVN_HOME}/${THIRD_PATH}/tags/curl-7.27.0/lib -lcurl \
 	 -L ${SVN_HOME}/${THIRD_PATH}/tags/apr-util-1.5.1/lib -l aprutil-1 -lexpat\
 	 -L ${SVN_HOME}/${THIRD_PATH}/tags/apr-1.4.6/lib -l apr-1 \
 	 -L ${SVN_HOME}/${THIRD_PATH}/tags/log4cplus-1.1.0.2/lib -llog4cplus \
 	 -L ${SVN_HOME}/${THIRD_PATH}/tags/boost-1.51.0/lib -lboost_system -lboost_thread -lboost_filesystem  -lpthread \
 	 -L ${SVN_HOME}/${THIRD_PATH}/tags/thrift-0.9.0/cpp/lib -lthrift \
	 -L ${SVN_HOME}/${THIRD_PATH}/tags/zeromq-2.2.0/lib -lzmq \
 	 -L ../../common/lib -lsdcm_common \
 	 -L ../lib/iostat-2.2 -liostat	\
 	 -L ${SVN_HOME}/${THIRD_PATH}/tags/libpcap-1.7.4/lib -lpcap \
 	 -L ${SVN_HOME}/${THIRD_PATH}/tags/redis-c-client-0.11.0/lib -lhiredis

CXX_FLAGS=-O2 -fPIC -DHAVE_NETINET_IN_H -DHAVE_INTTYPES_H 

OBJECTS=SystemInfoCollector.o ap_manager.o NetTrafficInfoCollector.o RedisSet.o

TARGETS=system_info_watcher module_info_watcher ap_status_watcher net_traffic_info_watcher

all: ${OBJECTS} system_info_watcher.o module_info_watcher.o ap_status_watcher.o net_traffic_info_watcher.o
	@for TARGET in ${TARGETS}; do \
		${CXX} ${CXX_FLAGS} -o $${TARGET} $${TARGET}.o ${OBJECTS} ${LIBS} ${LD_FLAGS}; \
	done
	cp -f ${TARGETS} ../bin

	#make -C kernel-module
	#cp -f ./kernel-module/net_traffic.ko ../bin

clean:
	rm -rf ${OBJECTS} ${TARGETS}
	#make -C kernel-module clean
%.o: %.cpp
	${CXX} ${CXX_FLAGS} -c -o $@ $^ ${INCLUDES}

