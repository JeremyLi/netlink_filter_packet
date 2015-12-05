#ifndef TCP_IP_H
#define TCP_IP_H
//////////////////////////////////////////////////
//常用TCP/IP数据结构定义						//
//////////////////////////////////////////////////


#define	PACKET_3_IP			0x0008
#define	PACKET_3_ARP		0x0608
#define	PACKET_3_RARP		0x3508
#define	PACKET_4_TCP		6
#define	PACKET_4_UDP		17
#define	PACKET_4_ICMP		1
#define	PACKET_4_IGMP		2

typedef unsigned char UCHAR;
typedef unsigned short USHORT;
typedef int DWORD;
typedef short WORD;

typedef struct
{
    UCHAR	sDestMAC[6];	//目的MAC;
    UCHAR	sSourceMAC[6];	//源MAC
    short	iProtocol;		//0x800=TYPE_IP;0x806=TYPE_ARP;0x835=TYPE_RARP
}MAC_PACKET,*PMAC_PACKET;

typedef struct
{
    short			iNetTyp	;		//00 01 = 以太网
    short			iUpProt;		//高层协议 08 00 = IP
    UCHAR			cPhyAddrLen;	//物理地址的长度 = 06
    UCHAR			cIpAddrLen;		//IP地址长度  = 04
    short			iOptionCode;	//00 01 = request; 00 02 = reply
//	UCHAR			sData[40];		//暂时用
    UCHAR			sSrcMAC[6];		//发送方的MAC地址
    long			lSrcIP;			//发送方的IP地址
    UCHAR			sDestMAC[6];	//目标的MAC地址
    long			lDesIP;			//目标的IP地址
    UCHAR			sReserv[18];	//保留的内容，通常真0x20
}ARP_PACKET,*PARP_PACKET;

typedef struct
{
    char	iIPLen		:4;	// *由于先放的是低位,故这两项交换了次序,  hlIP包首部长度,这个值以4字节为单位.IP协议首部的固定长度为20个字节,如果IP包没有选项,那么这个值为5
    char	iIPVer		:4;	//vIP协议的版本号,这里是4,现在IPV6已经出来了
    char	iTOS		;			//服务类型,说明提供的优先权
    short	iTotalLen;		//说明IP数据的长度.以字节为单位
    short	iID;			//标识
    USHORT	iFlagsOff;		//3+13位	//不能用位域	//USHORT	iFragMark	:3;				//标识这个IP数据包
                            //short	iFragOff	:13;//     碎片偏移,这和上面ID一起用来重组碎片的
    UCHAR	iTTL;			//生存时间.每经过一个路由的时候减一,直到为0时被抛弃
    UCHAR	iProtocol;		//表示创建这个IP数据包的高层协议.如TCP,UDP协议:1=TYPE_ICMP;2=TYPE_IGMP;6=TYPE_TCP;17=TYPE_UDP
    short	iCheckSum;		//首部校验和,提供对首部数据的校验;
    DWORD	iSourceIP;		//源IP;
    DWORD	iDestIP;		//目的IP;
}IP_PACKET,*PIP_PACKET;

typedef struct
{
    UCHAR	iSourcePortH;	//源端口
    UCHAR	iSourcePortL;	//源端口
    UCHAR	iDestPortH;		//目的端口
    UCHAR	iDestPortL;		//目的端口
    long	iSeq;			//标识该TCP所包含的数据字节的开始序列号
    long	iACKSeq;		//确认序列号,表示接受方下一次接受的数据序列号
    USHORT  iFlags;			/*
                            short	iTCPLen		:4;	//数据首部长度.和IP协议一样,以4字节为单位.一般的时候为5
                            short	iReserve	:6;	//保留
                            short	iURG		:1; //如果设置紧急数据指针,则该位为1
                            short	iACK		:1; //如果确认号正确,那么为1
                            short	iPSH		:1; //如果设置为1,那么接收方收到数据后,立即交给上一层程序
                            short	iRST		:1;	//为1的时候,表示请求重新连接
                            short	iSYN		:1; //为1的时候,表示请求建立连接
                            short	iFIN		:1;	//为1的时候,表示亲戚关闭连接
                            */
    short	iWindow;		//窗口,告诉接收者可以接收的大小
    short	iCheckSum;		//对TCP数据进行较核
    short	iURG_Ptr;		//果urg=1,那么指出紧急数据对于历史数据开始的序列号的偏移值
}TCP_PACKET,*PTCP_PACKET;

typedef struct
{
    UCHAR	iSourcePortH;	//源端口;	实际高位,物理位置
    UCHAR	iSourcePortL;	//源端口;
    UCHAR	iDestPortH;		//目的端口；
    UCHAR	iDestPortL;		//目的端口；
//	UCHAR	iUDPLenH;		//数据报长压;
    short	iUDPLen;		//数据报长压;
    short	iCheckSum;		//校验和
}UDP_PACKET,*PUDP_PACKET;

//伪UDP包头结构
typedef struct
{
    unsigned long iSourceIP;	//source address
    unsigned long iDestIP;	//destination address
    char iZero;					//0
    char iProtocol;					//protocol type
    unsigned short iUdpSize;			//UDP size 包括数据包在内的大小
}WUDP_HEADER,*PWUDP_HEADER;

typedef struct
{
    char	iType;			//类型；0 回送响应;3 目的不可达;4 源拥塞;5 重定向;8 回送;11 超时;12 参数问题;13 时间戳;14 时间戳响应;15 信息请求;16 信息响应
    char	iCode;			//CODE;根据TYPE的不同而不同
    short	iCheckSum;		//校验和；
    union
    {
        struct
        {
            short	iID;	//id;
            short	iSeq;	//sequence;
        }Echo;
        long	iGateway;	//网关；
        struct
        {
            short	iUnUsed;
            short	iMtu;	// path mtu discovery
        };
    }Info;
}ICMP_PACKET,*PICMP_PACKET;

//typedef struct
//{
//    MAC_PACKET	Mac;
//    struct Layer3P
//    {
//        IP_PACKET	Ip;
//        union
//        {
//            TCP_PACKET	Tcp;
//            UDP_PACKET	Udp;
//            ICMP_PACKET	Icmp;
//        }Layer4P;
//    };

//}ETHERNET_PACKET ,*PETHERNET_PACKET;

typedef struct
{
    MAC_PACKET Mac;
    ARP_PACKET Arp;
}MAC_ARP_PACKET,* PMAC_ARP_PACKET;

//DNS数据报:
typedef struct
{
    //标识，通过它客户端可以将DNS的请求与应答相匹配；
    WORD	id;
    //WORD	flags//标志:[QR | opcode | AA| TC| RD| RA | zero | rcode ]
    ////在16位的标志中:QR位判断是查询/响应报文，opcode区别查询类型，AA判断是否为授权回答，TC判断是否可截断，
    //RD判断是否期望递归查询，RA判断是否为可用递归，zero必须为0，rcode为返回码字段。
    //由于使用位域,得全部倒着定议
    UCHAR	RD		:1;
    UCHAR	TC		:1;		//切断。1位字段。当设置为1，表明消息已被切断。
    UCHAR    AA		:1;		//命令回答：1位字段。当设置为1时，
    UCHAR	opcode	:4;		//0 标准查询（由姓名到地址）；1 逆向查询；	2 服务状态请求
    UCHAR	QR		:1;		//0是问题,1是答案包
    UCHAR	Rcode	:4;		//响应代码，由名字服务器设置的4位字段用以识别查询状态。
    UCHAR	Zero	:3;		//备用，必须设置为0。
    UCHAR	RA		:1;
    WORD	quests;			//问题数目；
    WORD	answers;		//答案记录数目；
    WORD	author;			//授权资源记录数目；
    WORD	addition;		//额外资源记录数目；
}DNS_HEADER,*PDNS_HEADER;

typedef struct _ipoptionhdr
{
    unsigned char        code;        // Option type
    unsigned char        len;         // Length of option hdr
    unsigned char        ptr;         // Offset into options
    unsigned long        addr[9];     // List of IP addrs
} IpOptionHeader;

//DNS查询数据报:
typedef struct
{
    //UCHAR * pname;					由于不定长，所以要单独实现，试试用指针方式看看
                        //查询的域名,这是一个大小在0到63之间的字符串,不定长；
    WORD	itype;		//查询类型，大约有20个不同的类型
    WORD	classes;	//查询类,通常是A类既查询IP地址。
}DNS_QUERY,*PDNS_QUERY;

//DNS响应数据报:
typedef struct
{
    //pname:pchar;		由于不定长，所以要单独实现，
    //查询的域名		//查询的域名,这是一个大小在0到63之间的字符串；
    //可以用两个字节的指针,指向问题就可以了
    WORD	name;		//用指针代替
    WORD	itype;		//查询类型
    WORD	classes;	//类型码
    DWORD	ttl;		//生存时间
    WORD	length;		//资源数据长度
    DWORD	addr;		//资源数据
}DNS_RESPONSE ,*PDNS_RESPONSE;

//definde by fubibo
#define ETHERNET_HEADER_LEN             14
#define IP_HEADER_LEN					20
#define TCP_HEADER_LEN					20

#define ETHERNET_TYPE_IP				0x0800

/* tcpdump shows us the way to cross platform compatibility */
#define IP_VER(iph)		(((iph)->ip_verhl & 0xf0) >> 4)
#define IP_HLEN(iph)	((iph)->ip_verhl & 0x0f)

/* more macros for TCP offset */
#define TCP_OFFSET(tcph)	(((tcph)->th_offx2 & 0xf0) >> 4)
#define TCP_X2(tcph)	((tcph)->th_offx2 & 0x0f)

/* we need to change them as well as get them */
#define SET_TCP_OFFSET(tcph, value)  ((tcph)->th_offx2 = (((tcph)->th_offx2 & 0x0f) | (value << 4)))
#define SET_TCP_X2(tcph, value)  ((tcph)->th_offx2 = (((tcph)->th_offx2 & 0xf0) | (value & 0x0f)))

/* we need to change them as well as get them */
#define SET_IP_VER(iph, value)  ((iph)->ip_verhl = (((iph)->ip_verhl & 0x0f) | (value << 4)))
#define SET_IP_HLEN(iph, value)  ((iph)->ip_verhl = (((iph)->ip_verhl & 0xf0) | (value & 0x0f)))


#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)    //this removes the need of mstcpip.h


typedef unsigned char		u_int8_t;
typedef unsigned short		u_int16_t;
typedef unsigned int		u_int32_t;

/* 14 bytes for ethernet header.
Although as the article mentioned, We have 26 bytes in ethernet header but pCap only provide us
14 bytes which also is fairly enough for our need */
struct EtherHdr
{
#define ETH_HDR_LEN 14
    u_int8_t ether_dst[6]; // Destination MAC address
    u_int8_t ether_src[6]; // Source MAC address
    u_int16_t ether_type; // Protocol type
}__attribute__((packed)) ;


/* 20 bytes or more for IP header */
struct IPHdr
{
#define IP_HDR_LEN 20
    u_int8_t ip_verhl;      /* version & header length */
    u_int8_t ip_tos;        /* type of service */
    u_int16_t ip_len;       /* datagram length */
    u_int16_t ip_id;        /* identification  */
    u_int16_t ip_off;       /* fragment offset */
    u_int8_t ip_ttl;        /* time to live field */
    u_int8_t ip_proto;      /* datagram protocol */
    u_int16_t ip_csum;      /* checksum */
    union{
        u_int32_t sip;
        u_int8_t ip_src[4];  /* source IP */
    };
    union{
        u_int32_t dip;
        u_int8_t ip_dst[4];  /* dest IP */
    };
}__attribute__((packed));

/* 20 bytes or more for TCP header */
struct TCPHdr
{
#define TCP_HDR_LEN 20
    u_int16_t th_sport;     /* source port */
    u_int16_t th_dport;     /* destination port */
    u_int32_t th_seq;       /* sequence number */
    u_int32_t th_ack;       /* acknowledgement number */
    u_int8_t th_offx2;     /* offset and reserved */
    u_int8_t th_flags;
#define	TH_FIN	0x01
#define	TH_SYN	0x02
#define	TH_RST	0x04
#define	TH_PSH	0x08
#define	TH_ACK	0x10
#define	TH_URG	0x20
    u_int16_t th_win;       /* window */
    u_int16_t th_sum;       /* checksum */
    u_int16_t th_urp;       /* urgent pointer */

}__attribute__((packed));



 /* Our handy data structure which ease our work in packet processing */
struct Packet
{
    u_int8_t			*pkt;	/* base pointer to the raw packet data */

    struct EtherHdr			*eh;	/* standard TCP/IP/Ethernet/ARP headers */
    struct IPHdr				*iph;   /* and original headers for ICMP_*_UNREACH family */
    u_int32_t			ip_options_len;
    u_int8_t			*ip_options_data;


    struct TCPHdr				*tcph;
    u_int32_t			tcp_options_len;
    u_int8_t			*tcp_options_data;


    u_int8_t			*data;					/* packet payload pointer */
    u_int16_t			dsize;					/* packet payload size */

    u_int8_t			*http_uri_content;
    u_int32_t			http_payload_len;
    u_int8_t			http_state;				/* HTTP request / HTTP response */
    u_int8_t			banned;					/* Indicate if the request should be sensored */
    unsigned char		matched[128];			/* Keyword that this request matched to - maximum 128 byte*/
#define	CLIENT_REQUEST	0x01
#define	SERVER_RESPONSE	0x02
#define	NOT_HTTP		0x04

    u_int8_t frag_flag;     /* flag to indicate a fragmented packet */
    u_int16_t frag_offset;  /* fragment offset number */
    u_int8_t mf;            /* more fragments flag */
    u_int8_t df;            /* don't fragment flag */
    u_int8_t rf;            /* IP reserved bit */

};



#endif // TCP_IP_H
