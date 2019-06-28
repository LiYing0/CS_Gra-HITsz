
#include <pcap.h>
#include <string.h>

/*格式定义区*/
/*以太网协议格式的定义*/
struct ether_header {
	u_int8_t ether_dhost[6];
	/*目的以太网地址*/
	u_int8_t ether_shost[6];
	/*源以太网地址*/
	u_int16_t ether_type;
	/*以太网类型*/
};

/*IP地址格式的定义*/
typedef u_int32_t in_addr_t;
struct in_addr {
	in_addr_t s_addr;
};

/*IP协议格式的定义*/
struct ip_header {
#if defined(WORDS_BIGENDIAN)//大端
	u_int8_t ip_version : 4,/*版本*/ip_header_length : 4;/*首部长度*/
#else 
	u_int8_t ip_header_length : 4/*首部长度*/, ip_version : 4;/*版本*/
#endif
	u_int8_t ip_tos;
	/*服务质量*/
	u_int16_t ip_length;
	/*总长度*/
	u_int16_t ip_id;
	/*标识*/
	u_int16_t ip_off;
	/*偏移*/
	u_int8_t ip_ttl;
	/*生存时间*/
	u_int8_t ip_protocol;
	/*协议类型*/
	u_int16_t ip_checksum;
	/*校验和*/
	struct in_addr ip_source_address;
	/*源IP地址*/
	struct in_addr ip_destination_address;
	/*目的IP地址*/
};

/*TCP协议格式的定义*/
struct tcp_header {
	u_int16_t tcp_source_port;
	/*源端口号*/
	u_int16_t tcp_destination_port;
	/*目的端口号*/
	u_int32_t tcp_acknowledgement;
	/*序列号*/
	u_int32_t tcp_ack;
	/*确认码*/
#ifdef WORDS_BIGENDIAN//大端
	u_int8_t tcp_offset : 4,/*偏移*/tcp_reserved : 4;/*保留*/
#else 
	u_int8_t tcp_reserved : 4,/*保留*/tcp_offset : 4;/*偏移*/
#endif
	u_int8_t tcp_flags;
	/*标记*/
	u_int16_t tcp_windows;
	/*窗口大小*/
	u_int16_t tcp_checksum;
	/*校验和*/
	u_int16_t tcp_urgent_pointer;
	/*紧急指针*/
};

/*函数定义区*/
/*分析TCP协议的函数定义*/
void tcp_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content) {
	struct tcp_header *tcp_protocol;
	/*定义TCP协议变量*/
	u_char flags;
	/*标记*/
	int header_length;
	/*首部长度*/
	u_short source_port;
	/*源端口号*/
	u_short destination_port;
	/*目的端口号*/
	u_short windows;
	/*窗口*/
	u_short urgent_pointer;
	/*紧急指针*/
	u_int sequence;
	/*序列号*/
	u_int acknowledgement;
	/*确认号*/
	u_int16_t checksum;
	/*校验和*/

	tcp_protocol = (struct tcp_header *)(packet_content + 14 + 20);
	/*获得TCP协议数据内容，跳过以太网协议和IP协议部分*/
	source_port = ntohs(tcp_protocol->tcp_source_port);
	/*获得源端口号*/
	destination_port = ntohs(tcp_protocol->tcp_destination_port);
	/*获得目的端口号*/
	header_length = tcp_protocol->tcp_offset * 4;
	/*获得首部长度*/
	sequence = ntohl(tcp_protocol->tcp_acknowledgement);
	/*获得序列号*/
	acknowledgement = ntohl(tcp_protocol->tcp_ack);
	/*获得确认号*/
	windows = ntohs(tcp_protocol->tcp_windows);
	/*获得窗口大小*/
	urgent_pointer = ntohs(tcp_protocol->tcp_urgent_pointer);
	/*获得紧急指针*/
	flags = tcp_protocol->tcp_flags;
	/*获得标记*/
	checksum = ntohs(tcp_protocol->tcp_checksum);
	/*获得校验和*/

	printf("------TCP Protocol  (transport Layer)  ------\n");
	printf("Source Port:%d\n", source_port);
	printf("Destination Port:%d\n", destination_port);
	switch (destination_port)
		/*根据端口号判断应用层协议类型*/
	{
	case 80:
		printf("HTTP protocol\n");
		break;
		/*上层协议为HTTP协议，可以在此调用分析HTTP协议的函数*/

	case 21:
		printf("FTP protocol\n");
		break;
		/*上层协议为FTP协议*/

	case 23:
		printf("TELNET protocol\n");
		break;
		/*上层协议为TELNET协议*/

	case 25:
		printf("SMTP protocol\n");
		break;
		/*上层协议为SMTP协议*/

	case 110:
		printf("POP3 protocol\n");
		break;
		/*上层协议为POP3协议626626*/

	default:
		break;
		/*其它的端口号在这里没有分析*/
	}

	printf("Sequence Number: %u\n", sequence);
	printf("Acknowledgement Number：%u\n", acknowledgement);
	printf("Header Length: %d\n", header_length);
	printf("Reserved: %d\n", tcp_protocol->tcp_reserved);
	printf("Flags:");
	/*判断标记的种类*/
	if (flags & 0x08)
		printf("PSH ");
	if (flags & 0x10)
		printf("ACK ");
	if (flags & 0x02)
		printf("SYN ");
	if (flags & 0x20)
		printf("URG ");
	if (flags & 0x01)
		printf("FIN ");
	if (flags & 0x04)
		printf("RST ");
	printf("\n");
	printf("TCP Window Size:%d\n", windows);
	printf("TCP Checksum:%d\n", checksum);
	printf("TCP Urgent pointer:%d\n", urgent_pointer);
}

/*分析IP协议的函数定义*/
void ip_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content) {
	struct ip_header *ip_protocol;
	/*定义IP协议变量*/
	u_int header_length;
	/*首部长度*/
	u_int offset;
	/*偏移*/
	u_char tos;
	/*服务质量*/
	u_int16_t checksum;
	/*校验和*/
	u_int length;
	/*总长度*/
	u_int identification;
	/*获得标识*/
	u_int ttl;
	/*生存时间*/
	u_int protocol_type;
	/*协议类型*/
	u_int version;
	/*协议版本*/

	version = ip_protocol->ip_version;
	/*获得协议版本*/
	checksum = ntohs(ip_protocol->ip_checksum);
	/*获得校验和*/
	header_length = ip_protocol->ip_header_length * 4;
	/*获得IP首部长度*/
	tos = ip_protocol->ip_tos;
	/*获得服务质量*/
	offset = ntohs(ip_protocol->ip_off);
	/*活动偏移*/
	length = ntohs(ip_protocol->ip_length);
	/*获得总长度*/
	identification = ntohs(ip_protocol->ip_id);
	/*获得标识*/
	ttl = ip_protocol->ip_ttl;
	/*获得生存时间*/
	protocol_type = ip_protocol->ip_protocol;

	ip_protocol = (struct ip_header*)(packet_content + 14);
	/*获得IP协议数据内容，跳过以太网协议部分*/

	printf("------IP Protocol  (Network Layer)  ------\n");
	printf("IP Version:%d\n", version);
	printf("Header Length:%d\n", header_length);
	printf("Tos:%d\n", tos);
	printf("Total Length:%d\n", length);
	printf("Identification:%d\n", identification);
	printf("Offset:%d\n", (offset & 0x1fff) * 8);
	printf("TTL:%d\n", ttl);
	printf("Protocol:%d\n", protocol_type);

	printf("Header checksum:%d\n", checksum);

	/*
	printf("Source address:%s\n", inet_ntoa(ip_protocol->ip_source_address));
	/*获得源IP地址*
	printf("Destination address:%s\n", inet_ntoa(ip_protocol->ip_destination_address));
	/*获得目的IP地址*/

		/*上层协议为TCP协议*/
		tcp_protocol_packet_callback(argument, packet_header, packet_content);

}

/*分析以太网协议的函数定义，同时也是回调函数*/
void ethernet_protocol_packet_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content) {
	u_short ethernet_type;
	/*以太网类型*/
	struct ether_header *ethernet_protocol;
	/*以太网协议变量*/
	u_char *mac_string;
	/*以太网地址*/
	static int packet_number = 1;

	printf("***************************************************\n");
	printf("The %d HTTP packet is captured.\n", packet_number);
	printf("--------  Ethernet Protocol (Link Layer)  --------\n");
	ethernet_protocol = (struct ether_header*)packet_content;
	/*获得以太网协议数据内容*/
	printf("Ethernet type is :\n");
	ethernet_type = ntohs(ethernet_protocol->ether_type);
	/*获得以太网类型*/
	printf("%04x\n", ethernet_type);
	switch (ethernet_type) {
		/*根据以太网类型字段判断上层协议类型*/
	case 0x0800:
		printf("The network layer is IP protocol\n");
		break;
		/*上层协议为IP协议*/

	case 0x0806:
		printf("The network layer is ARP protocol\n");
		break;
		/*上层协议为ARP协议*/

	case 0x0835:
		printf("The network layer is RARP protocol\n");
		break;
		/*上层协议为RARP协议*/

	default:
		break;
	}

	mac_string = ethernet_protocol->ether_shost;
	printf("Mac Source Address is : \n%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));
	/*获得源以太网地址*/
	mac_string = ethernet_protocol->ether_dhost;
	printf("Mac Destination Address is : \n%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));
	/*获得目的以太网地址*/

		/*上层是IP协议*/
		ip_protocol_packet_callback(argument, packet_header, packet_content);


	printf("*****************************************************\n");
	packet_number++;
}

int main() {
	char error_content[PCAP_ERRBUF_SIZE];
	/*存放错误信息*/
	pcap_t *pcap_handle;
	/*Libpcap句柄*/
	struct bpf_program bpf_filter;
	/*bpf过滤规则*/
	char bpf_filter_string[] = "tcp dst port 80";
	/*过滤规则字符串，为空表示捕获所有的网络数据包，而不是捕获特定的网络数据包*/
	bpf_u_int32 net_mask;
	/*网络掩码*/
	bpf_u_int32 net_ip;
	/*网络地址*/
	char *net_interface;
	/*网络接口*/
	net_interface = pcap_lookupdev(error_content);
	/*获取网络接口*/
	pcap_lookupnet(net_interface/*网络接口*/, &net_ip/*网络地址*/, &net_mask/*网络掩码*/, error_content/*错误信息*/);
	/*获取网络地址和掩码地址*/
	pcap_handle = pcap_open_live(net_interface/*网络接口*/, BUFSIZ/*数据包大小*/, 1/*混杂模式*/, 0/*等待时间*/, error_content/*错误信息*/);
	/*打开网络接口*/
	pcap_compile(pcap_handle/*Libpcap句柄*/, &bpf_filter/*BPF过滤规则*/, bpf_filter_string/*BOF过滤规则字符串*/, 0/*优化参数*/, net_ip/*网络地址*/);
	/*编译过滤原则*/
	pcap_setfilter(pcap_handle/*Libpcap句柄*/, &bpf_filter/*BPF过滤规则*/);
	/*设置过滤规则*/
	if (pcap_datalink(pcap_handle) != DLT_EN10MB)
		return;/*DLT_EN10MB代表以太网*/
	pcap_loop(pcap_handle/*Libpcap句柄*/, -1/*捕获数据包的个数*/, ethernet_protocol_packet_callback/*回调函数*/, NULL/*传递给回调函数的参数*/);

	/*注册回调函数packet_callback()，然后循环捕获网络数据包，每捕获一个数据包就调用回调函数进行处理。
	如果个数设为-1，就表示无限循环*/


	pcap_close(pcap_handle);
	/*关闭Libpcap操作*/
}
