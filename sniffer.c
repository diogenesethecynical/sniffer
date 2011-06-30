#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAXBUFFERSIZE 1024
#define SNAPLEN 65535


/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14
/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN 6
/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};
/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
	FILE *fd=NULL;
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)
/* TCP header */
typedef u_int tcp_seq;
struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
 static int count = 1;                   
 
 const struct sniff_ethernet *ethernet;  
 const struct sniff_ip *ip;              
 const struct sniff_tcp *tcp;            
 const char *payload;                    
 int size_ip;
 int size_tcp;
 int size_payload;
 
 printf("\n\nPacket number %d", count);
 fprintf(fd,"\n\nPacket number %d", count);
 count++;
 ethernet = (struct sniff_ethernet*)(packet);
 ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
 size_ip = IP_HL(ip)*4;
 if (size_ip < 20) {
  printf("\nInvalid IP header length: %u bytes", size_ip);
  return;
 }

 printf("\nFrom: %s", inet_ntoa(ip->ip_src));
 printf("\nTo: %s", inet_ntoa(ip->ip_dst));
 fprintf(fd,"\nFrom: %s", inet_ntoa(ip->ip_src));
 fprintf(fd,"\nTo: %s", inet_ntoa(ip->ip_dst));
 
 switch(ip->ip_p) {
  case IPPROTO_TCP:
   printf("\nProtocol: TCP");
   fprintf(fd,"\nProtocol: TCP");
   break;
  case IPPROTO_UDP:
   printf("\nProtocol: UDP");
   fprintf(fd,"\nProtocol: UDP");
   return;
  case IPPROTO_ICMP:
   printf("\nProtocol: ICMP");
   fprintf(fd,"\nProtocol: ICMP");
   return;
  case IPPROTO_IP:
   printf("\nProtocol: IP");
   fprintf(fd,"\nProtocol: IP");
   //return;
  default:
   printf("\nProtocol: unknown");
   fprintf(fd,"\nProtocol: unknown");
   return;
 }
 tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
 size_tcp = TH_OFF(tcp)*4;
 if (size_tcp < 20) {
  printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
  return;
 }
 printf("\nSrc port: %d", ntohs(tcp->th_sport));
 printf("\nDst port: %d", ntohs(tcp->th_dport));
 fprintf(fd,"\nSrc port: %d", ntohs(tcp->th_sport));
 fprintf(fd,"\nDst port: %d", ntohs(tcp->th_dport));
return;
}



void resetBuffer(char *buf,int length)
{
	memset(buf,'\0',length);
}

int main(int argc, char *argv[])
{
	
	char *device,errorBuffer[MAXBUFFERSIZE],filter_exp[MAXBUFFERSIZE];
	pcap_t *pcap;
	int port=0,count=0;
	struct bpf_program bfp;
	bpf_u_int32 net,mask;

	

	//resetting the error buffer to avoid weird issues
	resetBuffer(errorBuffer,sizeof(errorBuffer)/sizeof(errorBuffer[0]));
	
	//open the device
	device = pcap_lookupdev(errorBuffer);
	if (!device)
	{
		printf("\nError: %s",errorBuffer);
		exit(1);
	}
	
	//we have device now
	resetBuffer(errorBuffer,sizeof(errorBuffer)/sizeof(errorBuffer[0]));
	
	pcap=pcap_open_live(NULL,SNAPLEN,1, 1000,errorBuffer);
	if (!pcap)
	{
		printf("\nError opening device %s,%s",device,errorBuffer);
		exit(1);
	}
	
	if (strlen(errorBuffer)!=0)
	{
		printf("\nWarning opening device %s, %s",device,errorBuffer);
	}
	
	//get the IP
	
	if (pcap_lookupnet(device, &net, &mask, errorBuffer) == -1) {
		 printf("\nError getting IP for  %s", device);
		 exit(1);
	 }
	
	//got the device and IP, now filtering
	
	printf("\nEnter the port number on which to listen (e.g. 22,80): ");
	scanf("%d",&port);
	resetBuffer(filter_exp,sizeof(filter_exp)/sizeof(filter_exp[0]));
	sprintf(filter_exp,"%s %d","port" ,port);
	
	printf("\nEnter the number of packets to capture");
	scanf("%d",&count);
		
	if (pcap_compile(pcap, &bfp, filter_exp, 0, net))
	{
		 printf("\nError compiling filter %s: %s\n", filter_exp, pcap_geterr(pcap));
		 exit(1);
	}
	
	 // set callback function 
	 fd = fopen("packets.txt","w"); /* open for writing */
	pcap_loop(pcap, count, got_packet, NULL);
	fclose(fd);
	
	//everything done
	pcap_freecode(&bfp);
	
	//save file output
	pcap_dump_open(pcap,"/tmp/lol");
	//pcap_dump
	pcap_close(pcap);
	printf("\nCapture complete");
	return 0;

	
}
	
	
