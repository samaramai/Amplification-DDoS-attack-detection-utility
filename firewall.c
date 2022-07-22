//#define _GNU_SOURCE
#define APP_NAME		"firewall"
#define APP_DESC		"Firewall Util"
#define APP_COPYRIGHT	"Copyright (c) 2005 The Tcpdump Group, 2014 Evgeny Sagatov"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <signal.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>

pthread_mutex_t mp;
pthread_mutex_t mp2;

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14
#define SIZE_LINUX_SLL 16

int header_size;

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
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

typedef u_int tcp_seq;

struct sniff_tcp{
         u_short th_sport;               // source port
         u_short th_dport;               // destination port 
         tcp_seq th_seq;                 // sequence number 
         tcp_seq th_ack;                 // acknowledgement number 
         u_char  th_offx2;               // data offset, rsvd 
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
         u_short th_win;                 // window 
         u_short th_sum;                 // checksum 
         u_short th_urp;                 // urgent pointer 
};

struct sniff_icmp {
    u_char icmp_type;         // Type of message
    u_char icmp_code;         // Type "sub code" (zero for echos)
};

struct stat_ip {
	struct  in_addr ip;
	unsigned long tcp, icmp;
	time_t ban_time;		
};

#define UNBAN_TIME 5*60

struct {
        struct stat_ip **list;
        unsigned long size;
} stat_list = { .size=0 };

unsigned long stat_about(struct in_addr ip_src){
        long min=0, max=stat_list.size-1, cur;
        while(min<=max){
                cur=min+(max-min)/2;
                if(stat_list.list[cur]->ip.s_addr < ip_src.s_addr){
                        min=cur+1;
                }else if(stat_list.list[cur]->ip.s_addr > ip_src.s_addr){
                        max=cur-1;
                }else{
                        return cur;
                }
        }
        return min;
}

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_app_banner(void);

void
print_app_usage(void);

void
signal_handler(int sig);

void unban(int signo);

void stat_set(struct in_addr ip_src, u_char ip_p, u_short ip_len){
	unsigned long index = stat_about(ip_src);
	//pthread_mutex_lock(&mp);
	if(stat_list.size==index || stat_list.list[index]->ip.s_addr!=ip_src.s_addr){
		struct stat_ip **old_list=stat_list.list;
		struct stat_ip **new_list=malloc(sizeof(struct stat_ip*)*(stat_list.size+1));
		memcpy(new_list,old_list,index*sizeof(struct stat_ip*));
		memcpy(&new_list[index+1],&old_list[index],sizeof(struct stat_ip*)*(stat_list.size-index));
		new_list[index]=malloc(sizeof(struct stat_ip));
		memset(new_list[index],0,sizeof(struct stat_ip));
		new_list[index]->ip=ip_src;
		stat_list.list=new_list;
		stat_list.size++;
		free(old_list);
	}

	switch(ip_p) {
        	case IPPROTO_TCP:
            		stat_list.list[index]->tcp++;
            break;
        	case IPPROTO_ICMP: //ICMP
            		stat_list.list[index]->icmp++;
			break;
	}

	if(stat_list.list[index]->tcp>=3 || stat_list.list[index]->icmp>=3){
		if(stat_list.list[index]->ban_time==0){	
			stat_list.list[index]->ban_time=time(NULL);
			printf("BAN IP %s!\n", inet_ntoa(ip_src));
			char ban_ip[256];
			sprintf(ban_ip, "iptables -A INPUT -s %s -j LOG_DROP", inet_ntoa(ip_src));		
			system(ban_ip);
		}
	}
	//pthread_mutex_unlock(&mp);
}
/*
 * app name/banner
 */
void
print_app_banner(void)
{
	printf("%s - %s\n", APP_NAME, APP_DESC);
	printf("%s\n", APP_COPYRIGHT);
	printf("%s\n", APP_DISCLAIMER);
	printf("\n");
return;
}

/*
 * print help text
 */
void
print_app_usage(void)
{
	printf("Usage: %s [interface]\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("\n");
return;
}

/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	/* declare pointers to packet headers */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const struct sniff_icmp *icmp;			/* The ICMP header */

	int size_ip;
	int size_tcp;

	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + header_size);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20)return;

	/* print source and destination IP addresses */
	printf("       From: %s\n", inet_ntoa(ip->ip_src));
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));

	printf("Got packet \n");


	if(ip->ip_p==IPPROTO_TCP){		
		const struct sniff_tcp *tcp = (struct sniff_tcp*)(packet + header_size + size_ip);
		if(tcp->th_flags & TH_RST){
			stat_set(ip->ip_dst,ip->ip_p,ntohs(ip->ip_len));
			printf("Got packet TCP RST\n");
		}
	}

	if(ip->ip_p==IPPROTO_ICMP){
		const struct sniff_icmp *icmp = (struct sniff_icmp*)(packet + header_size + size_ip);
		printf("Got packet ICMP\n");
		if(icmp->icmp_type == 3 && icmp->icmp_code == 3){
			stat_set(ip->ip_dst,ip->ip_p,ntohs(ip->ip_len));
			printf("Got packet ICMP 3.3\n");
		}
	}
return;
}

void signal_handler(int sig)
{
	//if(pthread_mutex_trylock(&mp2)==EBUSY)return;

	//printf("SIGNAL IN %u !\n", sig);

	//pthread_mutex_lock(&mp);

	switch(sig){
		case SIGUSR1:{
    			unsigned long i,tcp=0,icmp=0;
			for(i=0;i<stat_list.size;i++){
				printf("%s %lu %lu\n",
					inet_ntoa(stat_list.list[i]->ip),
					stat_list.list[i]->tcp,
					stat_list.list[i]->icmp
				);
				tcp+=stat_list.list[i]->tcp;
				icmp+=stat_list.list[i]->icmp;
			}
			printf("%s %lu %lu\n","TOTAL",tcp,icmp);
		break;
		}
		case SIGALRM:{

			time_t ttime=time(NULL);
		
			for(unsigned long index=0; index<stat_list.size; index++){
				if(stat_list.list[index]->ban_time && stat_list.list[index]->ban_time + UNBAN_TIME < ttime){
					stat_list.list[index]->ban_time=0;
					stat_list.list[index]->tcp=0;
					stat_list.list[index]->icmp=0;
					printf("UNBAN IP %s!\n", inet_ntoa(stat_list.list[index]->ip));
					char unban_ip[256];
					sprintf(unban_ip, "iptables -D INPUT -s %s -j LOG_DROP", inet_ntoa(stat_list.list[index]->ip));
					system(unban_ip);
				}
			}

		break;
		}
	}

	//pthread_mutex_unlock(&mp);
	//pthread_mutex_unlock(&mp2);
}

void * thread_func(void *handle)
{
	pcap_loop(handle, -1, got_packet, NULL);
}

int main(int argc, char **argv)
{
	pthread_mutex_init(&mp, NULL);
	pthread_mutex_init(&mp2, NULL);

	struct sigaction act;
	memset(&act, 0, sizeof(act));
	act.sa_handler = signal_handler;
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	sigaddset(&set, SIGALRM);
	act.sa_mask = set;
	sigaction(SIGUSR1, &act, 0);
	sigaction(SIGALRM, &act, 0);

	struct itimerval timer;
	/* Configure the timer to expire after 250 msec... */
	timer.it_value.tv_sec = 1;
	timer.it_value.tv_usec = 0;
	/* ... and every 250 msec after that. */
	timer.it_interval.tv_sec = 1;
	timer.it_interval.tv_usec = 0;
	/* Start a virtual timer. It counts down whenever this process is executing. */
	setitimer (ITIMER_REAL, &timer, NULL);

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[256];		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */

	print_app_banner();

	/* check for capture device name on command-line */
	if (argc == 2) {
		if(!strcmp(argv[1],"-h") || !strcmp(argv[1],"--help")){
			print_app_usage();
			exit(0);
		}
		dev = argv[1];
	}else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		print_app_usage();
		exit(EXIT_FAILURE);
	}else {
		/* find a capture device if not specified on command-line */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
	}

	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr={.ifr_addr.sa_family = AF_INET};

	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

	if(!ioctl(sock, SIOCGIFADDR, &ifr)){
		strcpy(filter_exp,"ip src host ");
		strcat(filter_exp, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	}else strcpy(filter_exp,"ip");

	close(sock);

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	int dl=pcap_datalink(handle);
	if(dl == DLT_EN10MB){
		header_size=SIZE_ETHERNET;
	}else if (dl == DLT_LINUX_SLL){
		header_size=SIZE_LINUX_SLL;
	}else{
		fprintf(stderr, "%s is not an Ethernet. This is %d type.\n", dev, pcap_datalink(handle));
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	pthread_t thread;
	pthread_create(&thread, NULL, thread_func, handle);
	pthread_join(thread, NULL);

	/* now we can set our callback function */
	//pcap_loop(handle, -1, got_packet, NULL);

	/* cleanup */
	timer.it_value.tv_sec = 0;
	timer.it_interval.tv_sec = 0;
        timer.it_value.tv_usec = 0;
        timer.it_interval.tv_usec = 0;
        setitimer (ITIMER_REAL, &timer, NULL);
	pcap_freecode(&fp);
	pcap_close(handle);
	unsigned int i; for(i=0;i<stat_list.size;i++)free(stat_list.list[i]);
	free(stat_list.list);
	pthread_mutex_destroy(&mp2);
	pthread_mutex_destroy(&mp);
return 0;
}
