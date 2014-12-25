#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#define COMPILE_AS_R_LIB 1

#if COMPILE_AS_R_LIB
#include <R.h>
#include <Rinternals.h>
#include <Rmath.h>
#endif

typedef unsigned int uint32;
typedef unsigned short uint16;
typedef signed int int32;
typedef unsigned char uint8;
typedef unsigned long long uint64;
typedef unsigned char mac_addr_t [6]; 

#define MAX_HASH_LENGTH  131072 
#define MAX_NUM_PACKETS  1000000
#define MAX_PACKET_SIZE  1024

uint8 packets [MAX_NUM_PACKETS][MAX_PACKET_SIZE];
uint32 g_flow_id = 0;

struct pcap_hdr_s {
        uint32 magic_number;   /* magic number */
        uint16 version_major;  /* major version number */
        uint16 version_minor;  /* minor version number */
        int32  thiszone;       /* GMT to local correction */
        uint32 sigfigs;        /* accuracy of timestamps */
        uint32 snaplen;        /* max length of captured packets, in bytes */
        uint32 network;        /* data link type */
};

struct pcaprec_hdr_s {
        uint32 ts_sec;         /* timestamp seconds */
        uint32 ts_usec;        /* timestamp microseconds */
        uint32 incl_len;       /* number of octets of packet saved in file */
        uint32 orig_len;       /* actual length of packet */
};

struct ethernet_hdr_s {
	mac_addr_t dst_mac; 
	mac_addr_t src_mac;
	uint16 type_length;  /* NETWORK ORDER */ 
};

struct ipv4_hdr_s {
	uint8 vers_hdrlen;
	uint8 dscp_ecn;
	uint16 total_len;         /* NETWORK ORDER */
	uint16 identification;         /* NETWORK ORDER */
	uint16 flags_frag_ofs;        /* NETWORK ORDER */
	uint8 ttl;
	uint8 proto; 
	uint16 hdr_checksum;         /* NETWORK ORDER */
	uint32 src_ip;         /* NETWORK ORDER */
	uint32 dst_ip;         /* NETWORK ORDER */
};

struct tcp_hdr_s {
	uint16 src_port;        /* NETWORK ORDER */
	uint16 dst_port;         /* NETWORK ORDER */
	uint32 seq_num;         /* NETWORK ORDER */
	uint32 ack_num;        /* NETWORK ORDER */
	uint16 ofs_ctrl;        /* NETWORK ORDER */        
	uint16 window_size;         /* NETWORK ORDER */
	uint16 checksum;         /* NETWORK ORDER */
	uint16 urgent_pointer;         /* NETWORK ORDER */
};

struct udp_hdr_s {
	uint16 src_port;        /* NETWORK ORDER */
	uint16 dst_port;         /* NETWORK ORDER */
	uint16 total_len;        /* NETWORK ORDER */
	uint16 checksum;         /* NETWORK ORDER */
};

struct icmp_hdr_s {
	uint8 type;
	uint8 code;
	uint16 checksum;  /* NETWORK ORDER */
};

#if 0  /* PREPROCESSOR DIRECTIVE */
struct packet_s {
	struct ethernet_hdr_s eth_hdr;
	struct ipv4_hdr_s ip_hdr;
	union {
		struct tcp_hdr_s tcp_hdr;
		struct udp_hdr_s udp_hdr;	
		struct icmp_hdr_s icmp_hdr;
	} u;
};

struct packet_s pkt;
#endif

struct counters {
	uint32 num_tcp_flows; 
	uint32 non_eth;
	uint32 num_ip_pkts;
/*	uint32 num_not_ip_pkts; */
	uint32 num_icmp_pkts;
	uint32 num_udp_pkts;
	uint32 num_tcp_pkts;
	uint32 num_not_tcp_udp_icmp_pkts;
	uint32 num_ipv6_pkts; 
	uint32 num_arp_pkts; 
};

struct flow_s {
	uint32 flow_id;
	uint32 src_ip; 
	uint32 dst_ip; 
	uint16 src_port; 
	uint16 dst_port; 
	uint32 num_pkts;
	uint32 seq_num; 
	uint8 is_open;
	uint32 num_bytes1; /* from initiator */
	uint32 num_bytes2; /* from responder */
	uint32 start_time; /* first syn */
	uint32 end_time; /* fin_ack or ack */
	uint8 closed; 
	uint32 num_init_pkts;
	uint32 num_resp_pkts;
	uint64 src_timestamps [MAX_NUM_PACKETS]; /* timestamps on pkts from initiator i.e. who sent first syn */
	uint64 dst_timestamps [MAX_NUM_PACKETS]; /* timestamps on pkts from responder */
	uint32 src_seq_nums [MAX_NUM_PACKETS];
	uint32 src_ack_nums [MAX_NUM_PACKETS];
	uint32 dst_seq_nums [MAX_NUM_PACKETS];
	uint32 dst_ack_nums [MAX_NUM_PACKETS];
	uint32 packets [MAX_NUM_PACKETS];
	struct flow_s *next;
};

struct ip_info_s {
	uint32 ip_addr; 
	uint32 num_pkts_sent;
	uint32 num_pkts_received; 
	uint32 num_bytes_sent; 
	uint32 num_bytes_received; 
	struct ip_info_s *next; 
};


uint32 num_ip_info_elements = 0;
struct ip_info_s *ip_infos = NULL; 
struct flow_s *list_of_flows = NULL;
struct flow_s *table[MAX_HASH_LENGTH]; 
struct counters cnt;

void clear_state ();

struct ip_info_s *
find_ip (uint32 ip)
{
        struct ip_info_s *tmp;

        tmp = ip_infos;
        while (tmp != NULL) {
		if (ip == tmp->ip_addr) {
                        return (tmp);
		}
                tmp = tmp->next;
	} 
        return (NULL);
}

void add_to_ip_list (struct ip_info_s *f)
{
        f->next = ip_infos;
        ip_infos = f;
	num_ip_info_elements++;
}


void print_global_hdr (struct pcap_hdr_s *p_hdr)
{
	printf ("magic number = %x\n", p_hdr->magic_number);
	printf ("version_major = %u\n", p_hdr->version_major);
	printf ("version_minor = %u\n", p_hdr->version_minor);	
	printf ("thiszone = %d\n", p_hdr->thiszone);	
	printf ("sigfigs = %u\n", p_hdr->sigfigs);	
	printf ("snaplen = %u\n", p_hdr->snaplen);	
	printf ("network = %u\n", p_hdr->network);	
}


void copy_bytes (void *_from, void *_to, int num)
{
	int i;
	uint8 *from = (uint8 *)_from;
	uint8 *to = (uint8 *)_to;
	
	for (i = 0; i < num; i++) {
		to[i] = from[i];
	}
#if 0
	while (i < num) 
		*to = *from;
		to = to + 1;
		from = from + 1;
	i++;
#endif
}

void print_counters (struct counters *c)
{
	printf("number non ethernet = %u\n",c->non_eth);
	printf("number of ip packets = %u\n",c->num_ip_pkts);
	printf("num ipv6 packets = %u\n",c->num_ipv6_pkts);
	printf("num arp packets = %u\n", c->num_arp_pkts);
	printf("number icmp packets = %u\n",c->num_icmp_pkts);
	printf("number udp packets = %u\n",c->num_udp_pkts);
	printf("number tcp packets = %u\n",c->num_tcp_pkts);
	printf("number non tcp udp or icmp packets %u\n",c->num_not_tcp_udp_icmp_pkts);
}


unsigned short _short_switcher (unsigned short *x)
{
    char *p;
    char *p2;
    char temp;

    p = (char *) x;
    p2 = p + 1;
    temp = *p;
    *p = *p2;
    *p2 = temp;
    return (*x);
}

unsigned int _int_switcher(unsigned int *x)
{
    char *b1;
    char temp;

    b1 = (char *) x;
    temp = *b1;
    *b1 = *(b1+3);
    *(b1+3) = temp;

    temp = *(b1+1);
    *(b1+1) = *(b1+2);
    *(b1+2) = temp;
    return (*x);
}




void add_to_list (struct flow_s *f)
{
	f->next = list_of_flows;
	list_of_flows = f;
}

struct flow_s *
find_flow1 (uint32 src_ip, uint32 dst_ip, uint16 src_port, uint16 dst_port, uint32 seq_num)
{
	struct flow_s *tmp; 
	tmp = list_of_flows; 

	while (tmp != NULL) {
		if (((tmp->src_ip == src_ip) && (tmp->dst_ip == dst_ip) && 
			(tmp->src_port == src_port) && (tmp->dst_port == dst_port))
			|| ((tmp->src_ip == dst_ip) && (tmp->dst_ip == src_ip) && (tmp->src_port == dst_port) && 
				(tmp->dst_port == src_port))) {
			return (tmp); 		
		}
		tmp = tmp->next; 
	}
	return (NULL); 
}

void 
conv_ip_to_str (char *str, uint32 ip)
{       
	sprintf (str, "%u.%u.%u.%u", 
        	(ip & 0xff000000) >> 24,
        	(ip & 0x00ff0000) >> 16, 
        	(ip & 0x0000ff00) >> 8, 
        	(ip & 0x000000ff)); 
}

void 
print_dotted_ips (uint32 *ip)
{       
        int tmp = 0; 
        tmp = (*ip & 0xff000000) >> 24; 
        printf("%d.", tmp);
        tmp = (*ip & 0x00ff0000) >> 16; 
        printf("%d.", tmp); 
        tmp = (*ip & 0x0000ff00) >> 8; 
        printf("%d.", tmp); 
        tmp = (*ip & 0x000000ff); 
        printf("%d", tmp);      
}

void 
print_hash_table_flows ()
{
	int i; 
	int counter = 0;
	struct flow_s *tmp; 

	for (i = 0; i < MAX_HASH_LENGTH; i++) {
		tmp = table[i];
		while (tmp != NULL) {	
			counter++; 
			printf("-------------------------------------- "); 
			printf("Flow %u\n", counter);
			printf("Source IP ");
			print_dotted_ips(&tmp->src_ip); 
			printf("\n");  
			printf("Dst IP "); 
			print_dotted_ips(&tmp->dst_ip); 
			printf("\n");
			printf("Source port %u\n", tmp->src_port);
			printf("dst port %u\n", tmp->dst_port);
			printf("num pkts %u\n", tmp->num_pkts); 	 
			tmp = tmp->next; 
		}
	}
}

void
print_flows ()
{
	uint32 counter = 1; 
	while (list_of_flows != NULL){
		printf("-------------------------------------- "); 
		printf("Flow %u\n", counter);
		printf("Source IP ");
		print_dotted_ips(&list_of_flows->src_ip); 
		printf("\n");  
		printf("Dst IP "); 
		print_dotted_ips(&list_of_flows->dst_ip); 
		printf("\n");
		printf("Source port %u\n", list_of_flows->src_port);
		printf("dst port %u\n", list_of_flows->dst_port);
		printf("num pkts %u\n", list_of_flows->num_pkts); 	 
		list_of_flows = list_of_flows->next; 
		counter++;
	}
}

// needs cleanup - different pcap files seem to have different timestamp resolution
static void
record_timestamp_and_seq_ack_nums (struct flow_s *flow, struct pcaprec_hdr_s *pkt_hdr, 
							struct ipv4_hdr_s *ip_hdr, struct tcp_hdr_s *tcp_hdr)
{
	if (ip_hdr->src_ip == flow->dst_ip) {
		flow->dst_seq_nums[flow->num_pkts] = tcp_hdr->seq_num; 
		if ((tcp_hdr->ofs_ctrl & 0x10) == 0x10) {
			flow->dst_ack_nums[flow->num_pkts] = tcp_hdr->ack_num; 
		}
		flow->dst_timestamps[flow->num_pkts] = (((uint64)pkt_hdr->ts_sec) * 1000000LL) + (uint64)pkt_hdr->ts_usec;
	}
	else {
		flow->src_seq_nums[flow->num_pkts] = tcp_hdr->seq_num; 
		if ((tcp_hdr->ofs_ctrl & 0x10) == 0x10) {
			flow->src_ack_nums[flow->num_pkts] = tcp_hdr->ack_num;
		}

		flow->src_timestamps[flow->num_pkts] = (uint64)pkt_hdr->ts_sec * 1000000; 
		if (pkt_hdr->ts_usec > 1000000) {
			/* possibly nanosecond pcap file */
			flow->src_timestamps[flow->num_pkts] += (pkt_hdr->ts_usec/1000);
		}
		else {
			flow->src_timestamps[flow->num_pkts] += pkt_hdr->ts_usec;
        	}
	}
}

void add_to_hash_list (struct flow_s *f, struct flow_s **l)
{
	f->next = *l; 
	*l = f; 
}

void add_to_hash_table (struct flow_s *flow)
{
	uint32 x,y,num;

	x = (flow->src_ip) & 0x0000ffff;
	y = (flow->dst_ip) & 0x0000ffff;
	num = x + y; 
	
	flow->flow_id = g_flow_id++;
	add_to_hash_list (flow, &table [num % MAX_HASH_LENGTH]); 
}

int are_flows_equal (uint32 src_ip, uint32 dst_ip,  struct flow_s *flow)
{
	if (((src_ip == flow->src_ip) && (dst_ip == flow->dst_ip)) || ((dst_ip == flow->src_ip) && (src_ip == flow->dst_ip))) {
		return (1);
	}
	return(0); 
}

int spec_flow (uint32 src_ip, uint32 dst_ip, uint16 src_port, uint16 dst_port, struct flow_s *tmp)
{
	if (((tmp->src_ip == src_ip) && (tmp->dst_ip == dst_ip) && 
		(tmp->src_port == src_port) && (tmp->dst_port == dst_port))
		|| ((tmp->src_ip == dst_ip) && (tmp->dst_ip == src_ip) && (tmp->src_port == dst_port) && (tmp->dst_port == src_port))) {
		return(1); 
	}
	return (0); 
}

struct flow_s *
search_hash_list_to_edit (uint32 src_ip, uint32 dst_ip, uint16 src_port, uint16 dst_port)
{
	uint32 x = (src_ip) & 0x0000ffff;
	uint32 y = (dst_ip) & 0x0000ffff; 
	uint32 num = x + y; 
	
	struct flow_s *tmp = table [num % MAX_HASH_LENGTH]; 
	
	while (tmp != NULL) {
		if (spec_flow (src_ip, dst_ip, src_port, dst_port, tmp)) {
			return (tmp); 
		}
		tmp = tmp->next; 
	}
	return NULL; 
}

struct flow_s *
search_hash_list (uint32 src_ip, uint32 dst_ip) 
{
	uint32 x,y,num; 
	x = (src_ip) & 0x0000ffff; 
	y = (dst_ip) & 0x0000ffff; 
	num = x + y; 
	
	struct flow_s *hash_flow = table[num % MAX_HASH_LENGTH]; 
	struct flow_s *tmp = hash_flow; 
	struct flow_s *return_list = NULL; 
	struct flow_s *tmp2 = NULL; 

	while (tmp != NULL) {
		if (are_flows_equal(src_ip, dst_ip, tmp)) {
			tmp2 = malloc (sizeof (struct flow_s));
			*tmp2 = *tmp;
			add_to_hash_list (tmp2, &return_list);   
		}
		tmp = tmp->next; 	
	}	
	return (return_list); 
}


static int 
parse_pcap_file (const char *file_name, int debug)
{
	
	int n, rc, fd, size_of_data;
	struct pcap_hdr_s global_hdr;
	struct pcaprec_hdr_s pkt_hdr;
	struct ethernet_hdr_s *eth_hdr;
	struct ipv4_hdr_s *ip_hdr; 
	struct tcp_hdr_s tcp_hdr; 
	struct ip_info_s *ip_info;
	struct flow_s *f;
	uint8 dummy [16000];
	uint32 extra_read;	
	//struct udp_hdr_s *udp_hdr; 
	//struct icmp_hdr_s *icmp_hdr; 

	
	memset (&cnt, 0, sizeof(cnt));

	fd = open (file_name, O_RDONLY);
	if (fd < 0) {
		printf ("error reading file %s\n", file_name);
		return -1;
	}

	rc = read (fd, &global_hdr, sizeof(struct pcap_hdr_s));	
	if (rc < sizeof(struct pcap_hdr_s)) {
		printf ("could not read global hdr\n");
		return -2;
	}

	if (debug) {
		printf("------------------------------------------------------------------------------------ \n"); 
		print_global_hdr (&global_hdr);
	}

	memset (table, 0, sizeof(table));

	n = 0;
	while (n < MAX_NUM_PACKETS) {
		rc = read (fd, &pkt_hdr, sizeof(struct pcaprec_hdr_s));
		if (rc < sizeof(struct pcaprec_hdr_s)) {
			break;
		}

		if (pkt_hdr.incl_len > 1024) {
			if (debug) { 
				printf ("####### length of packet = %u\n", pkt_hdr.incl_len);
			}
			extra_read = pkt_hdr.incl_len - 1024;
			pkt_hdr.incl_len = 1024;
		}
		else {
			extra_read = 0;
		}
		
		rc = read (fd, packets[n], pkt_hdr.incl_len);	
		if (rc < pkt_hdr.incl_len) {
			printf ("NeedData..\n");	
			break;
		}

		if (extra_read > 0) {
			read (fd, dummy, extra_read);
		}
		
		eth_hdr = (struct ethernet_hdr_s *) packets[n];
		eth_hdr->type_length =  _short_switcher (&eth_hdr->type_length); 

		if (eth_hdr->type_length > 1500) {

			if (eth_hdr->type_length == 0x800) {  /* IPv4 Packet */

				cnt.num_ip_pkts++; 

				ip_hdr = (struct ipv4_hdr_s *) (packets[n] + sizeof(struct ethernet_hdr_s));
			
				if (debug) {
					printf ("ip packet %u ", cnt.num_ip_pkts);
				}
				
				_int_switcher (&ip_hdr->src_ip); 
				_int_switcher (&ip_hdr->dst_ip); 

				if (debug) {
					printf (" src ip ");  
					print_dotted_ips (&ip_hdr->src_ip); 
					printf (" dst ip "); 
					print_dotted_ips (&ip_hdr->dst_ip);
					printf ("\n"); 
				}

				size_of_data = _short_switcher(&ip_hdr->total_len); 
				size_of_data = (size_of_data - sizeof(*ip_hdr) - sizeof(tcp_hdr) - 
								sizeof(struct ethernet_hdr_s)); 
						
				ip_info = find_ip (ip_hdr->src_ip); 
				if (ip_info == NULL) {
					ip_info = malloc(sizeof(struct ip_info_s));
					ip_info->ip_addr = ip_hdr->src_ip;
					ip_info->num_pkts_sent = 0;
					ip_info->num_pkts_received = 0;
					ip_info->num_bytes_sent = 0;
					ip_info->num_bytes_received =  0;
					ip_info->next = NULL;
					add_to_ip_list(ip_info);
				}

				ip_info->num_pkts_sent++;
				ip_info->num_bytes_sent += size_of_data;

				ip_info = find_ip (ip_hdr->dst_ip);
				if (ip_info == NULL) {
					ip_info = malloc (sizeof(struct ip_info_s));
					ip_info->ip_addr = ip_hdr->dst_ip;
					ip_info->num_pkts_sent = 0;
					ip_info->num_pkts_received = 0;
					ip_info->num_bytes_sent = 0;
					ip_info->num_bytes_received =  0;
					ip_info->next = NULL; 
					add_to_ip_list(ip_info); 
				}

				ip_info->num_pkts_received++; 
				ip_info->num_bytes_received += size_of_data; 

				switch (ip_hdr->proto) {

					case 6: /* TCP */

						cnt.num_tcp_pkts++;

						copy_bytes (packets[n]+sizeof(*eth_hdr)+sizeof(*ip_hdr), &tcp_hdr, sizeof(tcp_hdr));
							
						_short_switcher (&tcp_hdr.ofs_ctrl);
						_int_switcher (&tcp_hdr.seq_num); 
						_int_switcher (&tcp_hdr.ack_num); 

						tcp_hdr.src_port = _short_switcher(&tcp_hdr.src_port); 
						tcp_hdr.dst_port = _short_switcher(&tcp_hdr.dst_port); 
 
						f = search_hash_list_to_edit (ip_hdr->src_ip, ip_hdr->dst_ip, 
										tcp_hdr.src_port, tcp_hdr.dst_port); 

						if ((tcp_hdr.ofs_ctrl & 0x02) == 0x02) {
							/* syn + syn ack */
							if (f == NULL || f->closed == 1) {
                                                                /* if f == NULL assume that this is first syn pkt */
								f = malloc (sizeof (struct flow_s));
								f->src_ip = ip_hdr->src_ip;
								f->dst_ip = ip_hdr->dst_ip;
								
								f->src_port = 0;
								f->dst_port = 0;
								f->src_port = tcp_hdr.src_port;
								f->dst_port = tcp_hdr.dst_port;
								f->seq_num = tcp_hdr.seq_num;
								f->num_pkts = 0;
								f->packets[f->num_pkts] = n;

								record_timestamp_and_seq_ack_nums (f, &pkt_hdr, ip_hdr, &tcp_hdr);

								f->num_pkts++;
								f->next = NULL;
								
								add_to_hash_table (f); 	
								cnt.num_tcp_flows++; 
							}
							else {
								/* this could be retransmission of syn pkt */
								/* or syn+ack */

								f->packets[f->num_pkts] = n;
								f->num_pkts++;

								record_timestamp_and_seq_ack_nums (f, &pkt_hdr, ip_hdr, &tcp_hdr);
							}
						} 
						else if ((tcp_hdr.ofs_ctrl & 0x01) == 0x01) { 
							if (f != NULL) {
								f->packets[f->num_pkts] = n;
								f->num_pkts++;
								record_timestamp_and_seq_ack_nums (f, &pkt_hdr, ip_hdr, &tcp_hdr);
								f->closed = 1; 
							}
						} 
						else {
							if (f != NULL) {
								f->packets[f->num_pkts] = n;
								f->num_pkts++;
								record_timestamp_and_seq_ack_nums (f, &pkt_hdr, ip_hdr, &tcp_hdr);
							}
						}
						break; 

					case 17: 
						cnt.num_udp_pkts++;
						//copy_bytes(packet+sizeof(eth_hdr) + sizeof(ip_hdr), &udp_hdr, sizeof(udp_hdr));
						break;

					case 1: 
						cnt.num_icmp_pkts++; 
						//copy_bytes(packet+sizeof(eth_hdr) + sizeof(ip_hdr), &icmp_hdr, sizeof(icmp_hdr));
						break; 

					default: 
						cnt.num_not_tcp_udp_icmp_pkts++; 
					
				}	
			}
			else if (eth_hdr->type_length == 0x86dd) {
				cnt.num_ipv6_pkts++; 
			}
			else if (eth_hdr->type_length == 0x806) {
				cnt.num_arp_pkts++; 
			}
		}
		else {
			cnt.non_eth++; 
		}

		n++;
	}

	if (debug) {
		printf ("num pkts read = %d\n", n);
		print_counters (&cnt);
	}

	close (fd);

	if (debug) {
		printf ("Printing hash table...\n");
		print_hash_table_flows();
		printf("------------------------------------------------------------------------------------\n");
	}

	return 0;
}


#if COMPILE_AS_R_LIB

SEXP read_pcap_file (SEXP r_filename, SEXP r_debug)
{
	const char *fname;
	int debug_flag;
		
	clear_state();

	fname = CHAR(STRING_ELT(r_filename, 0));
	debug_flag = (int) REAL(r_debug)[0];

	printf ("fname = %s, debug = %d\n", fname, debug_flag);
	parse_pcap_file (fname, debug_flag);
	return R_NilValue;
}

void clear_state ()
{
	int i;
	struct flow_s *tmp; 
	struct flow_s *save; 
	for (i = 0; i < MAX_HASH_LENGTH; i++) {
		tmp = table[i];
		while (tmp) {
			save = tmp->next;
			free (tmp);
			tmp = save; 
		}
		table[i] = NULL;
	}
	g_flow_id = 0;
	num_ip_info_elements = 0;
	
	//CLEAN UP IP_INFOS	
	struct ip_info_s *tmp1, *save1;
	tmp1 = ip_infos;		
	while (tmp1) {
		save1 = tmp1->next;
		free (tmp1);			
		tmp1  = save1; 
	}
	ip_infos = NULL;
	memset (&cnt, 0, sizeof(cnt));
}

SEXP get_ipaddr_vector (void)
{
	struct ip_info_s *tmp;
	char ip_addr_str [32];
	SEXP vec;
	SEXP e;
	int i;

	vec = allocVector (STRSXP, num_ip_info_elements);
	tmp = ip_infos; 
	i = 0;

	while (tmp != NULL) {
		conv_ip_to_str (ip_addr_str, tmp->ip_addr);
		e = mkChar (ip_addr_str);
		SET_STRING_ELT (vec, i, e);
		tmp = tmp->next;		
		i++;
	}	
	return vec;
}


SEXP get_num_ip_pkts_sent_vector (void)
{
	struct ip_info_s *tmp;
//	char ip_addr_str [32];
	SEXP vec;
//	SEXP e;
 	int i;

	vec = allocVector (REALSXP, num_ip_info_elements);
	tmp = ip_infos; 
	i = 0;

	while (tmp != NULL) {
		REAL(vec)[i] = (double)tmp->num_pkts_sent;
		tmp = tmp->next;		
		i++;
	}	
    return vec;
}



SEXP get_num_ip_pkts_rcvd_vector (void)
{
        struct ip_info_s *tmp;
        SEXP vec;
        int i;

        vec = allocVector (REALSXP, num_ip_info_elements);
        tmp = ip_infos;
        i = 0;

        while (tmp != NULL) {
                REAL(vec)[i] = (double)tmp->num_pkts_received;
                tmp = tmp->next;
                i++;
        }
        return vec;
}

void  
get_num_flows (int *num_flows) 
{
	*num_flows = cnt.num_tcp_flows;   
}




SEXP get_src_ipaddr_vector (void)
{
	struct flow_s *tmp;
	char ip_addr_str [32];
	SEXP vec;
	SEXP e;
	uint32 i,n = 0;

	vec = allocVector (STRSXP, cnt.num_tcp_flows);
	for (i = 0; i < MAX_HASH_LENGTH && n < cnt.num_tcp_flows; i++) {
		tmp = table [i];
		while (tmp != NULL) {
			conv_ip_to_str (ip_addr_str, tmp->src_ip);
			e = mkChar (ip_addr_str);
			SET_STRING_ELT (vec, n, e);
			tmp = tmp->next;		
			n++;
		}	
	}
	return vec;
}

SEXP get_dst_ipaddr_vector (void)
{
	struct flow_s *tmp;
	char ip_addr_str [32];
	SEXP vec;
	SEXP e;
	uint32 i,n = 0;

	vec = allocVector (STRSXP, cnt.num_tcp_flows);
	for (i = 0; i < MAX_HASH_LENGTH && n < cnt.num_tcp_flows; i++) {
		tmp = table [i];
		while (tmp != NULL) {
			conv_ip_to_str (ip_addr_str, tmp->dst_ip);
			e = mkChar (ip_addr_str);
			SET_STRING_ELT (vec, n, e);
			tmp = tmp->next;		
			n++;
		}	
	}
	return vec;
}


SEXP get_src_port_vector (void)
{
	struct flow_s *tmp;
	SEXP vec;
	uint32 i, n = 0;

	vec = allocVector (REALSXP, cnt.num_tcp_flows);
	for (i = 0; i < MAX_HASH_LENGTH && n < cnt.num_tcp_flows; i++) {
		tmp = table [i];
		while (tmp != NULL) {
			REAL(vec)[n] = (double)tmp->src_port;
			tmp = tmp->next;		
			n++;
		}	
	}
	return vec;
}


SEXP get_dst_port_vector (void)
{
	struct flow_s *tmp;
	SEXP vec;
//	SEXP e;
	uint32 i, n = 0;

	vec = allocVector (REALSXP, cnt.num_tcp_flows);
	for (i = 0; i < MAX_HASH_LENGTH && n < cnt.num_tcp_flows; i++) {
		tmp = table [i];
		while (tmp != NULL) {
			REAL(vec)[n] = (double)tmp->dst_port;
			tmp = tmp->next;		
			n++;
		}	
	}
	return vec;
}

SEXP get_flow_id_vector (void)
{
	struct flow_s *tmp;
	SEXP vec = NULL;
//	SEXP e;
	uint32 i, n = 0;

	vec = allocVector (REALSXP, cnt.num_tcp_flows);
	for (i = 0; i < MAX_HASH_LENGTH && n < cnt.num_tcp_flows; i++) {
		tmp = table [i];
		while (tmp != NULL) {
			REAL(vec)[n] = (double)tmp->flow_id;
			tmp = tmp->next;		
			n++;
		}	
	}
	return vec;
}

SEXP get_start_time_vector (void)
{
	struct flow_s *tmp;
	SEXP vec;
//	SEXP e;
	uint32 i, n = 0;

	vec = allocVector (REALSXP, cnt.num_tcp_flows);
	for (i = 0; i < MAX_HASH_LENGTH && n < cnt.num_tcp_flows; i++) {
		tmp = table [i];
		while (tmp != NULL) {
			REAL(vec)[n] = (double)tmp->src_timestamps[0];
			tmp = tmp->next;		
			n++;
		}	
	}
	return vec;
}


struct flow_s *
find_flow_by_id (uint32 flow_id)
{
	int i; 
	struct flow_s *tmp; 
	
	for (i = 0; i < MAX_HASH_LENGTH; i++) {
		tmp = table[i]; 
		while (tmp != NULL) {
			if (tmp->flow_id == flow_id) {
				return (tmp); 
			}
			tmp = tmp->next; 
		}		
	}	
	return (NULL); 
	
}

#if 0
SEXP get_src_timestamps_vector (SEXP flow_id)
{
	int i; 
	uint32 id = (unsigned int) REAL(flow_id)[0];
	struct flow_s *flow;
	SEXP vec = NULL;

	flow = find_flow_by_id (id);
	if (flow) {
		vec = allocVector (REALSXP, flow->num_pkts);
		for (i = 0; i < flow->num_pkts; i++) {
			REAL(vec)[i] = (double)flow->src_timestamps[i];
		}
	} 
	return vec;
}

SEXP get_dst_timestamps_vector (SEXP flow_id)
{
	int i; 
	uint32 id = (unsigned int) REAL(flow_id)[0];
	struct flow_s *flow;
	SEXP vec = NULL;

	flow = find_flow_by_id (id);
	if (flow) {
		vec = allocVector (REALSXP, flow->num_pkts);
		for (i = 0; i < flow->num_pkts; i++) {
			REAL(vec)[i] = (double)flow->dst_timestamps[i];
		}
	} 
	return vec;
}
#else
SEXP get_src_timestamps_vector (SEXP flow_id)
{
    int i;
    uint32 id = (unsigned int) REAL(flow_id)[0];
    struct flow_s *flow;
    uint64 base_ts = 0LL;
    SEXP vec = NULL;

    flow = find_flow_by_id (id);
    if (flow) {
        vec = allocVector (REALSXP, flow->num_pkts);

        /* find first timestamp */
        for (i = 0; i < flow->num_pkts; i++) {
            if (flow->src_timestamps[i]) {
                base_ts = flow->src_timestamps[i];
                break;
            }
        }

        for (i = 0; i < flow->num_pkts; i++) {
            if (flow->src_timestamps[i]) {
                //printf ("base_ts = %llu pkt_ts = %llu ts = %llu\n", 
                //      base_ts, flow->src_timestamps[i], (flow->src_timestamps[i]-base_ts)/1000);
                REAL(vec)[i] = (double)(flow->src_timestamps[i] - base_ts);
            }
            else {
                REAL(vec)[i] = (double)flow->src_timestamps[i];
            }
        }
    }
    return vec;
}

SEXP get_dst_timestamps_vector (SEXP flow_id)
{
    uint32 id = (unsigned int) REAL(flow_id)[0];
    uint64 base_ts = 0LL;
    struct flow_s *flow;
    SEXP vec = NULL;
    int i;

    flow = find_flow_by_id (id);
    if (flow) {
        /* find first timestamp */
        for (i = 0; i < flow->num_pkts; i++) {
            if (flow->src_timestamps[i]) {
                base_ts = flow->src_timestamps[i];
                break;
            }
        }
        vec = allocVector (REALSXP, flow->num_pkts);
        for (i = 0; i < flow->num_pkts; i++) {
            if (flow->dst_timestamps[i]) {
                REAL(vec)[i] = (double)(flow->dst_timestamps[i] - base_ts);
            }
            else {
                REAL(vec)[i] = (double)(flow->dst_timestamps[i]);
            }
        }
    }
    return vec;
}

#endif



SEXP get_src_ack_nums_vector (SEXP flow_id)
{
	int i; 
	uint32 id = (unsigned int) REAL(flow_id)[0];
	struct flow_s *flow;
	SEXP vec = NULL;

	flow = find_flow_by_id (id);
	if (flow) {
		vec = allocVector (REALSXP, flow->num_pkts);
		for (i = 0; i < flow->num_pkts; i++) {
			REAL(vec)[i] = (double)flow->src_ack_nums[i];
		}
	} 
	return vec;
}

SEXP get_src_seq_nums_vector (SEXP flow_id)
{
	int i; 
	uint32 id = (unsigned int) REAL(flow_id)[0];
	struct flow_s *flow;
	SEXP vec = NULL;

	flow = find_flow_by_id (id);
	if (flow) {
		vec = allocVector (REALSXP, flow->num_pkts);
		for (i = 0; i < flow->num_pkts; i++) {
			REAL(vec)[i] = (double)flow->src_seq_nums[i];
		}
	} 
	return vec;
}

SEXP get_dst_ack_nums_vector (SEXP flow_id)
{
	int i; 
	uint32 id = (unsigned int) REAL(flow_id)[0];
	struct flow_s *flow;
	SEXP vec = NULL;

	flow = find_flow_by_id (id);
	if (flow) {
		vec = allocVector (REALSXP, flow->num_pkts);
		for (i = 0; i < flow->num_pkts; i++) {
			REAL(vec)[i] = (double)flow->dst_ack_nums[i];
		}
	} 
	return vec;
}

SEXP get_dst_seq_nums_vector (SEXP flow_id)
{
	int i; 
	uint32 id = (unsigned int) REAL(flow_id)[0];
	struct flow_s *flow;
	SEXP vec = NULL;

	flow = find_flow_by_id (id);
	if (flow) {
		vec = allocVector (REALSXP, flow->num_pkts);
		for (i = 0; i < flow->num_pkts; i++) {
			REAL(vec)[i] = (double)flow->dst_seq_nums[i];
		}
	} 
	return vec;
}


#else

int main (int argc, char *argv[])
{
    parse_pcap_file (argv[1], 1);
}



#endif

