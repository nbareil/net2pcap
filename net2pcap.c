/*
 * net2pcap --- an auditable packet capture tool
 *              see http://www.secdev.org/projects/net2pcap.html
 *              for more informations
 *
 * Copyright (C) 2003-2011  Philippe Biondi <phil@secdev.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#define IDENT "net2pcap -- http://www.secdev.org/projects/net2pcap.html\n"

#define _FILE_OFFSET_BITS 64

#include <sys/types.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <getopt.h>
#include <stdio.h>
#include <errno.h>
#include <sys/time.h>
#include <signal.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>

#define MAX_LEN_ERRORMSG 2048

#if __BYTE_ORDER == __BIG_ENDIAN
#  error "net2pcap is not compatible with big endian architecture because of timestamp issues"
#endif

int daemonize = 0;

#define ERROR(x...) do{LOG(LOG_ERR, "ERROR: " x);exit(EXIT_FAILURE);}while(0)
#define LOG(prio,x...) do{if(daemonize > 1) syslog(prio, x); \
                          else fprintf(stderr,"net2pcap: " x);} while(0)

void PERROR(char *err) {
        char errormsg[MAX_LEN_ERRORMSG];

        strerror_r(errno, errormsg, MAX_LEN_ERRORMSG);
        LOG(LOG_CRIT, "%s: %s\n", err, errormsg);
        exit(EXIT_FAILURE);
}



#define CRATIONMASK (S_IRUSR|S_IWUSR)

struct timeval_compat {
        __u32 tv_sec;     /* seconds */
        __u32 tv_usec;    /* microseconds */
};

/* From pcap.h */

struct pcap_file_header {
	__u32 magic;
	__u16 version_major;
	__u16 version_minor;
	__s32 thiszone;     /* gmt to local correction */
	__u32 sigfigs;    /* accuracy of timestamps */
	__u32 snaplen;    /* max length saved portion of each pkt */
	__u32 linktype;   /* data link type (LINKTYPE_*) */
};

struct pcap_pkthdr {
	struct timeval_compat ts;      /* time stamp using 32 bits fields */
	__u32 caplen;     /* length of portion present */
	__u32 len;        /* length this packet (off wire) */
};


/* mmmh.. what about big endian platforms ? */
#define PCAP_MAGIC 0xa1b2c3d4
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4


/* made from pcap-linux.c and bpf/net/bpf.h */

#ifndef ARPHRD_IEEE80211_PRISM  /* From Linux 2.4.18 */
#define ARPHRD_IEEE80211_PRISM 802
#endif

#define LINKTYPE_NULL           0
#define LINKTYPE_ETHERNET       1      /* also for 100Mb and up */
#define LINKTYPE_EXP_ETHERNET   2       /* 3Mb experimental Ethernet */
#define LINKTYPE_AX25           3
#define LINKTYPE_PRONET         4
#define LINKTYPE_CHAOS          5
#define LINKTYPE_TOKEN_RING     6     /* DLT_IEEE802 is used for Token Ring */
#define LINKTYPE_ARCNET         7
#define LINKTYPE_SLIP           8
#define LINKTYPE_PPP            9
#define LINKTYPE_FDDI           10
#define LINKTYPE_PPP_HDLC       50              /* PPP in HDLC-like framing */
#define LINKTYPE_PPP_ETHER      51              /* NetBSD PPP-over-Ethernet */
#define LINKTYPE_ATM_RFC1483    100             /* LLC/SNAP-encapsulated ATM */
#define LINKTYPE_RAW            101             /* raw IP */
#define LINKTYPE_SLIP_BSDOS     102             /* BSD/OS SLIP BPF header */
#define LINKTYPE_PPP_BSDOS      103             /* BSD/OS PPP BPF header */
#define LINKTYPE_C_HDLC         104             /* Cisco HDLC */
#define LINKTYPE_IEEE802_11     105             /* IEEE 802.11 (wireless) */
#define LINKTYPE_ATM_CLIP       106             /* Linux Classical IP over ATM */
#define LINKTYPE_LOOP           108             /* OpenBSD loopback */
#define LINKTYPE_LINUX_SLL      113             /* Linux cooked socket capture */
#define LINKTYPE_LTALK          114             /* Apple LocalTalk hardware */
#define LINKTYPE_ECONET         115             /* Acorn Econet */
#define LINKTYPE_CISCO_IOS      118             /* For Cisco-internal use */
#define LINKTYPE_PRISM_HEADER   119             /* 802.11+Prism II monitor mode */
#define LINKTYPE_AIRONET_HEADER 120             /* FreeBSD Aironet driver stuff */

int pcap_map[] = { ARPHRD_ETHER, LINKTYPE_ETHERNET,
		   ARPHRD_METRICOM, LINKTYPE_ETHERNET,
		   ARPHRD_LOOPBACK, LINKTYPE_ETHERNET,
		   ARPHRD_EETHER, LINKTYPE_EXP_ETHERNET,
		   ARPHRD_AX25, LINKTYPE_AX25,
		   ARPHRD_PRONET, LINKTYPE_PRONET,
		   ARPHRD_CHAOS, LINKTYPE_CHAOS,
		   ARPHRD_IEEE802_TR, LINKTYPE_TOKEN_RING,
		   ARPHRD_IEEE802, LINKTYPE_TOKEN_RING,
		   ARPHRD_ARCNET, LINKTYPE_ARCNET,
		   ARPHRD_FDDI, LINKTYPE_FDDI,
		   ARPHRD_ATM, LINKTYPE_LINUX_SLL,
		   ARPHRD_IEEE80211, LINKTYPE_IEEE802_11,
		   ARPHRD_IEEE80211_PRISM, LINKTYPE_PRISM_HEADER,
		   ARPHRD_PPP, LINKTYPE_RAW,
		   ARPHRD_HDLC, LINKTYPE_C_HDLC,
		   ARPHRD_TUNNEL, LINKTYPE_RAW,
		   ARPHRD_SIT, LINKTYPE_RAW,
		   ARPHRD_CSLIP, LINKTYPE_RAW,
		   ARPHRD_SLIP6, LINKTYPE_RAW,
		   ARPHRD_CSLIP6,LINKTYPE_RAW,
		   ARPHRD_ADAPT, LINKTYPE_RAW,
		   ARPHRD_SLIP, LINKTYPE_RAW,
		   ARPHRD_RAWHDLC, LINKTYPE_RAW,
		   ARPHRD_LOCALTLK, LINKTYPE_LTALK,
		   0, 0};

int arphdr_to_linktype(int arphdr)
{
	int *p;

	for (p = pcap_map; *p; p += 2)
		if (*p == arphdr)
			return *(p+1);
	return -1;
}

void usage(void)
{
        fprintf(stderr, IDENT
                "Usage: net2pcap -i interface [-pdx] [-f capfile] [-t ethertype] [-s snaplen] [-r newroot]\n"
                "\t-p : doesn't set promiscuous mode\n"
                "\t-d : daemon mode (background + uses syslog)\n"
                "\t-x : hexdumps every packet on output (if not daemon)\n"
                "\t-u : drop priviledges to UID\n"
                "\t-g : drop priviledges to GID\n"
                "\t-r : chroot into newroot\n"
                "\t snaplen   defaults to 1600\n"
                "\t capfile   defaults to net2pcap.cap\n"
                "\t ethertype defaults to ETH_P_ALL (sniff all)\n");
        exit(EXIT_FAILURE);
}


/* Hexdump functions */

int sane(unsigned char x)
{
	return ((x >= 0x20) && (x < 0x80));
}

void hexdump(void *buf, int len)
{
	unsigned char *b = buf;
	int i,j;
	
	for (i=0; i < (len+15)/16*16; i++) {
		if (i < len) printf("%02x ",b[i]); else printf("   ");
		if (i%8 == 7) printf(" ");
		if (i%16 == 15) {
			for (j=i-15; (j < i) && (j < len); j++)
				printf("%c", sane(b[j]) ? b[j] : '.');
			printf("\n");
		}
	}
}

int term_received, hup_received; /* in .bss ==> initialized to 0 */ 

void term_handler(int x)
{
	term_received = 1;
}

void hup_handler(int x)
{
	hup_received = 1;
}

int main(int argc, char *argv[])
{
	int s,l;
	int ptype = ETH_P_ALL;
	char *iff = NULL;
        char *newroot = NULL;
	char *fcap = "net2pcap.cap";
	int promisc = 1;
	int ifidx = 0;
	char c;
	void *buf;
	int snaplen = 1600;
	int f;
	struct sockaddr_ll sll;
	struct pcap_file_header hdr;
	struct pcap_pkthdr phdr;
	struct timeval native_tv;
	struct timezone tz;
	struct sigaction sa;
	int xdump = 0;
	unsigned long long int pktnb = 0;
	int linktype;
        uid_t uid = 0;
        gid_t gid = 0;

	sa.sa_handler = &term_handler;
	if (sigemptyset(&sa.sa_mask) == -1) ERROR("sigemptyset");
	sa.sa_flags= SA_RESTART;
	if (sigaction(SIGTERM, &sa, NULL) == -1) PERROR("sigaction(term)");

	sa.sa_handler = &term_handler;
	if (sigemptyset(&sa.sa_mask) == -1) ERROR("sigemptyset");
	if (sigaction(SIGINT, &sa, NULL) == -1) PERROR("sigaction(int)");

	sa.sa_handler = &hup_handler;
	if (sigemptyset(&sa.sa_mask) == -1) ERROR("sigemptyset");
	sa.sa_flags= SA_RESTART;
	if (sigaction(SIGHUP, &sa, NULL) == -1) PERROR("sigaction(hup)");

	/* Get options */

        while ((c = getopt(argc, argv, "dxhi:f:t:r:s:pu:g:")) != -1) {
		switch(c) {
		case 'h':
			usage();
		case 'i':
			iff = optarg;
			break;
		case 'f':
			fcap = optarg;
			break;
		case 't':
			ptype = strtoul(optarg, NULL, 0);
			break;
		case 'p':
			promisc = 0;
			break;
		case 'r':
			newroot = optarg;
			break;
		case 's':
			snaplen = strtoul(optarg, NULL,0);
			break;
		case 'd':
			daemonize = 1;
			break;
                case 'u':
                        uid = strtoul(optarg, NULL,0);
                        break;
                case 'g':
                        gid = strtoul(optarg, NULL,0);
                        break;
		case 'x':
			xdump = 1;
			break;
		default:
			printf("Error!\n");
			usage();
		}
	}

	if (snaplen <= 0) ERROR("Error: bad snaplen\n");
	if (!iff) ERROR ("No interface specified\n");

	buf = malloc(snaplen);
	if (!buf) PERROR("malloc");
	
	/* Prepare socket according to options */

	s = socket(PF_PACKET, SOCK_RAW, htons(ptype));
	if (s == -1) PERROR("socket");

	if (iff) {
		struct ifreq ifr;
		strncpy(ifr.ifr_name, iff, IF_NAMESIZE);
		if (ioctl(s, SIOCGIFINDEX, &ifr) == -1) PERROR("ioctl");
		ifidx = ifr.ifr_ifindex;
	}

	if (promisc) {
		struct packet_mreq mreq;
		mreq.mr_ifindex = ifidx;
		mreq.mr_type = PACKET_MR_PROMISC;
		mreq.mr_alen = 0;
		if (setsockopt(s, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == -1)
			PERROR("setsockopt");
	}
	
	if (ifidx || (ptype != ETH_P_ALL)) {
		sll.sll_family = AF_PACKET;
		sll.sll_protocol = htons(ptype);
		sll.sll_ifindex = ifidx;
		if (bind(s, (struct sockaddr *)&sll, sizeof(sll)) == -1) PERROR("bind");
	}
	
	l = sizeof(sll);
	if (getsockname(s, (struct sockaddr *)&sll, &l) == -1)
		PERROR("getsockname");
	linktype = arphdr_to_linktype(sll.sll_hatype);

        if (newroot) {
                if (chroot(newroot) != 0)
                        PERROR("chroot");
                if (chdir("/") != 0)
                        PERROR("chdir(/)");
        }

        if (gid && (setgid(gid) == -1))
                PERROR("setgid()");

        if (uid && (setuid(uid) == -1))
                PERROR("setuid()");

	if (daemonize) {
                if (daemon(0, 0) != 0)
                        PERROR("daemon()");
		openlog("net2pcap", LOG_PID, LOG_DAEMON);
                daemonize++;
	}

	LOG(LOG_INFO,"Started.\n");

	while (!term_received) { /* Main loop */
	
        	/* Prepare capture file */
        	f = open(fcap, O_CREAT|O_WRONLY|O_APPEND, CRATIONMASK);
		if (f == -1) PERROR("open(append)");
		l = lseek(f, 0, SEEK_END);
		if (l == -1) PERROR("lseek");
		if (!l) { /* Empty file --> add header */
        		LOG(LOG_NOTICE, "Creating capture file %s\n", fcap);
                        if (gettimeofday(&native_tv, &tz) == -1) PERROR("gettimeofday");
                 	hdr.magic = PCAP_MAGIC;
                	hdr.version_major = PCAP_VERSION_MAJOR;
                	hdr.version_minor = PCAP_VERSION_MINOR;
                	hdr.thiszone = tz.tz_dsttime; /* XXX */
                	hdr.sigfigs = 0; 
                	hdr.snaplen = snaplen;
                	hdr.linktype = linktype; 
			if (write(f, &hdr, sizeof(hdr)) == -1) PERROR("write(hdr)");
		} else 
			LOG(LOG_NOTICE, "Appending to capture file %s\n", fcap);

        	hup_received = 0;
		pktnb = 0;
        	while (!hup_received && !term_received) {  /* Receive loop */
        		l = recv(s, buf, snaplen, 0);
        		if (l == -1) PERROR("recv");
        		if (xdump && !daemonize)
        			hexdump(buf, l);
                        gettimeofday(&native_tv, NULL);

                        phdr.ts.tv_sec  = (__u32) native_tv.tv_sec;
                        phdr.ts.tv_usec = (__u32) native_tv.tv_usec;

        		phdr.caplen = l;
        		phdr.len = l;
        		if (write(f, &phdr, sizeof(phdr)) == -1) PERROR("write(phdr)");
        		if (write(f, buf, l) == -1) PERROR("write(buf)");
			pktnb++;
        	}
		LOG(LOG_INFO,"Received %lld packets\n", pktnb);
        	if (close(f) == -1) PERROR("close");
	}
	if (daemonize) closelog();
	LOG(LOG_INFO,"Stopped.\n");
        exit(EXIT_SUCCESS);
}
