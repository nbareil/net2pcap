/*
 * net2pcap --- an auditable packet capture tool
 *              see http://www.secdev.org/projects/net2pcap.html
 *              for more informations
 *
 * Copyright (C) 2003-2013  Philippe Biondi <phil@secdev.org>
 *                          Nicolas Bareil <nico@chdir.org>
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

#define IDENT "##PACKAGE_NAME -- ## PACKAGE_URL\n"

#define _FILE_OFFSET_BITS 64
#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <netinet/if_ether.h>
#include <getopt.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/signalfd.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <stdlib.h>
#if HAVE_SECCOMP_H
#        include <seccomp.h>
#endif
#include <syslog.h>
#include <string.h>
#include <unistd.h>

#ifndef O_LARGEFILE /* needed for SECCOMP rule */
#        define O_LARGEFILE    00100000
#endif

#define MAX(a,b) (a > b ? a : b)

#define DEFAULT_SNAPLEN 65535
#define MAX_LEN_ERRORMSG 2048

#if __BYTE_ORDER == __BIG_ENDIAN
#        define NATIVE2COMPAT(x) (sizeof(struct timeval) != 8 ? (uint32_t)(x >> 32) : (x))
#else
#        define NATIVE2COMPAT(x) ((uint32_t)(x))
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
        uint32_t tv_sec;     /* seconds */
        uint32_t tv_usec;    /* microseconds */
};

/* From pcap.h */

struct pcap_file_header {
	uint32_t magic;
	uint16_t version_major;
	uint16_t version_minor;
	int32_t thiszone;     /* gmt to local correction */
	uint32_t sigfigs;    /* accuracy of timestamps */
	uint32_t snaplen;    /* max length saved portion of each pkt */
	uint32_t linktype;   /* data link type (LINKTYPE_*) */
};

struct pcap_pkthdr {
	struct timeval_compat ts;      /* time stamp using 32 bits fields */
	uint32_t caplen;     /* length of portion present */
	uint32_t len;        /* length this packet (off wire) */
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
                "\t snaplen   defaults to %d\n"
                "\t capfile   defaults to net2pcap.cap\n"
                "\t ethertype defaults to ETH_P_ALL (sniff all)\n",
                DEFAULT_SNAPLEN);
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


/* xwrite(): wrapper handling partial writes */
void xwrite(int fd, void *buf, size_t len) {
        ssize_t ret;
        size_t remaining = len;

        do {
                ret = write(fd, buf, remaining);
                if (ret == -1) {
                        if (errno == EAGAIN || errno == EINTR)
                                continue;
                        else
                                PERROR("write(buf)");
                }
                remaining  -= ret;
                buf += ret;
        } while (remaining > 0);
}

int only_digits(char *s) {
        char c;
        int nondigit_found = 0;

        while (c = *s++) {
                if (! isdigit(c)) {
                        nondigit_found = 1;
                }
        }

        return !nondigit_found;
}

int term_received = 0, hup_received = 0;

int main(int argc, char *argv[])
{
	int s, l, sigfd;
	int ptype = ETH_P_ALL;
	char *iff = NULL;
        char *newroot = NULL;
	char *fcap = "net2pcap.cap";
	int promisc = 1;
	int ifidx = 0;
	char c;
	void *buf;
	size_t snaplen = DEFAULT_SNAPLEN;
	int f;
	struct sockaddr_ll sll;
	struct pcap_file_header hdr;
	struct pcap_pkthdr phdr;
        struct passwd *user_entry;
        struct group *group_entry;
	struct timeval native_tv;
	struct timezone tz;
	struct sigaction sa;
        struct signalfd_siginfo sigfdinfo;
        sigset_t mask;
	int xdump = 0;
	unsigned long long int pktnb = 0;
	int linktype;
        uid_t uid = 0;
        gid_t gid = 0;
        fd_set readset;
#if HAVE_SECCOMP_H
        scmp_filter_ctx ctx;
#endif

        sigemptyset(&mask);
        sigaddset(&mask, SIGINT);
        sigaddset(&mask, SIGTERM);
        sigaddset(&mask, SIGQUIT);
        sigaddset(&mask, SIGHUP);

        if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1)
                PERROR("sigprocmask()");

        sigfd = signalfd(-1, &mask, 0);
        if (sigfd == -1)
                PERROR("signalfd()");

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
                        errno = 0;
			snaplen = strtoul(optarg, NULL,0);
                        if (errno)
                                PERROR("invalid snaplen");
			break;
		case 'd':
			daemonize = 1;
			break;
                case 'u':
                        errno = 0;
                        if (only_digits(optarg)) {
                                uid = strtoul(optarg, NULL, 0);
                                if (errno) {
                                        PERROR("Invalid uid");
                                }
                        } else {
                                errno = 0;
                                user_entry = getpwnam(optarg);
                                if (user_entry == NULL) {
                                        if (errno) {
                                                PERROR("getpwent()");
                                        } else {
                                                ERROR("Username not found\n");
                                        }
                                }
                                uid = user_entry->pw_uid;
                        }
                        break;
                case 'g':
                        errno = 0;
                        if (only_digits(optarg)) {
                                gid = strtoul(optarg, NULL, 0);
                                if (errno) {
                                        ERROR("Invalid gid");
                                }
                        } else {
                                errno = 0;
                                group_entry = getgrnam(optarg);
                                if (group_entry == NULL) {
                                        if (errno) {
                                                PERROR("getgrnam()");
                                        } else {
                                                ERROR("Group name not found\n");
                                        }
                                }
                                gid = group_entry->gr_gid;
                        }
                        break;
		case 'x':
			xdump = 1;
			break;
		default:
			printf("Error!\n");
			usage();
		}
	}

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

        if (daemonize) {
                openlog("net2pcap", LOG_PID|LOG_NDELAY, LOG_DAEMON);
                if (daemon(0, 0) != 0)
                        PERROR("daemon()");
                daemonize++;
        }

        if (newroot) {
                if (chroot(newroot) != 0)
                        PERROR("chroot");
                if (chdir("/") != 0)
                        PERROR("chdir(/)");
        }

        if (uid && !gid) {
                /*
                 * uid set but gid not, good behavior is to
                 * set gid to primary group of uid
                 */
                errno = 0;
                user_entry = getpwuid(uid);
                if (!user_entry) {
                        if (errno)
                                PERROR("getpwuid()");
                        else
                                ERROR("uid %d does not exist,"
                                      " cannot find primary group\n",
                                      uid);
                }
                gid = user_entry->pw_gid;
        }

        if (gid && (setgid(gid) == -1))
                PERROR("setgid()");

        if (uid && (setuid(uid) == -1))
                PERROR("setuid()");

#if HAVE_SECCOMP_H
        ctx = seccomp_init(SCMP_ACT_KILL);

        if (ctx == NULL)
                ERROR("Cannot go into SECCOMPv2");

        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1,
                         SCMP_A1(SCMP_CMP_EQ, O_CREAT|O_WRONLY|O_APPEND|O_LARGEFILE));
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socketcall), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettimeofday), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(_llseek), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(_newselect), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sigreturn), 0);

        if (daemonize) {
                seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(time), 0);
                seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat64), 0);
                seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap2), 0);
                seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
        }

        if (seccomp_load(ctx) < 0)
                ERROR("Cannot load SECCOMP filters");

        LOG(LOG_INFO,"Started [sandboxed].\n");
        seccomp_release(ctx);
#else
        LOG(LOG_INFO,"Started.\n");
#endif /* HAVE_SECCOMP_H */


	while (!term_received) { /* Main loop */
                off_t filepos;
        	/* Prepare capture file */
        	f = open(fcap, O_CREAT|O_WRONLY|O_APPEND, CRATIONMASK);
		if (f == -1) PERROR("open(append)");
                filepos = lseek(f, 0, SEEK_END);
                if (filepos == -1) PERROR("lseek");
                if (!filepos) { /* Empty file --> add header */
        		LOG(LOG_NOTICE, "Creating capture file %s\n", fcap);
                        if (gettimeofday(&native_tv, &tz) == -1) PERROR("gettimeofday");
                 	hdr.magic = PCAP_MAGIC;
                	hdr.version_major = PCAP_VERSION_MAJOR;
                	hdr.version_minor = PCAP_VERSION_MINOR;
                	hdr.thiszone = tz.tz_dsttime; /* XXX */
                	hdr.sigfigs = 0; 
                	hdr.snaplen = snaplen;
                	hdr.linktype = linktype; 
                        xwrite(f, &hdr, sizeof(hdr));
		} else 
			LOG(LOG_NOTICE, "Appending to capture file %s\n", fcap);

        	hup_received = 0;
		pktnb = 0;
        	while (!hup_received && !term_received) {  /* Receive loop */
                        FD_ZERO(&readset);
                        FD_SET(s, &readset);
                        FD_SET(sigfd, &readset);

                        if (select(MAX(s, sigfd) + 1, &readset, NULL, NULL, NULL) == -1)
                                PERROR("select()");

                        if (FD_ISSET(s, &readset))
                        {
                                ssize_t rcvdlen = recv(s, buf, snaplen, 0);
                                if (rcvdlen == -1)
                                        PERROR("recv");
                                if (xdump && !daemonize)
                                        hexdump(buf, rcvdlen);
                                gettimeofday(&native_tv, NULL);

                                phdr.ts.tv_sec  = NATIVE2COMPAT(native_tv.tv_sec);
                                phdr.ts.tv_usec = NATIVE2COMPAT(native_tv.tv_usec);

                                phdr.len    = rcvdlen;
                                phdr.caplen = rcvdlen;

                                xwrite(f, &phdr, sizeof(phdr));
                                xwrite(f, buf, rcvdlen);
                                pktnb++;
                        }

                        if (FD_ISSET(sigfd, &readset))
                        {
                                if (read(sigfd, &sigfdinfo, sizeof(sigfdinfo)) != sizeof(sigfdinfo))
                                        PERROR("read(signalfd_siginfo)");

                                switch (sigfdinfo.ssi_signo)
                                {
                                        case SIGINT:
                                        case SIGTERM:
                                                term_received = 1;
                                                break;
                                        case SIGHUP:
                                                hup_received = 1;
                                                break;
                                        default:
                                                ERROR("signal %d received", sigfdinfo.ssi_signo);
                                }
                        }
        	}
		LOG(LOG_INFO,"Received %lld packets\n", pktnb);
        	if (close(f) == -1) PERROR("close");
	}
	if (daemonize) closelog();
	LOG(LOG_INFO,"Stopped.\n");
        exit(EXIT_SUCCESS);
}
