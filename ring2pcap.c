#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/net_tstamp.h>

#if __BYTE_ORDER == __BIG_ENDIAN
#        define NATIVE2COMPAT(x) (sizeof(struct timeval) != 8 ? (__u32)(x >> 32) : (x))
#else
#        define NATIVE2COMPAT(x) ((__u32)(x))
#endif

/* From pcap.h */

struct timeval_compat {
     __u32 tv_sec;     /* seconds */
     __u32 tv_usec;    /* microseconds */
};

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

#define PCAP_MAGIC 0xa1b2c3d4
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4
#define CRATIONMASK (S_IRUSR|S_IWUSR)
#define FLUSH_THRESHOLD 12

#define SNAPLEN 65536

#define TP_BLOCK_NR  4          /* greater than TPACKET_HDRLEN */
#define TP_FRAMES_NR 8          /* exactly frames_per_block*tp_block_nr */
#define TP_FRAME_SIZE    2048   /* multiple of TPACKET_ALIGNMENT */
#define TP_BLOCK_MINSIZE 4096   /* multiple of PAGE_SIZE */

#define TPKT2LOAD(x) ((char *) x + TPACKET_HDRLEN + 14)
#define LOAD2TPKT(x) ((char *) x - TPACKET_HDRLEN - 14)

#define MAX_LEN_ERRORMSG 2048
#define ERROR(x...) do{LOG(LOG_ERR, "ERROR: " x);exit(EXIT_FAILURE);}while(0)
#define LOG(prio,x...) do{if(daemonize > 1) syslog(prio, x);    \
          else fprintf(stderr,"net2pcap: " x);} while(0)

int daemonize = 0;
volatile sig_atomic_t term_received = 0;

void PERROR(char *err)
{
     char errormsg[MAX_LEN_ERRORMSG];

     strerror_r(errno, errormsg, MAX_LEN_ERRORMSG);
     /* LOG(LOG_CRIT, "%s: %s\n", err, errormsg); */
     perror(err);
     exit(EXIT_FAILURE);
}

void term_handler(int x)
{
     term_received = 1;
}

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

void set_promiscuous(int sock, int ifidx, int val)
{
     struct packet_mreq mreq;
     int action;

     mreq.mr_ifindex = ifidx;
     mreq.mr_type = PACKET_MR_PROMISC;
     mreq.mr_alen = 0;
     action = val ? PACKET_ADD_MEMBERSHIP : PACKET_DROP_MEMBERSHIP;

     if (setsockopt(sock, SOL_PACKET, action, &mreq, sizeof(mreq)) == -1)
          PERROR("setsockopt(promiscuous)");
}

int get_iface_index(int sock, char *iface)
{
     struct ifreq ifr;

     strncpy(ifr.ifr_name, iface, IF_NAMESIZE);
     if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1)
          PERROR("ioctl");
     return ifr.ifr_ifindex;
}

void *setup_packetring(int sock)
{
     int ret, timesource = SOF_TIMESTAMPING_RAW_HARDWARE ; /* XXX or SOF_TIMESTAMPING_SYS_HARDWARE */
     size_t ringsize;
     void *ringbuf;
     struct tpacket_req treq =
          {
               .tp_block_size = TP_BLOCK_MINSIZE,
               .tp_block_nr   = TP_BLOCK_NR,
               .tp_frame_size = TP_FRAME_SIZE,
               .tp_frame_nr   = TP_FRAMES_NR,
          };

     ret = setsockopt(sock, SOL_PACKET, PACKET_RX_RING,
                      (void *)&treq, sizeof(treq));
     if (ret == -1)
          PERROR("setsockopt(PACKET_RX_RING)");


     /* ret = setsockopt(sock, SOL_PACKET, PACKET_TIMESTAMP, */
     /*                  (void *)&timesource, sizeof(timesource)); */
     /* if (ret == -1) */
     /*      PERROR("setsockopt(PACKET_TIMESTAMP)"); */

     ringsize = treq.tp_block_size * treq.tp_block_nr;
     ringbuf = mmap(NULL, ringsize, PROT_READ|PROT_WRITE, MAP_SHARED, sock, 0);
     if (ringbuf == MAP_FAILED)
          PERROR("mmap(PACKET_RX_RING)");

     return ringbuf;
}

void flush_packets(int fd, struct iovec *iov, unsigned long n)
{
     int i;

     if (vmsplice(fd, iov, n, SPLICE_F_MOVE) == -1)
          PERROR("vmsplice()");

     /* packets were written, we can now release the ring entries */
     for (i=1 ; i < n; i += 2)
     {
          struct iovec *v = (iov+i);
          struct tpacket_hdr *tpkt = (struct tpacket_hdr *) LOAD2TPKT(v->iov_base);
          tpkt->tp_status = TP_STATUS_KERNEL;
     }
}

void packet_harvester(int fd, void *base)
{
     unsigned int i, j, k;
     struct pcap_pkthdr pcaphdr[2*TP_FRAMES_NR];
     struct iovec iov[2*TP_FRAMES_NR];

     i = j = k = 0;
     while (! term_received)
     {
          struct tpacket_hdr *hdr;
          struct pcap_pkthdr *phdr;

          hdr  = (struct tpacket_hdr *) ((char *)base + i*TP_FRAME_SIZE);
          
          if (hdr->tp_status & TP_STATUS_USER)
          {
               if (hdr->tp_status & TP_STATUS_LOSING)
               {
                    printf("loosing packets, fuck!\n");
                    exit(0);
               }

               phdr = (pcaphdr + k++);

               phdr->len        = hdr->tp_len;
               phdr->caplen     = hdr->tp_snaplen;
               phdr->ts.tv_sec  = NATIVE2COMPAT(hdr->tp_sec);
               phdr->ts.tv_usec = NATIVE2COMPAT(hdr->tp_usec);

               /* printf("%x %x %x %x\n", phdr->len, phdr->caplen, phdr->ts.tv_sec, phdr->ts.tv_usec); */
               iov[j].iov_len = sizeof(pcaphdr);
               iov[j].iov_base = phdr;
               j++;

               iov[j].iov_len = hdr->tp_len;
               iov[j].iov_base = TPKT2LOAD(hdr);
               /* printf("mac=%d net=%d hdr=%p load=%p\n", hdr->tp_mac, hdr->tp_net, hdr, iov[j].iov_base); */

               hexdump(iov[j].iov_base, iov[j].iov_len);
               j++;

          }
          /* XXX check that 2*TP_FRAMES_NR < IOV_MAX */
          i++;
          if (i >= TP_FRAMES_NR)
          {
               /* if (j > FLUSH_THRESHOLD) */
               if (j > 0)
               {
                    flush_packets(fd, iov, j);
                    j = k = 0;
               }
               i = 0;
          }
     }
}

void writer(char *filename, int fd_in)
{
     int fd_out;
     ssize_t len;
     struct pcap_file_header fhdr;
     struct timeval native_tv;
     struct timezone tz;
     off_t filepos;

     /* opening the file in append mode is incompatible with splice() */
     fd_out = open(filename, O_CREAT|O_WRONLY, CRATIONMASK);
     if (fd_out < 0)
          PERROR("open(pcapfile)");

     filepos = lseek(fd_out, 0, SEEK_END);
     if (filepos == -1)
          PERROR("lseek");

     if (!filepos)
     { 
          /* Empty file --> add header */
          LOG(LOG_NOTICE, "Creating capture file %s\n", filename);

          if (gettimeofday(&native_tv, &tz) == -1)
               PERROR("gettimeofday");

          fhdr.magic         = PCAP_MAGIC;
          fhdr.version_major = PCAP_VERSION_MAJOR;
          fhdr.version_minor = PCAP_VERSION_MINOR;
          fhdr.thiszone      = tz.tz_dsttime; /* XXX */
          fhdr.sigfigs       = 0; 
          fhdr.snaplen       = SNAPLEN;
          fhdr.linktype      = 1; /* XXX:1= LINKTYPE_ETHERNET */

          write(fd_out, &fhdr, sizeof(fhdr));
     }
     else
     {
          LOG(LOG_NOTICE, "Appending to capture file %s\n", filename);
     }

     while (1)
     {
          len = splice(fd_in, NULL, fd_out, NULL, 4096, SPLICE_F_MOVE|SPLICE_F_MORE);
          if (len == -1)
               PERROR("splice(pcapfile)");
          if (len == 0)
               sleep(1);
     }
}


int main(int argc, char *argv[])
{
     char *iface = "eth0"; /* XXX */
     char *pcapfile = "/tmp/ring2pcap.pcap"; /* XXX */
     int sock, ifdx;
     int ptype = ETH_P_ALL;
     void *ringbuf;
     struct sigaction sa;
     int pipes[2];
     pid_t child;

     sa.sa_handler = &term_handler;
     if (sigemptyset(&sa.sa_mask) == -1)
          ERROR("sigemptyset");
     sa.sa_flags= SA_RESTART;
     if (sigaction(SIGTERM, &sa, NULL) == -1)
          PERROR("sigaction(term)");

     if (pipe(pipes) == -1)
          PERROR("socketpair()");

     child = fork();
     if (child == -1)
          PERROR("fork(child_writer)");

     if (child == 0)
     {
          if (close(pipes[1]) == -1)
               PERROR("close(pipes[W])");
          writer(pcapfile, pipes[0]);
          exit(EXIT_SUCCESS);
     }

     if (close(pipes[0]) == -1)
          PERROR("close(pipes[R])");

     sock = socket(PF_PACKET, SOCK_RAW, htons(ptype));
     if (sock == -1)
          PERROR("socket(SOCK_RAW)");

     ifdx = get_iface_index(sock, iface);
     set_promiscuous(sock, ifdx, 1);
     ringbuf = setup_packetring(sock);
     packet_harvester(pipes[1], ringbuf);
     set_promiscuous(sock, ifdx, 0);

     /* XXX: kill shared memory? */

     exit(EXIT_SUCCESS);
}

/* Local Variables: */
/* c-default-style: k&r */
/* End: */
