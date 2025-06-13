/*
 * Copyright 2000 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <errno.h>
#include <err.h>

#include "config.h"

struct phdr { 
  unsigned long saddr;
  unsigned long daddr;
  char zero;
  unsigned char protocol;
  unsigned short length;
};

#define MAXSOCKS	32

extern int port;

static int synsock[MAXSOCKS];
static int current;

static struct in_addr synsrc;

pcap_t *
pcap_filter_init(char *filter)
{
	pcap_t *pd;
  	struct bpf_program fcode;
	char ebuf[PCAP_ERRBUF_SIZE];
	char *dev;
	u_int net, mask;

	if ((dev = pcap_lookupdev(ebuf)) == NULL)
		errx(1, "pcap_filter_init: %s", ebuf);
	fprintf(stderr, "pcap on %s\n", dev);
	if (pcap_lookupnet(dev, &net, &mask, ebuf) == -1)
		errx(1, "pcap_filter_init: %s", ebuf);
	
	if ((pd = pcap_open_live(dev, 128, 0, 100, ebuf)) == NULL)
		errx(1, "pcap_filter_init: %s", ebuf);
	
	if (pcap_compile(pd, &fcode, filter, 0, mask) < 0) {
		pcap_perror(pd, "pcap_compile");
		return (NULL);
	}
	if (pcap_setfilter(pd, &fcode) < 0) {
		pcap_perror(pd, "pcap_setfilter");
		return (NULL);
	}

	return (pd);
}

int
pcap_get_address(pcap_t *pd, struct in_addr *address)
{
	struct ether_header *eth;
	struct ip *ip;
	struct tcphdr *tcp;
	u_char *pkt;
	struct pcap_pkthdr pkthdr;

	if ((pkt = (u_char *) pcap_next(pd, &pkthdr)) == NULL)
		return (-1);

	eth = (struct ether_header *) pkt;
	ip = (struct ip *)(eth + 1);
	tcp = (struct tcphdr *)(ip + 1);

	*address = ip->ip_src;
#ifdef DEBUG_PCAP
	{
#include <netdb.h>
		char ntop[NI_MAXHOST];
		ipv4toa(ntop, sizeof(ntop), address);
		fprintf(stderr, "%s (hl:%d) %c%c%c\n",
			ntop, ip->ip_hl,
			tcp->th_flags & TH_RST ? 'R' : ' ',
			tcp->th_flags & TH_SYN ? 'S' : ' ',
			tcp->th_flags & TH_ACK ? 'A' : ' ');
	}
#endif
	if (pkthdr.caplen > sizeof(*eth) + sizeof(*ip) + sizeof(*tcp))
		return (1); /* Try normally */

	/* Connection refused */
	if (tcp->th_flags & TH_RST)
		return (0);

	return (1);
}

void
synprobe_init(char *name)
{
	int hincl = 1, s;                  /* 1 = on, 0 = off */
	int sndb = 256 * 128;
	int i;

	if (inet_pton(AF_INET, name, &synsrc) == -1)
		err(1, "inet_pton");

	for (i = 0; i < MAXSOCKS; i++) {
		if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
			err(1, "socket");

		if (setsockopt(s, IPPROTO_IP, IP_HDRINCL,
			       &hincl, sizeof(hincl)) == -1)
			err(1, "setsockopt: IP_HDRINCL");

		if (setsockopt(s, SOL_SOCKET, SO_SNDBUF,
			       &sndb, sizeof(sndb)) == -1)
			err(1, "setsockopt: SO_SNDBUF");

		synsock[i] = s;
	}
	current = 0;
}

int
in_cksum(u_short *addr, int len)
{
	int sum, nleft;
	u_short ans, *w;
	
	sum = ans = 0;
	nleft = len;
	w = addr;
	
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}
	if (nleft == 1) {
		*(u_char *)(&ans) = *(u_char *)w;
		sum += ans;
	}
	return (sum);
}

#define CKSUM_CARRY(x) \
    (x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))

int
synprobe_send(struct in_addr dst, u_int32_t *seqnr)
{
	struct ip *ip;
	struct tcphdr *tcp;
	struct sockaddr_in sa;
	u_char buf[sizeof(*ip) + sizeof(*tcp)];
	struct phdr *pseudo;
	int i;

	pseudo = (struct phdr *)(buf + sizeof(struct ip) - sizeof(*pseudo)); 
	memset(buf, 0, sizeof(buf));

	if (*seqnr == 0)
		*seqnr = arc4random();

	pseudo->saddr = synsrc.s_addr;
	pseudo->daddr = dst.s_addr;
	pseudo->protocol = IPPROTO_TCP;
	pseudo->length = htons(sizeof(*tcp));

	tcp = (struct tcphdr *)(buf + sizeof(*ip));
	tcp->th_sport = ntohs(*seqnr);
	tcp->th_dport = ntohs(port);
	tcp->th_off = 5;
	tcp->th_flags = TH_SYN;
	tcp->th_win = htons(16384);
	tcp->th_seq = *seqnr;

	i = in_cksum((u_short *)pseudo, sizeof(*pseudo) + sizeof(*tcp));
	tcp->th_sum = CKSUM_CARRY(i);

	memset(buf, 0, sizeof(*ip));
	ip = (struct ip *)buf;
	ip->ip_v = 4;
	ip->ip_hl = 5;
#ifdef BSD_RAWSOCK_ORDER
	ip->ip_len = sizeof(*ip) + sizeof(*tcp);
#else
	ip->ip_len = htons(sizeof(*ip) + sizeof(*tcp));
#endif
	ip->ip_id = 0;
	ip->ip_ttl = 255;
	ip->ip_p = IPPROTO_TCP;
	ip->ip_src.s_addr = synsrc.s_addr;
	ip->ip_dst.s_addr = dst.s_addr;

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(22);
	sa.sin_addr.s_addr = dst.s_addr;

	current = (current + 1) % MAXSOCKS;
	if (sendto(synsock[current], buf, sizeof(buf), 0,
		   (struct sockaddr *)&sa, sizeof(sa)) == -1) {
#ifdef EHOSTDOWN
		if (errno == EHOSTDOWN)
			return (0);
#endif
		if (errno != ENOBUFS)
			warn("sendto");
		return (-1);
	}

	return (0);
}

