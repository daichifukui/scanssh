/*
 * ScanSSH - simple SSH version scanner
 *
 * Copyright 2000-2001 Niels Provos <provos@citi.umich.edu>
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
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <netdb.h>
#include <pcap.h>
#include <unistd.h>
#include <md5.h>

#define VERSION	"V1.6b"

#include "config.h"
#ifdef HAVE_FDMASK_IN_SELECT
#include <sys/select.h>
#endif

#include "scanssh.h"
#include "exclude.h"
#include "pcapu.h"
#include "xmalloc.h"

#ifndef howmany
#define howmany(x,y)	(((x) + ((y) - 1)) / (y))
#endif

struct address_node {
	TAILQ_ENTRY (address_node) an_next;

	sa_family_t an_type;
	union {
		struct in_addr ipv4;
	} an_ipstart;
#define an_ipv4start an_ipstart.ipv4

	union {
		struct in_addr ipv4;
	} an_ipend;
#define an_ipv4end an_ipend.ipv4

	int an_bits;
};

struct generate {
	TAILQ_ENTRY (generate) gen_next;

	TAILQ_HEAD (an_list, address_node) gen_anqueue;

	int gen_flags;

	u_int32_t gen_seed;		/* Seed for PRNG */

	u_int32_t gen_bits;
	u_int32_t gen_start;
	u_int32_t gen_iterate;
	u_int32_t gen_end;
	u_int32_t gen_current;
	u_int32_t gen_n;		/* successful generations */
	u_int32_t gen_max;
};

int populate(struct argument **, int *);
int next_address(struct generate *, struct in_addr *);

/* Globals */
int usepcap;
int ssh_sendident;
char *ssh_ipalias = NULL;
int port = SCAN_PORT;
pcap_t *pd;
int rndexclude = 1;

struct address_slot slots[MAXSLOTS];

#define MAX_PROCESSES	30

int commands[MAX_PROCESSES];
int results[MAX_PROCESSES];

TAILQ_HEAD (gen_list, generate) genqueue;
TAILQ_HEAD (queue_list, argument) readyqueue;
TAILQ_HEAD (syn_list, argument) synqueue;

#define synlist_hasspace()	(synqueuesz < MAXSYNQUEUESZ)
#define synlist_empty()		(synqueuesz == 0)

int synqueuesz;

struct address_slot *
slot_get(void)
{
	int i;
	struct address_slot *slot;

	for (i = 0; i < MAXSLOTS; i++)
		if (slots[i].slot_base == NULL)
			break;

	if (i >= MAXSLOTS)
		return (NULL);
	
	slot = &slots[i];

	if (slot->slot_base == NULL) {
		slot->slot_size = EXPANDEDARGS;
		slot->slot_base = xmalloc(EXPANDEDARGS * sizeof(struct argument));
		memset(slot->slot_base, 0,
		       slot->slot_size * sizeof(struct argument));
	}

	return (slot);
}

void
slot_free(struct address_slot *slot)
{
	slot->slot_ref--;
	if (slot->slot_ref)
		return;

	slot->slot_size = 0;
	free(slot->slot_base);
	slot->slot_base = 0;
}

void
synlist_init(void)
{
	TAILQ_INIT(&synqueue);
	synqueuesz = 0;
}

int
synlist_insert(struct argument *arg)
{
	struct timeval tmp;
	struct argument *listarg;

	if (!synlist_hasspace())
		return (-1);

	timerclear(&tmp);
	tmp.tv_sec += (arg->a_retry/2 + 1) * SYNWAIT;
	tmp.tv_usec = arc4random();

	gettimeofday(&arg->a_tv, NULL);
	timeradd(&tmp, &arg->a_tv, &arg->a_tv);

	/* Insert in time order */
	TAILQ_FOREACH_REVERSE(listarg, &synqueue, a_next, syn_list) {
		if (timercmp(&listarg->a_tv, &arg->a_tv, <=))
			break;
	}
	if (listarg)
		TAILQ_INSERT_AFTER(&synqueue, listarg, arg, a_next);
	else
		TAILQ_INSERT_TAIL(&synqueue, arg, a_next);

	synqueuesz++;

	return (0);
}

void
synlist_remove(struct argument *arg)
{
	TAILQ_REMOVE(&synqueue, arg, a_next);
	synqueuesz--;
}

struct argument *
synlist_dequeue(void)
{
	struct argument *arg;

	arg = TAILQ_FIRST(&synqueue);
	if (arg == NULL)
		return (NULL);

	synlist_remove(arg);
	return (arg);
}

int
synlist_expired(void)
{
	struct argument *arg;
	struct timeval tv;

	arg = TAILQ_FIRST(&synqueue);
	if (arg == NULL)
		return (0);

	gettimeofday(&tv, NULL);

	return (timercmp(&tv, &arg->a_tv, >));
}

int
synlist_probe(struct argument *arg)
{
	int res = 0; 

        if (arg->a_type != AF_INET ||
	    (res = synprobe_send(arg->a_ipv4, &arg->a_seqnr)) == -1 ||
	    synlist_insert(arg) == -1)
		TAILQ_INSERT_TAIL(&readyqueue, arg, a_next);
	    
	return (res);
}

void
sigchld_handler(int sig)
{
        int save_errno = errno;
	int status;
	wait(&status);
        signal(SIGCHLD, sigchld_handler);
        errno = save_errno;
}

void
printres(struct argument *exp, char *result)
{
	char ntop[NI_MAXHOST];
	ipv4toa(ntop, sizeof(ntop), &exp->a_ipv4);
	fprintf(stdout, "%s %s\n", ntop, result);
	fflush(stdout);
}

void
scanips(void)
{
	u_int32_t entries = 0;
	fd_set *readset, *writeset;
	int maxfd = 0, fdsetsz, counts = 0;
	struct timeval tv;
	int res, i, lastinsert, newinsert;
	struct argument *args;
	char buf[MAXBUF], *p;

	for (i = 0; i < MAX_PROCESSES; i++) {
		if (commands[i] > maxfd)
			maxfd = commands[i];
		if (results[i] > maxfd)
			maxfd = results[i];
	}
	fdsetsz = howmany(maxfd + 1, NFDBITS) * sizeof(fd_mask);
	if ((readset = malloc(fdsetsz)) == NULL)
		err(1, "malloc for readset");
	if ((writeset = malloc(fdsetsz)) == NULL)
		err(1, "malloc for readset");

	TAILQ_INIT(&readyqueue);
	synlist_init();

	/* Keep track where which process received the last insert */
	lastinsert = 0;

	while (TAILQ_FIRST(&genqueue) || entries ||
	       counts || !synlist_empty()) {
		/* Create new entries, if we need them */
		if (!entries && TAILQ_FIRST(&genqueue)) {
			 if (populate(&args, &entries) == -1)
				 entries = 0;
		}

		memset(readset, 0, fdsetsz);
		memset(writeset, 0, fdsetsz);
		
		for (i = 0; i < MAX_PROCESSES; i++) {
			if (commands[i] >= 0)
				FD_SET(commands[i], writeset);
			if (results[i] >= 0)
				FD_SET(results[i], readset);
		}

		/* Find new timeout */
		timerclear(&tv);
		tv.tv_usec = 250000;
		if (!synlist_empty()) {
			struct timeval ctv, tmp;
			struct argument *sarg = TAILQ_FIRST(&synqueue);

			gettimeofday(&ctv, NULL);
			tmp = sarg->a_tv;
			/* If it overflows, it will become bigger */
			timersub(&tmp, &ctv, &tmp);
			if (timercmp(&tmp, &tv, <))
				tv = tmp;
			timerclear(&tmp);
			if (timercmp(&tmp, &tv, >))
				tv = tmp;
		}

		/* Wait in select until there is a connection. */
		if ((res = select(maxfd + 1, readset, writeset, NULL,
				  &tv)) == -1) {
			if (errno != EINTR)
				err(1, "select");
			continue;
		}

		/* Read back commands */
		for (i = 0; i < MAX_PROCESSES; i++) {
			int count;
			if (results[i] < 0 || !FD_ISSET(results[i], readset))
				continue;

			res = -1;
			count = 0;
			while (res != 0 && count < sizeof(buf)) {
				res = read(results[i], buf + count,
					   sizeof(buf) - count);
				if (res == -1 &&
				    (errno != EINTR && errno != EAGAIN))
					break;
				if (res > 0) {
					count += res;
					if (buf[count - 1] == '\0')
						break;
				}
			}
			if (res == 0) {
				/* Child terminated */
				close (results[i]);
				results[i] = -1;
				if (commands[i] != -1) {
					close(commands[i]);
					commands[i] = -1;
				}
			} else if(res == -1)
				err(1, "read");
			p = buf;
			while (count > 0) {
				fprintf(stdout, "%s\n", p);
				fflush(stdout);
				count -= strlen(p) + 1;
				p += strlen(p) + 1;
				counts--;
			}
		}

		if (usepcap) {
			int res, nsent, probefailed;
			struct in_addr address;
			struct argument *addrchk;
			struct timeval now;

			/* See if we get results from our syn probe */
			while (!synlist_empty() &&
			       (res = pcap_get_address(pd, &address)) != -1) {
				TAILQ_FOREACH(addrchk, &synqueue, a_next) {
					if (address.s_addr == addrchk->a_ipv4.s_addr)
						break;
				}
				if (addrchk) {
					synlist_remove(addrchk);
					if (res == 0)
						printres(addrchk, "<refused>");
					else
						TAILQ_INSERT_TAIL(&readyqueue,
								  addrchk,
								  a_next);
				}
			}

			gettimeofday(&now, NULL);
			nsent = 0;
			probefailed = 0;
			/* Remove all expired entries */
			while (synlist_expired() && nsent < MAXBURST) {
				struct argument *exp;
				
				exp = synlist_dequeue();
				if (exp->a_retry < SYNRETRIES) {
					exp->a_retry++;
					if (synlist_probe(exp) == -1) {
						probefailed = 1;
						break;
					}
					nsent++;
				} else {
					printres(exp, "<timeout>");
					slot_free(exp->a_slot);
				}
			}

			/* Put new entries in the synlist */
			while (!probefailed && entries && nsent < MAXBURST &&
			       synlist_hasspace()) {
				entries--;
				args[entries].a_retry = 0;
				if (synlist_probe(&args[entries])== -1) {
					probefailed = 1;
					break;
				}
				nsent++;
			}
#ifdef DEBUG
			fprintf(stderr, "Sent: %d %s (%d-%d:%d)\n", nsent,
				probefailed ? "failed" : "",
				synqueuesz, entries, counts);
#endif /* DEBUG */
		} else {
			/* No advanced syn probing, place data direcly
			 * on ready queue.
			 */
			for (i = 0; i < MAX_PROCESSES && entries; i++) {
				entries--;
				TAILQ_INSERT_TAIL(&readyqueue, &args[entries],
						  a_next);
			}
		}

		/* Round robin the inserts */
		i = (lastinsert + 1) % MAX_PROCESSES;
		newinsert = lastinsert;
		while (i != lastinsert) {
			i = (i + 1) % MAX_PROCESSES;

			if (commands[i] < 0 ||
			    !FD_ISSET(commands[i], writeset))
				continue;
			if (TAILQ_FIRST(&readyqueue)) {
				struct argument *arg;
				arg = TAILQ_FIRST(&readyqueue);
				TAILQ_REMOVE(&readyqueue, arg, a_next);
				atomicio(write, commands[i], arg,
					 sizeof(struct argument));
				slot_free(arg->a_slot);
				counts++;
				newinsert = i;
			} else if (synlist_empty()) {
				struct argument arg;
				memset(&arg, 0, sizeof(arg));
				atomicio(write, commands[i], &arg,
					 sizeof(arg));
				close (commands[i]);
				commands[i] = -1;
			}
		}
		lastinsert = newinsert;
	}
}

void
setupchildren(void)
{
	struct rlimit rlimit;
	int cpipefds[2], rpipefds[2];
	int i, j;
	pid_t pid;

        /* Increase number of open files */
        if (getrlimit(RLIMIT_NOFILE, &rlimit) == -1)
                err(1, "router_socket: getrlimit");
        rlimit.rlim_cur = rlimit.rlim_max;
        if (setrlimit(RLIMIT_NOFILE, &rlimit) == -1)
                err(1, "router_socket: setrlimit");

	/* Arrange SIGCHLD to be caught. */
	signal(SIGCHLD, sigchld_handler);

	for (i = 0; i < MAX_PROCESSES; i++) {
		if (pipe(cpipefds) == -1)
			err(1, "pipe for commands fds failed");
		if (pipe(rpipefds) == -1)
			err(1, "pipe for results fds failed");
		fcntl(cpipefds[1], F_SETFL, O_NONBLOCK);
		fcntl(rpipefds[0], F_SETFL, O_NONBLOCK);
		if ((pid = fork()) == 0) {
			/* Child */
			close(cpipefds[1]);
			close(rpipefds[0]);
			/* Close pipes to other children */
			for (j = 0; j < i; j++) {
				close(commands[j]);
				close(results[j]);
			}
			waitforcommands(cpipefds[0], rpipefds[1]);
			exit (0);
		} else if(pid == -1)
			err(1, "fork failed");
		
		/* Parent */
		close(cpipefds[0]);
		close(rpipefds[1]);

		commands[i] = cpipefds[1];
		results[i] = rpipefds[0];
	}

}

void
usage(char *name)
{
	fprintf(stderr, 
		"%s: [-VIERh] [-n port] [-e excludefile] [-b alias] [-p ifaddr] <IP address|network>...\n\n"
		"\t-V          print version number of scanssh,\n"
		"\t-I          do not send identification string,\n"
		"\t-E          exit if exclude file is missing,\n"
		"\t-R          do not honor exclude file for random addresses,\n"
		"\t-n <port>   the port number to scan.  Either 22 or 80.\n"
		"\t-e <file>   exclude the IP addresses and networks in <file>,\n"
		"\t-b <alias>  specifies the IP alias to connect from,\n"
		"\t-p <ifaddr> specifies the local interface address,\n"
		"\t-h          this message.\n\n",
		name);
}

#ifndef HAVE_SOCKADDR_STORAGE
struct sockaddr_storage {
	u_char iamasuckyoperatingsystem[2048];
};
#endif

int
ipv4toa(char *buf, size_t size, void *addr)
{
	struct sockaddr_storage from;
	struct sockaddr_in *sfrom = (struct sockaddr_in *)&from;
	socklen_t fromlen = sizeof(from);

	memset(&from, 0, fromlen);
#ifdef HAVE_SIN_LEN
	sfrom->sin_len = sizeof (struct sockaddr_in);
#endif
	sfrom->sin_family = AF_INET;
	memcpy(&sfrom->sin_addr.s_addr, addr, 4);

	if (getnameinfo ((struct sockaddr *)sfrom,
#ifdef HAVE_SIN_LEN
			 sfrom->sin_len,
#else
			 sizeof (struct sockaddr_in),
#endif
			 buf, size, NULL, 0, NI_NUMERICHOST) != 0) {
		fprintf(stderr, "ipsec_ipv4toa: getnameinfo() failed");
		return -1;
	}
	return 0;
}

void
generate_free(struct generate *gen)
{
	struct address_node *node;

	/* Remove generator and attached addr nodes */
	for (node = TAILQ_FIRST(&gen->gen_anqueue);
	     node;
	     node = TAILQ_FIRST(&gen->gen_anqueue)) {
		TAILQ_REMOVE(&gen->gen_anqueue,
			     node, an_next);
		xfree(node);
	}

	TAILQ_REMOVE(&genqueue, gen, gen_next);
	xfree(gen);
}

/*
 * Given an IP prefix and mask create all addresses contained
 * exlcuding any addresses specified in the exlcude queues.
 */

int
populate(struct argument **pargs, int *nargs)
{
	struct generate *gen;
	struct in_addr addr;
	struct address_slot *slot = NULL;
	struct argument *args;
	int count;

	u_int32_t i = 0;

	if (!TAILQ_FIRST(&genqueue))
		return (-1);

	if ((slot = slot_get()) == NULL)
		return (-1);

	args = slot->slot_base;
	count = slot->slot_size;

	while (TAILQ_FIRST(&genqueue) && count) {
		gen = TAILQ_FIRST(&genqueue);
		
		/* Initalize generator */
		if (!gen->gen_current) {
			if (gen->gen_flags & FLAGS_USERANDOM)
				rndsboxinit(gen->gen_seed);

			gen->gen_current = gen->gen_start;
		}

		while (count) {
			if (next_address(gen, &addr) == -1) {
				generate_free(gen);
				break;
			}

			args[i].a_type = AF_INET;
			args[i].a_ipv4.s_addr = htonl(addr.s_addr);
			args[i].a_slot = slot;

			slot->slot_ref++;

			count--;
			i++;
		}
	}

	*pargs = args;
	*nargs = i;

	return (0);
}

int
address_from_offset(struct address_node *an, u_int32_t offset,
		    struct in_addr *addr)
{
	for (; an; an = TAILQ_NEXT(an, an_next)) {
		if (an->an_ipv4start.s_addr + offset <= an->an_ipv4end.s_addr)
			break;
		offset -= an->an_ipv4end.s_addr - an->an_ipv4start.s_addr + 1;
	}

	if (an == NULL)
		return (-1);

	addr->s_addr = an->an_ipv4start.s_addr + offset;
	
	return (0);
}

/*
 * get the next address, keep state.
 */

int
next_address(struct generate *gen, struct in_addr *addr)
{
	struct in_addr ipv4addr, tmp;
	u_int32_t offset;
	int done = 0, random;

	/* Check if generator has been exhausted */
	if (gen->gen_n >= gen->gen_max)
		return (-1);

	random = gen->gen_flags & FLAGS_USERANDOM;

	do {
		/* Get offset into address range */
		if (random)
			offset = rndgetaddr(gen->gen_bits,
					    gen->gen_current);
		else
			offset = gen->gen_current;
		
		gen->gen_current += gen->gen_iterate;
		
		if (address_from_offset(TAILQ_FIRST(&gen->gen_anqueue),
					offset, &ipv4addr) == -1)
			continue;
		
		if (!random || rndexclude) {
			tmp = exclude(ipv4addr, &excludequeue);
			if (ipv4addr.s_addr != tmp.s_addr) {
				if (random) {
					if (gen->gen_flags & FLAGS_SUBTRACTEXCLUDE)
						gen->gen_max--;

					continue;
				}

				/* In linear mode, we can skip these */
				offset = gen->gen_current;
				offset += tmp.s_addr - ipv4addr.s_addr;
				if (offset < gen->gen_current) {
					gen->gen_current = gen->gen_end;
					break;
				}
				gen->gen_current = offset;
				
				if (gen->gen_iterate == 1)
					continue;

				/* Adjust for splits */
				offset /= gen->gen_iterate;
				offset *= gen->gen_iterate;

				offset += gen->gen_start;

				if (offset < gen->gen_current)
					offset += gen->gen_iterate;
				if (offset < gen->gen_current) {
					gen->gen_current = gen->gen_end;
					break;
				}

				gen->gen_current = offset;
				continue;
			}
		}
		
		if (random) {
			tmp = exclude(ipv4addr, &rndexclqueue);
			if (ipv4addr.s_addr != tmp.s_addr) {
				if (gen->gen_flags & FLAGS_SUBTRACTEXCLUDE)
					gen->gen_max--;
				continue;
			}
		}
		
		/* We have an address */
		done = 1;
	} while ((gen->gen_current < gen->gen_end) && 
		 (gen->gen_n < gen->gen_max) && !done);

	if (!done)
		return (-1);

	gen->gen_n += gen->gen_iterate;

	*addr = ipv4addr;

	return (0);
}

struct address_node *
address_node_get(char *line)
{
	struct address_node *an;
	struct in_addr ipv4mask;
	int bits;

	/* Allocate an address node */
	an = xmalloc(sizeof(struct address_node));
	memset(an, 0, sizeof(struct address_node));
	if (parseaddress(line, &an->an_ipv4start, &bits) == -1) {
		fprintf(stderr, "Can not parse %s\n", line);
		return (NULL);
	}

	an->an_bits = bits;
	an->an_type = AF_INET;

	/* Calculate start and end address for this node */
	if (bits > 0)
		ipv4mask.s_addr = 0xFFFFFFFF << (32 - bits);
	else
		ipv4mask.s_addr = 0;

	an->an_ipv4start.s_addr = ntohl(an->an_ipv4start.s_addr);
	an->an_ipv4start.s_addr &= ipv4mask.s_addr;
	an->an_ipv4end.s_addr = an->an_ipv4start.s_addr | (~ipv4mask.s_addr);

	return (an);
}

/*
 * Creates a generator from a command line
 * [split(x/n)/][random(x,s)/][(]<address/mask> .... [)]
 */

int
generate_split(struct generate *gen, char **pline)
{
	char *line, *end;

	line = *pline;

	if ((end = strstr(line, ")/")) == NULL ||
	    strchr(line, '/') < end) {
		fprintf(stderr, "Split not terminated correctly: %s\n", line);
		return (-1);
	}

	line = 	strsep(pline, "/");

	/* Generate a random scan entry */
	if (sscanf(line, "split(%d,%d)/",
		   &gen->gen_start, &gen->gen_iterate) != 2)
		return (-1);
		
	if (!gen->gen_start || gen->gen_start > gen->gen_iterate) {
		fprintf(stderr, "Invalid start/iterate pair: %d/%d\n",
			gen->gen_start, gen->gen_iterate);
		return (-1);
	}

	/* Internally, we start counting at 0 */
	gen->gen_start--;

	return (0);
}

/*
 * Creates a generator from a command line
 * [split(x/n)/][random(x,s)/][(]<address/mask> .... [)]
 */

int
generate_random(struct generate *gen, char **pline)
{
	int i;
	char seed[31], *line, *end;

	line = *pline;

	if ((end = strstr(line, ")/")) == NULL ||
	    strchr(line, '/') < end) {
		fprintf(stderr, "Random not terminated correctly: %s\n", line);
		return (-1);
	}

	line = strsep(pline, "/");

	/* Generate a random scan entry */
	seed[0] = '\0';
	if (sscanf(line, "random(%d,%30s)/", &gen->gen_max, seed) < 1)
		return (-1);
		
	/* Generate seed from string */
	if (strlen(seed)) {
		MD5_CTX ctx;
		u_char digest[16];
		u_int32_t *tmp = (u_int32_t *)digest;

		MD5Init(&ctx);
		MD5Update(&ctx, seed, strlen(seed));
		MD5Final(digest, &ctx);

		gen->gen_seed = 0;
		for (i = 0; i < 4; i ++)
			gen->gen_seed ^= *tmp++;
				
	} else
		gen->gen_seed = arc4random();

	gen->gen_flags |= FLAGS_USERANDOM;

	/* If the random numbers exhaust all possible addresses,
	 * we need to subtract those addresses from the count
	 * that can not be generated because they were excluded
	 */
	if (!gen->gen_max)
		gen->gen_flags |= FLAGS_SUBTRACTEXCLUDE;

	return (0);
}

int
generate(char *line)
{
	struct generate *gen;
	struct address_node *an;
	u_int32_t count, tmp;
	char *p;
	int bits, i, done;

	gen = xmalloc(sizeof(struct generate));
	memset(gen, 0, sizeof(struct generate));
	TAILQ_INIT(&gen->gen_anqueue);

	/* Insert in generator queue, on failure generate_free removes it */
	TAILQ_INSERT_TAIL(&genqueue, gen, gen_next);

	done = 0;
	while (!done) {
		done = 1;
		if (strncmp(line, "random(", 7) == 0) {
			if (gen->gen_flags & FLAGS_USERANDOM) {
				fprintf(stderr,
					"Random already specified: %s\n",
					line);
				goto fail;
			}
			if (generate_random(gen, &line) == -1)
				goto fail;

			done = 0;
		} else if (strncmp(line, "split(", 6) == 0) {
			if (gen->gen_iterate) {
				fprintf(stderr,
					"Split already specified: %s\n",
					line);
				goto fail;
			}
			if (generate_split(gen, &line) == -1)
				goto fail;

			done = 0;
		}
	}

	/* If no special split is specified, always iterated by 1 */
	if (!gen->gen_iterate)
		gen->gen_iterate = 1;

	if (line[0] == '(') {
		char *end;
		
		line++;
		if ((end = strchr(line, ')')) == NULL) {
			fprintf(stderr, "Missing ')' in line: %s\n", line);
			goto fail;
		}
		*end = '\0';
		
	}

	while (line && (p = strsep(&line, " "))) {
		if ((an = address_node_get(p)) == NULL)
			goto fail;

		TAILQ_INSERT_TAIL(&gen->gen_anqueue, an, an_next);
	}

	/* Try to find out the effective bit range */
	count = 0;
	for (an = TAILQ_FIRST(&gen->gen_anqueue); an;
	     an = TAILQ_NEXT(an, an_next)) {
		bits = an->an_bits;
		if (bits == 0) {
			count = -1;
			break;
		}

		if (count + (1 << (32 - bits)) < count) {
			count = -1;
			break;
		}

		count += 1 << (32 - bits);
	}

	/* Try to convert count into a network mask */
	bits = 0;
	tmp = count;
	for (i = -1; tmp; tmp >>= 1, i++) {
		if (tmp & 1)
			bits++;
	}

	/* a count of 01100, results in bits = 29, but it should be 28 */
	gen->gen_bits = 32 - i;
	if (bits > 1)
		gen->gen_bits--;
	bits = gen->gen_bits;

	if (gen->gen_flags & FLAGS_USERANDOM) {
		if (bits == 0)
			gen->gen_end = -1;
		else 
			gen->gen_end = 1 << (32 - bits);
	} else
		gen->gen_end = count;

	if (gen->gen_max == 0)
		gen->gen_max = count;

	return (0);
 fail:
	if (gen)
		generate_free(gen);

	return (-1);
}

int
main(int argc, char **argv)
{
	char *name, *src = NULL, *p;
	int ch;
	struct argument *args = NULL;
	int failonexclude = 0;

	ssh_sendident = 1;

	name = argv[0];
	while ((ch = getopt(argc, argv, "VIhb:p:e:n:ER")) != -1)
		switch(ch) {
		case 'V':
			fprintf(stderr, "ScanSSH %s\n", VERSION);
			exit(0);
		case 'I':
			ssh_sendident = 0;
			break;
		case 'b':
			ssh_ipalias = optarg;
			break;
		case 'p':
			src = optarg;
			break;
		case 'n':
			port = strtoul(optarg, &p, 0);
			if (*p != '\0') {
				usage(name);
				exit(1);
			}
			break;
		case 'e':
			excludefile = optarg;
			/* FALLTHROUGH */
		case 'E':
			failonexclude = 1;
			break;
		case 'R':
			rndexclude=0;
			break;
		case 'h':
		default:
			usage(name);
			exit(1);
		}

	argc -= optind;
	argv += optind;

	/* With probe optimization */
	if (src) {
		char filter[128];

		snprintf(filter, sizeof(filter), 
		    "(tcp[13] & 18 = 18 or tcp[13] & 4 = 4) and src port %d",
		    port);

		synprobe_init(src);
		pd = pcap_filter_init(filter);
		usepcap = 1;
	} else
		usepcap = 0;


	/* revoke privs */
#ifdef HAVE_SETEUID
        seteuid(getuid());
#endif /* HAVE_SETEUID */
        setuid(getuid());

	setupchildren();

	if (setupexcludes() == -1 && failonexclude) {
		warn("fopen: %s", excludefile);
		exit(1);
	}

	memset(slots, 0, sizeof(slots));

	TAILQ_INIT(&genqueue);

	while (argc) {
		if (generate(argv[0]) == -1)
			warnx("generate failed on %s", argv[0]);

		argv++;
		argc--;
	}

	if (!TAILQ_FIRST(&genqueue))
		errx(1, "nothing to scan");

	scanips();

	return (1);
}
