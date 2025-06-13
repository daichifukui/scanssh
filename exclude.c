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
#include <sys/queue.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <netdb.h>
#include <string.h>
#include <err.h>

#include "config.h"
#include "exclude.h"

char *excludefile = "exclude.list";
struct exclude_list excludequeue;
struct exclude_list rndexclqueue;

#define RNDSBOXSIZE	128
#define RNDSBOXSHIFT	7
#define RNDROUNDS	32

u_int32_t rndsbox[RNDSBOXSIZE];

char *unusednets[] = {
	"127.0.0.0/8",		/* local */
	"10.0.0.0/8",		/* rfc-1918 */
	"172.16.0.0/12",	/* rfc-1918 */
	"192.168.0.0/16",	/* rfc-1918 */
	"224.0.0.0/4",		/* rfc-1112 */
	"240.0.0.0/4",
	"0.0.0.0/8",
	"255.0.0.0/8",
	NULL
};

void
rndsboxinit(u_int32_t seed)
{
	int i;

	/* We need repeatable random numbers here */
	srandom(seed);
	for (i = 0; i < RNDSBOXSIZE; i++) {
		rndsbox[i] = random();
	}
}

/*
 * We receive the prefix in host-order.
 * Use a modifed TEA to create a permutation of 2^(32-bits)
 * elements.
 */

u_int32_t
rndgetaddr(int bits, u_int32_t count)
{
	u_int32_t sum = 0, mask, sboxmask;
	int i, left, right, kshift;

	if (bits == 32)
		return (0);

	left = (32 - bits) / 2;
	right = (32 - bits) - left;

	mask  = 0xffffffff >> bits;
	if (RNDSBOXSIZE < (1 << left)) {
		sboxmask = RNDSBOXSIZE - 1;
		kshift = RNDSBOXSHIFT;
	} else {
		sboxmask = (1 << left) - 1;
		kshift = left;
	}

	for (i = 0; i < RNDROUNDS; i++) {
		sum += 0x9e3779b9;
		count ^= rndsbox[(count^sum) & sboxmask]  << kshift;
		count += sum;
		count &= mask;
		count = ((count << left) | (count >> right)) & mask;
	}

	return (count);
}

int
parseaddress(char *line, struct in_addr *address, int *bits)
{
	char *part2 = line;
	char *part1 = strsep(&part2, "/");

	if (inet_pton(AF_INET, part1, address) != 1)
		return (-1);
	if (part2 && *part2) {
		*bits = strtol(part2, &part1, 10);
		if (*part2 == '\0' || (*part1 && !isspace(*part1)))
			return (-1);
		if (*bits < 0 || *bits > 32)
			return (-1);
	} else
		*bits = 32;

	return (0);
}

void
excludeinsert(struct in_addr *address, int bits, struct exclude_list *queue)
{
	struct exclude *entry;
	struct in_addr mask;

	if ((entry = malloc(sizeof(*entry))) == NULL)
		err(1, "malloc");

	mask.s_addr = 0xFFFFFFFF << (32 - bits);
	entry->e_type = AF_INET;
	entry->e_ipv4s.s_addr = ntohl(address->s_addr) & mask.s_addr;
	entry->e_ipv4e.s_addr = ntohl(address->s_addr) | (~mask.s_addr);
	TAILQ_INSERT_HEAD(queue, entry, e_next);
}

int
setupexcludes(void)
{
	FILE *stream;
	char line[BUFSIZ];
	size_t len;
	struct in_addr address;
	int bits, i;

	TAILQ_INIT(&excludequeue);
	TAILQ_INIT(&rndexclqueue);

	for (i = 0; unusednets[i]; i++) {
		char *line;
		if ((line = strdup(unusednets[i])) == NULL)
			err(1, "malloc");
		if (parseaddress(line, &address, &bits) == -1)
			errx(1, "parseaddress for unused");
		excludeinsert(&address, bits, &rndexclqueue);
	}

	if ((stream = fopen(excludefile, "r")) == NULL)
		return (-1);

	while (fgets(line, sizeof(line), stream) != NULL) {
		len = strlen(line);
		if (line[len - 1] != '\n') {
			fprintf(stderr, "Ignoring line without newline\n");
			continue;
		}
		line[len - 1] = '\0';
		if (parseaddress(line, &address, &bits) == -1) {
			fprintf(stderr, "Can't parse <%s> in exclude file.\n",
				line);
			exit (1);
		}
		excludeinsert(&address, bits, &excludequeue);
	}

	return (0);
}

struct in_addr
exclude(struct in_addr address, struct exclude_list *queue)
{
	struct exclude *entry;

	/* Check for overflow */
	if (address.s_addr == INADDR_ANY)
		return (address);

	TAILQ_FOREACH(entry, queue, e_next) {
		if (address.s_addr >= entry->e_ipv4s.s_addr &&
		    address.s_addr <= entry->e_ipv4e.s_addr) {
			/* Increment and check overflow */
			address.s_addr = entry->e_ipv4e.s_addr + 1;
			return (exclude(address, queue));
		}
	}
	return (address);
}
