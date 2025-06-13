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

#ifndef _SCANSSH_H_
#define _SCANSSH_H_

#define SSHMAPVERSION	"SSH-1.0-SSH_Version_Mapper\n"
#define MAXITER		10
#define LONGWAIT	30
#define SHORTWAIT	2
#define CONNECTWAIT	20
#define SYNWAIT		1
#define SYNRETRIES	7
#define MAXBUF		2048
#define MAXSYNQUEUESZ	4096
#define MAXBURST	256
#define SEEDLEN		4
#define EXPANDEDARGS	64000	/* number of expanded addresses */
#define MAXSLOTS	10	/* number of slots addrs are alloced from */

#define SCAN_PORT	22	/* ssh per default */

#define FLAGS_USERANDOM		0x01
#define FLAGS_SUBTRACTEXCLUDE	0x02

struct argument;

struct address_slot {
	struct argument *slot_base;
	u_int32_t slot_size;
	u_int32_t slot_ref;
};

struct argument {
	TAILQ_ENTRY (argument) a_next;

	struct timeval a_tv;
	sa_family_t a_type;
	int a_retry;		/* what a waste of memory */
	u_int32_t a_seqnr;
	union {
		struct in_addr ipv4;
	} ip;

#define a_ipv4 ip.ipv4

	struct address_slot *a_slot;
};

ssize_t atomicio(ssize_t (*)(), int, void *, size_t);
int ipv4toa(char *, size_t, void *);
void waitforcommands(int, int);

#endif /* _SCANSSH_H_ */
