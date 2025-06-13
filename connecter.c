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
#include <sys/time.h>
#include <netinet/in.h>

#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

#include "config.h"
#include "scanssh.h"

extern int ssh_sendident;
extern char *ssh_ipalias;
extern int port;
int alarmed;

void
sigalrm_handler(int sig)
{
        int save_errno = errno;
	alarmed = 1;
        errno = save_errno;
}

int
scan_ssh(int sock, char *buf, size_t size)
{
	int j;
	char firstline[255];
	
	/* Read other side\'s version identification. */
        for (j = 0; j < MAXITER; j++) {
		int i;
                for (i = 0; i < size - 1; i++) {
                        int len = -1;
			if (!j && !i)
				alarm (LONGWAIT);
			else
				alarm (SHORTWAIT);
			while ((len = read(sock, &buf[i], 1)) == -1) {
				if (len == -1 && errno == EINTR)
					break;
			}
			alarm(0);
                        if (len < 0 && !j) {
				strlcpy(buf, "<timeout>", size);
				return (-1);
			} else if (len != 1 && !j) {
                                strlcpy(buf, "<closed>", size);
				return (-1);
			} else if (len != 1) {
				j = MAXITER;
				break;
			}
			
                        if (buf[i] == '\r') {
                                buf[i] = 0;
                                continue;
                        }
                        if (buf[i] == '\n') {
                                buf[i] = 0;
                                break;
                        }
                }
                buf[size - 1] = 0;
                if (strncmp(buf, "SSH-", 4) == 0)
                        break;
		if (j == 0)
			strlcpy(firstline, buf, sizeof(firstline));
        }
	if (j >= MAXITER)
		strlcpy(buf, firstline, size);
	else if (ssh_sendident)
		atomicio(write, sock, SSHMAPVERSION, sizeof(SSHMAPVERSION));

	return (0);
}

#define HTTP_SCAN	"HEAD /index.html HTTP/1.0\n\n"

int
scan_http(int sock, char *buf, size_t size)
{
	int j;
	char firstline[255];

	atomicio(write, sock, HTTP_SCAN, strlen(HTTP_SCAN));
	
	/* Read other side\'s version identification. */
        for (j = 0; j < MAXITER; j++) {
		int i;
                for (i = 0; i < size - 1; i++) {
                        int len = -1;
			if (!j && !i)
				alarm (LONGWAIT);
			else
				alarm (SHORTWAIT);
			while ((len = read(sock, &buf[i], 1)) == -1) {
				if (len == -1 && errno == EINTR)
					break;
			}
			alarm(0);
                        if (len < 0 && !j) {
				strlcpy(buf, "<timeout>", size);
				return (-1);
			} else if (len != 1 && !j) {
                                strlcpy(buf, "<closed>", size);
				return (-1);
			} else if (len != 1) {
				j = MAXITER;
				break;
			}
			
                        if (buf[i] == '\r') {
                                buf[i] = 0;
                                continue;
                        }
                        if (buf[i] == '\n') {
                                buf[i] = 0;
                                break;
                        }
                }
                buf[size - 1] = 0;
                if (strncmp(buf, "Server:", 7) == 0)
                        break;
		if (j == 0)
			strlcpy(firstline, buf, sizeof(firstline));
        }

	if (j >= MAXITER)
		strlcpy(buf, firstline, size);
}

int
scanhost(struct argument *arg, char *buf, size_t size)
{
	int res, sock;
	struct addrinfo hints, *ai;
	char ntop[NI_MAXHOST], sport[NI_MAXSERV];
	
	switch (arg->a_type) {
	case AF_INET:
		ipv4toa(ntop, sizeof(ntop), &arg->a_ipv4);
		break;
	default:
		strlcpy(buf, "<unsuppfamily>", size);
		return (-1);
	}

	sock = socket(arg->a_type, SOCK_STREAM, 0);
	if (sock == -1) {
		strlcpy(buf, "<socketcreate>", size);
		return (-1);
	}
	if (ssh_ipalias != NULL) {
	    memset(&hints, 0, sizeof(hints));
	    hints.ai_family = PF_UNSPEC;
	    hints.ai_socktype = SOCK_STREAM;
	    hints.ai_flags = AI_PASSIVE;
	    res = getaddrinfo(ssh_ipalias, "0", &hints, &ai);
	    if (res) {
		warn("%s: getaddrinfo() failed: %d", ssh_ipalias, res);
		close(sock);
		return (-1);
	    }
	    if (bind(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
		perror(ssh_ipalias);
		close(sock);
		freeaddrinfo(ai);
		return (-1);
            }
	    freeaddrinfo(ai);
	}

	memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
	snprintf(sport, sizeof(sport), "%d", port);
        if (getaddrinfo(ntop, sport, &hints, &ai) != 0) {
		strlcpy(buf, "<getaddrinfo>", size);
		return (-1);
	}

	alarm(CONNECTWAIT);
	res = connect(sock, ai->ai_addr, ai->ai_addrlen);
	alarm(0);
	freeaddrinfo(ai);
	if (res == -1) {
		close(sock);
		switch (errno) {
		case ETIMEDOUT:
		case EINTR:
#ifdef __linux__
		case EHOSTUNREACH:
#endif
			strlcpy(buf, "<timeout>", size);
			return (-1);
		case ECONNREFUSED:
			strlcpy(buf, "<refused>", size);
			return (-1);
		case ENETUNREACH:
			strlcpy(buf, "<unreachable>", size);
			return (-1);
		default:
			snprintf(buf, size, "<%s>", strerror(errno));
			return (-1);
		}
	}

	switch(port) {
	case 22:
		scan_ssh(sock, buf, size);
		break;
	case 80:
		scan_http(sock, buf, size);
		break;
	}

	close(sock);
	return (0);
}

void
waitforcommands(int readfd, int writefd)
{
	struct argument arg;
	char buf[200];
	char result[200];
	struct sigaction sa;

        /* block signals, get terminal modes and turn off echo */
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = sigalrm_handler;
        (void) sigaction(SIGALRM, &sa, NULL);

	while(atomicio(read, readfd, &arg, sizeof(arg))) {
		/* exit command */
		if (arg.a_ipv4.s_addr == 0)
			return;

		scanhost(&arg, result, sizeof(result));
		ipv4toa(buf, sizeof(buf), &arg.a_ipv4);
		strlcat(buf, " ", sizeof(buf));
		strlcat(buf, result, sizeof(buf));

		atomicio(write, writefd, buf, strlen(buf) + 1);
	}
}
