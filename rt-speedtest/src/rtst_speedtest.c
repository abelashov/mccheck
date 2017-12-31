/*
 * rtst_speedtest.c -- Functions for speed test
 *
 * Andrew Belashov, <Andrey.Belashov@center.rt.ru>
 *
 * Copyright (c) 2013, Andrew Belashov.
 * Copyright (c) 2013, Rostelecom JSC.
 *
 * This software is an open source.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef WINDOWS

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#else

#include <sys/types.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>

#endif

#include "rtst.h"

static const char * sockaddr_ntop(struct sockaddr * sa)
{
	void *		addr;
	static char	addrbuf[INET6_ADDRSTRLEN];

	switch (sa->sa_family) {
	case AF_INET:
		addr = &((struct sockaddr_in *)sa)->sin_addr;
		break;
	case AF_INET6:
		addr = &((struct sockaddr_in6 *)sa)->sin6_addr;
		break;
	default:
		/* return "<unknown family address>"; */
		return NULL;
	}
	inet_ntop(sa->sa_family, addr, addrbuf, sizeof(addrbuf));
	return addrbuf;
}

void rtst_gettime(struct timeval * t)
{
	if (gettimeofday(t, NULL) != 0) {
		rtst_error("Can not get current time\n");
	}
}

long rtst_msdiff(struct timeval * t1, struct timeval * t2)
{
	struct timeval		timediff;

	timersub(t2, t1, &timediff);
	/* Convert to milliseconds */
	return 1000 * timediff.tv_sec + timediff.tv_usec / 1000;
}

static void do_speedtest(
 struct url * config,
 struct rtst_stat * st,
 int sock, int pingtest)
{
	int				reqlen;
	ssize_t				len, clen;
	struct timeval			t1, t2, t3;
	int				needt2 = 1;
	unsigned long			readbytes = 0;
	long				duration;
	static char *			reqbuf = NULL;
	static char *			respbuf = NULL;

	if (respbuf == NULL) {
		respbuf = malloc(RTST_BUFFLEN);
		reqbuf = respbuf;
		if (reqbuf == NULL || respbuf == NULL) {
			rtst_error(
			 "No free memory for request and response buffers\n");
		}
	}

	rtst_gettime(&t1);

	reqlen = sprintf(reqbuf,
"GET %s HTTP/1.1\r\n"
"Host: %s:%s\r\n"
"User-Agent: rt-speedtest\r\n"
"Connection: close\r\n"
"\r\n", config->path, config->host, config->port);

	if ((len = write(sock, reqbuf, reqlen)) == -1) {
		rtst_warning("Write HTTP request failed: %s\n", 
			strerror(errno));
		return;
	} else if (len != reqlen) {
		rtst_warning("Unexpected partial write HTTP request\n");
		return;
	}
	clen = 0;
	while ((len = read(sock, respbuf, RTST_BUFFLEN)) > 0
	       && !exit_requested) {
		if (needt2) {
			rtst_gettime(&t2);
			needt2 = 0;
		}
		readbytes += len;
		clen += len;
		if (clen > 1024 * 1024) {	/* Check timeout */
			rtst_gettime(&t3);
			duration = rtst_msdiff(&t1, &t3);
			if (duration > 1000 * RTST_SPEEDTEST_TO) {
				break;
			}
			clen = 0;
		}
	}
	if (exit_requested) {
		return;
	}
	rtst_gettime(&t3);
	if (len == -1) {
		rtst_warning("Read HTTP response error: %s\n", 
			strerror(errno));
	}
	duration = rtst_msdiff(&t2, &t3);
	if (!pingtest) {
		st->reqms = rtst_msdiff(&t1, &t2);
		if (readbytes < RTST_BUFFLEN) {
		 rtst_warning("Too small response and object: %lu bytes\n",
		  readbytes);
		} else if (duration < 10) {
		 rtst_warning("Too short duration of measurement: %ld ms\n",
		  duration);
		} else {
			st->speedkbps = readbytes * 8 / duration;
		}
	}
}

static void do_test(struct url * config, struct rtst_stat * st, int pingtest)
{
	struct timeval			t1, t2;
	int				sock = -1;
	struct addrinfo	*		ai;
	struct addrinfo			hints;
	int				errorcode;
	int				connected = 0;
	int				optval;
	socklen_t			optlen;

	if (config->url == NULL) {
		return;
	}

	/* Set some hints for getaddrinfo */
	memset(&hints, 0, sizeof(hints));

	/* We want a IPv4 socket */
	hints.ai_family = AF_INET;

	/* We want a TCP socket */
	hints.ai_socktype = SOCK_STREAM;

	rtst_gettime(&t1);

	/* Get address information for creating socket */
	if ( (errorcode =
	      getaddrinfo(config->host, config->port, &hints,
	       &config->addrinfo)
	     ) != 0)
	{
		rtst_warning("Error getting %s:%s address information: %s\n", 
			config->host, config->port, gai_strerror(errorcode));
		return;
	}

	rtst_gettime(&t2);

	if (!pingtest) {
		st->dnsms = rtst_msdiff(&t1, &t2);
	}

	ai = config->addrinfo;
	do {
		config->addr = sockaddr_ntop(ai->ai_addr);
		rtst_gettime(&t1);

		/* Create a socket */
		if ((sock = socket(ai->ai_family, ai->ai_socktype, 
	 	     ai->ai_protocol)) < 0)
		{
			rtst_warning("Could not create socket for %s:%s\n",
			 config->addr, config->port);
			ai = ai->ai_next;
		} else {
			optval = 1;
			optlen = sizeof(optval);
			if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE,
			    &optval, optlen) < 0) {
				rtst_warning(
				 "Can't set socket option SO_KEEPALIVE\n");
			}
			if (connect(sock, ai->ai_addr, ai->ai_addrlen) < 0) {
				rtst_warning(
				 "Could not connect to %s:%s\n",
			 	 config->addr, config->port);
				ai = ai->ai_next;
			} else {
				connected = 1;
				rtst_gettime(&t2);
				if (pingtest) {
					st->tcppingms = rtst_msdiff(&t1, &t2);
				} else {
					st->connms = rtst_msdiff(&t1, &t2);
				}
			}
		}
	} while (connected == 0 && ai && !exit_requested);
	if (config->addrinfo) {
		freeaddrinfo(config->addrinfo);
		config->addrinfo = NULL;
	}
	if (connected && !exit_requested) {
		do_speedtest(config, st, sock, pingtest);
	}
	if (sock != -1) {
		/* shutdown(sock, SHUT_RDWR); */
		close(sock);
		sock = -1;
		connected = 0;
	}
}

static void parse_ping_stat(char * s, struct rtst_pingstat * st)
{
	char			*peq, *token;

	st->minping = RTST_PING_TO_MS;
	st->avgping = RTST_PING_TO_MS;
	st->maxping = RTST_PING_TO_MS;

/*
 * Example ping output:
 * rtt min/avg/max/mdev = 14.171/20.923/39.871/10.946 ms
 */

#if 0
	printf("%s", s);
#endif

	if ((peq = strstr(s, "=")) == NULL) {
		return;
	}
	peq++;
	while (*peq == ' ' && *peq) {
		peq++;
	}
	if (*peq == 0) {
		return;
	}
	token = strtok(peq, "/");		/* min */
	if (token) {
		st->minping = 0.5 + atof(token);
		token = strtok(NULL, "/");	/* avg */
	}
	if (token) {
		st->avgping = 0.5 + atof(token);
		token = strtok(NULL, "/");	/* max */
	}
	if (token) {
		st->maxping = 0.5 + atof(token);
	}

	if (st->minping > 2 * RTST_PING_TO_MS) {
		st->minping = 2 * RTST_PING_TO_MS;
	}
	if (st->avgping > 2 * RTST_PING_TO_MS) {
		st->avgping = 2 * RTST_PING_TO_MS;
	}
	if (st->maxping > 2 * RTST_PING_TO_MS) {
		st->maxping = 2 * RTST_PING_TO_MS;
	}
}

static void exec_ping(const char * host, struct rtst_pingstat * st)
{
	static char *		buff = NULL;
	int			len;
	FILE *			ping;
	static char *		format = "ping -c 4 -q %s";

	if (host == NULL) {
		return;
	}

	if (buff == NULL) {
		buff = malloc(1024);
		if (buff == NULL) {
			rtst_error(
			 "No free memory for ping buffers\n");
		}
	}

	len = strlen(format) + strlen(host) - 2 + 1;
	if (len > 1024) {
		rtst_error("Internal error: buffer overflow\n");
	}
	sprintf(buff, format, host);

	if ((ping = popen(buff, "r")) == NULL) {
		rtst_warning("Can't executing ping\n");
		return;
	}

	st->minping = RTST_PING_TO_MS; /* Default timeout */
	st->avgping = RTST_PING_TO_MS;
	st->maxping = RTST_PING_TO_MS;

	while (fgets(buff, 1023, ping)) {
		if (strstr(buff, " min/avg/max")) {
			parse_ping_stat(buff, st);
		}
	}

	pclose(ping);
}

static void do_ping(struct url * config, struct rtst_stat * st)
{
	if (config->url == NULL || config->addr == NULL) {
		return;
	}

	exec_ping(config->addr, &st->pingstat);
}

static long do_tcpping(char * host)
{
	struct url		url;
	struct rtst_stat	st;

	memset(&url, 0, sizeof(url));
	memset(&st, 0, sizeof(st));
	st.tcppingms = RTST_PING_TO_MS;

	parseurl(host, &url);
	do_test(&url, &st, 1); /* TCP ping speed */
	if (st.tcppingms > RTST_PING_TO_MS) {
		st.tcppingms = RTST_PING_TO_MS;
	}
	return st.tcppingms;
}

static void do_pinglist(char ** hosts, struct rtst_stat * st)
{
	int			idx;
	struct rtst_pingstat	pingstat;
	long			rtt;

	if (hosts == NULL) {
		return;
	}
	memset(&pingstat, 0, sizeof(pingstat));

	for (idx = 0; !exit_requested && hosts[idx]
	              && idx < RTST_PINGLIST_SIZE; idx++) {
		sleep(1);
		if (!exit_requested) {
			exec_ping(hosts[idx], &pingstat);
		}
		rtt = pingstat.avgping;
		if ( rtt >= RTST_PING_TO_MS && !exit_requested) {
			rtst_warning("Doing TCPping for host %s\n", hosts[idx]);
			rtt = do_tcpping(hosts[idx]);
		}
		st->pinglist[idx] = rtt;
	}
}

void rtst_speedtest(struct rtst_configuration * config, struct rtst_stat * st)
{
#if 0
	st->dnsms = 0;
	st->connms = 0;
	st->reqms = 0;
	st->speedkbps = 0;
	st->tcppingms = 0;
	memset(&st->pingstat, 0, sizeof(st->pingstat));
	memset(&st->pinglist[0], 0, sizeof(st->pinglist));
#else
	memset(st, 0, sizeof(*st));
#endif

	if (!exit_requested) {
	 do_test(&config->url, st, 0);		/* Test speed */
	}
	if (!exit_requested) {
	 do_test(&config->pingurl, st, 1);	/* TCP ping speed */
	}
	if (!exit_requested) {
	 do_ping(&config->pingurl, st);		/* Ping speed */
	}
	if (!exit_requested) {
	 do_pinglist(config->pinghosts, st);	/* Ping for list of hosts */
	}
}
