/*
 * rtst.h -- Rostelecom SpeedTest
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

#ifndef _RTST_H_
#define _RTST_H_

#ifndef WINDOWS

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/time.h>
#include <signal.h>

#else

#include <winsock2.h>
#include <ws2tcpip.h>

#endif

#define RTST_DEFAULT_INTERVAL	"3600"
#define RTST_BUFFLEN	65536
#define RTST_PING_TO_MS	1000
#define RTST_SPEEDTEST_TO 300	/* seconds */
#define RTST_PINGLIST_SIZE 10
#define RTST_STAT_FILE	"/var/run/rt-speedtest.stat"
#define RTST_PID_FILE	"/var/run/rt-speedtest.pid"

struct url
{
	char	*		url;
	char	*		protocol;
	char	*		host;
	char	*		port;
	char	*		path;
	const char	*	addr;
	struct addrinfo *	addrinfo;
};

struct rtst_configuration
{
	/* The URLs */
	struct url		url;
	struct url		pingurl;

	/* The list of hosts for ping */
	char	*		pinglist;	/* Coma separated host list */
	char	*		pinghosts[RTST_PINGLIST_SIZE];

	/* The test interval */
	char	*		interval;
	
	/* The daemon mode */
	enum {NONE, DAEMON, CLIENT}	daemon;

	/* Index of output field for SNMP get requests (client mode) */
	char	*		field;
};

struct rtst_pingstat
{
	long			minping;	/* Min ping time (ms) */
	long			avgping;	/* Avg ping time (ms) */
	long			maxping;	/* Max ping time (ms) */
};

struct rtst_stat
{
	long			dnsms;		/* DSN request time (ms) */
	long			connms;		/* Connect time (ms) */
	long			reqms;		/* Request time (ms) */
	long			tcppingms;	/* TCP Ping time (ms) */
	struct rtst_pingstat	pingstat;	/* ping times (ms) */
	unsigned long		speedkbps;	/* Speed (Kbps) */
	long			pinglist[RTST_PINGLIST_SIZE];
						/* Avg ping time (ms) */
};

/* Global variables */
extern int daemonmode;
extern volatile sig_atomic_t exit_requested;

/* Functions in rtst_opts.c */
void 				usage(void);
struct rtst_configuration * 	parse_arguments(int argc, char **argv);
void parseurl(char * url, struct url * config);

/* Functions in rtst_speedtest.c */
void rtst_speedtest(struct rtst_configuration *, struct rtst_stat *);
void rtst_gettime(struct timeval *);
long rtst_msdiff(struct timeval *, struct timeval *);

/* Functions in rtst_error.c */
void rtst_warning(char * string, ...);
void rtst_error(char * string, ...);

#endif /* _RTST_H_ */
