/*
 * rtst_opts.c -- Running options
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifndef WINDOWS

/* UNIX-y includes */
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#else

/* WINDOWS-y includes */
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "rtst.h"

/* Display a usage statement */
void usage(void)
{
	fprintf(stderr, 
		"Usage:\n rt-speedtest [-d] [-i interval] [-p URL] [-l pinglist] URL\n"
		" rt-speedtest -c [-n index]\n\n"
		"-d :    daemon mode\n"
		"-c :    get current statistics from daemon\n"
		"-n :    split output (/[, ]+/) and return field by index\n"
		"-i :    specify maximum interval for testing (defailt 3600 seconds)\n"
		"-p :    URL for TCP ping. http://ya.ru for example\n"
		"-l :    Colon separated list of hosts for ping test (max 10 hosts)\n"
		"URL : http://xdsl.orel.ru/speedtest.bin for example\n\n"
	);
	exit(1);
}

void parseurl(char * url, struct url * config)
{
	/* Variables for parsing URL */
	char * phost	= "localhost";
	char * pport	= "80";
	char * ppath	= "/";
	char * p;
	char * pcolon;
	char * pslash;
	size_t len;

	config->url = url;

	if (url == NULL) {
		config->protocol = NULL;
		config->host = NULL;
		config->port = NULL;
		config->path = NULL;
		config->addr = NULL;
		return;
	}

	/* Parse URL */
	p = config->url;

	/* Get protocol */
	if (strstr(p, "://")) {
	 if (strncasecmp(p, "http://", 7) == 0) {
	  p += 7;
	  config->protocol = "http";
	  pport = "80";
	 } else {
	  rtst_error("Unknown protocol in URL. Only HTTP supported yet\n");
	 }
	}

	/* Get port */
	pcolon = index(p, ':');
	pslash = index(p, '/');
	len = strlen(pport);
	if (pcolon) {
	 pcolon++;
	 if (pslash && pslash > pcolon) {
	  pport = pcolon;
	  len = pslash - pcolon;
	 } else if (!pslash) {
	  pport = pcolon;
	  len = strlen(pcolon);
	 } else {
	  len = strlen(pport);
	 }
	 pcolon--;
	}
	if ((config->port = malloc(len+1)) == NULL) {
	 rtst_error("No free memory\n");
	}
	strncpy(config->port, pport, len);
	config->port[len] = '\0';

	/* Get host */
	len = 0;
	if (pcolon) {
	 len = pcolon - p;
	} else if (pslash) {
	 len = pslash - p;
	} else {
	 len = strlen(p);
	}
	if (len) {
	 phost = p;
	}
	if ((config->host = malloc(len+1)) == NULL) {
	 rtst_error("No free memory\n");
	}
	strncpy(config->host, phost, len);
	config->host[len] = '\0';

	/* Get path */
	if (pslash) {
	 ppath = pslash;
	}
	len = strlen(ppath);
	if ((config->path = malloc(len+1)) == NULL) {
	 rtst_error("No free memory\n");
	}
	strcpy(config->path, ppath);
}

static void parsepinglist(char * pinglist, char ** pinghosts)
{
	char *			token;
	int			idx;
	static char *		buff = NULL;

	pinghosts[0] = NULL;
	if (pinglist == NULL) {
		return;
	}

	if (buff) {
		free(buff);
	}
	buff = malloc(sizeof(char) * (strlen(pinglist) + 1));
	if (buff == NULL) {
		rtst_error(
		 "No free memory for internal pinghosts array\n");
	}
	strcpy(buff, pinglist);

	token = strtok(buff, ";:/");
	for (idx = 0; token && idx < RTST_PINGLIST_SIZE; idx++) {
		pinghosts[idx] = token;
		token = strtok(NULL, ";:/");
	}
	for (; idx < RTST_PINGLIST_SIZE; idx++) {
		pinghosts[idx] = NULL;
	}
}

struct rtst_configuration * parse_arguments(int argc, char **argv)
{
	/* Utility variables */
	int					optind;
	char	*				url = NULL;
	char	*				pingurl = NULL;

	/* Our persisting configuration */
	static	struct rtst_configuration	config;

	/* Set some defaults */
	config.interval	= RTST_DEFAULT_INTERVAL;
	config.daemon	= NONE;
	config.field	= "-1";
	parseurl(url, &config.url);
	parseurl(pingurl, &config.pingurl);
	config.pinglist = NULL;
	parsepinglist(config.pinglist, config.pinghosts);

	/* Loop through the arguments */
	for (optind = 1; optind < argc; optind++)
	{
		if ( (argv[optind][0] == '-') || (argv[optind][0] == '/') )
		{
			switch(argv[optind][1])
			{

				/* Set daemon mode */
				case 'd':	config.daemon = DAEMON;
						break;

				/* Set client mode */
				case 'c':	config.daemon = CLIENT;
						break;

				/* Set field index */
				case 'n':	config.field = argv[++optind];
						break;

				/* Set maximum interval */
				case 'i':	config.interval = argv[++optind];
						break;

				/* Set ping URL */
				case 'p':	pingurl = argv[++optind];
						break;

				/* Set pinglist */
				case 'l':	config.pinglist = argv[++optind];
						break;

				/* Unrecognised option */
				default:	usage();
						break;
			}
		}
		else
		{
			/* assume we've ran out of options */
			break;
		}
	}

	if (config.daemon == CLIENT) {
		return &config;
	}

	/* There's a chance we were passed one option */
	if (optind >= argc || argv[optind][0] == '-')
	{
		usage();
	}

	/* Now make sure we have either exactly 1 more arguments */
	if ( (argc - optind) != 1 )
	{
		/* We have not been given the right ammount of 
		   arguments */
		usage();
	}

	/* Get the URL information */
	url = argv[optind];

	/* Move on to next argument */
	optind++;

	parseurl(url, &config.url);
	parseurl(pingurl, &config.pingurl);
	parsepinglist(config.pinglist, config.pinghosts);

	return &config;
}
