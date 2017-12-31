/*
 * rtst_main.c -- Rostelecom Speed Test
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

/* Non-windows includes */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>

#else 

/* Windows-specific includes */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>

#endif /* WINDOWS */

#include "rtst.h"

int daemonmode = 0;
volatile sig_atomic_t exit_requested = 0;
static FILE * statfile = NULL;
static struct rtst_stat st;

static void handle_sig(int sig);

static int dumpstat(char * format, ...)
{
 va_list ap;
 int rval = 0;

 /* Do the vararg stuff */
 va_start(ap, format);
 if (daemonmode) {
  if (statfile == NULL) {
   if ((statfile = fopen(RTST_STAT_FILE, "w")) == NULL) {
    rtst_error("Could not fopen stat file: %s\n", strerror(errno));
   }
  }

  /* lock */
  if (flock(fileno(statfile), LOCK_EX) < 0) {
   rtst_error("Could not flock stat file: %s\n", strerror(errno));
  }

  rewind(statfile);
  if (ftruncate(fileno(statfile), 0) < 0) {
   rtst_error("Could not ftruncate stat file: %s\n", strerror(errno));
  }
  rval = vfprintf(statfile, format, ap);
  if (fflush(statfile) == EOF) {
   rtst_error("Could not fflush stat file: %s\n", strerror(errno));
  }

  /* unlock */
  if (flock(fileno(statfile), LOCK_UN) < 0) {
   rtst_error("Could not unlock stat file: %s\n", strerror(errno));
  }

 } else {
  rval = vprintf(format, ap);
 }
 va_end(ap);
 return rval;
}

static char* gentimestr(struct timeval *ct)
{
 static char timestr[64];

 if (strftime(timestr, sizeof(timestr), "%d.%m.%Y %H:%M:%S",
     localtime(&(ct->tv_sec))) == 0) {
  rtst_error("Can not format timestamp string\n");
 }

 return &timestr[0];
}

int main(int argc, char **argv)
{
	/* Utility variables */
	int				len;
#ifdef _PROFILE
	int				loops = 0;
#endif

	/* Our main configuration */
	struct rtst_configuration *	config;
	char				statbuff[1024];
	char *				pstr;
	pid_t				process_id = 0;
	pid_t				sid = 0;
	FILE *				pidf = NULL;
	long				field = -1;
	int				interval, rnd_int;
	struct timeval			ct;
	struct sigaction		act;

#ifdef WINDOWS
	WSADATA 			wsaData;
 
	if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0)
	{
		rtst_error("This operating system is not supported\n");
	}
#endif
	
	/* Parse the command line */
	config = parse_arguments(argc, argv);

	if (config->daemon == CLIENT) {

		if ((statfile = fopen(RTST_STAT_FILE, "r")) == NULL) {
			rtst_error("Could not open %s: %s\n",
				RTST_STAT_FILE, strerror(errno));
		}

		/* lock */
		if (flock(fileno(statfile), LOCK_SH) < 0) {
			rtst_error("Could not flock stat file: %s\n",
				strerror(errno));
		}

		pstr = fgets(statbuff, sizeof(statbuff)-2, statfile);

		/* unlock */
		if (flock(fileno(statfile), LOCK_UN) < 0) {
			rtst_error("Could not unlock stat file: %s\n",
				strerror(errno));
		}

		if (pstr != NULL) {
			len = strlen(pstr);
			if (len > 0 && pstr[len - 1] == '\n') {
				pstr[--len] = '\0';
			}
			field = strtol(config->field, NULL, 10);
			if (field >= 0) {
				pstr = strtok(pstr, "%, ");
				while (pstr && field > 0) {
					pstr = strtok(NULL, "%, ");
					field--;
				}
				if (pstr == NULL) {
					pstr = "";
				}
			}
			puts(pstr);
		}

		fclose(statfile);
		statfile = NULL;

		return 0;
	} else if (config->daemon == DAEMON) {
		if (geteuid() != 0) {
			rtst_error("must be root to run in daemon mode\n");
		}
		process_id = fork();
		if (process_id < 0) {
			rtst_error("fork() failed\n");
		}
		if (process_id > 0) {
			if ((pidf = fopen(RTST_PID_FILE, "w")) != NULL) {
				fprintf(pidf, "%d\n", process_id);
				fclose(pidf);
			}
			return 0; /* exit from parent */
		}
		/* child */
		daemonmode = 1;
		umask(0022);
		sid = setsid();
		if (sid < 0) {
			rtst_error("setsid() failed: %s\n", strerror(errno));
		}
		if (chdir("/") < 0) {
			rtst_error("chdir(\"/\") failed: %s\n", strerror(errno));
		}
		if (setpriority(PRIO_PROCESS, 0, 10) < 0) {
			rtst_warning("setpriority() failed: %s\n",
				strerror(errno));
		}
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
#if 0
		signal(SIGINT, handle_sig);
		signal(SIGTERM, handle_sig);
#else
		memset(&act, 0, sizeof(act));
		act.sa_handler = handle_sig;
		act.sa_flags = 0;		/* No SA_RESTART */
		sigaction(SIGINT, &act, NULL);
		sigaction(SIGTERM, &act, NULL);
#endif
	}

	/* Init random generator */
	srandom((unsigned int)time(NULL));

	interval = atoi(config->interval);

	while (!exit_requested) {
		rtst_speedtest(config, &st);

		if (exit_requested) {
			break;
		}

		rtst_gettime(&ct);

		dumpstat("%s %s DNS: %ld ms, Conn: %ld ms, Req: %ld ms, "
			"Speed: %lu Kbps, %s: %ld ms, "
			"ping(min/avg/max): %ld %ld %ld ms "
			"pinglist: "
#if 1
			"%s "
#endif
			"%ld %ld %ld %ld %ld %ld %ld %ld %ld %ld ms"
			"\n",
			gentimestr(&ct), config->url.url,
			st.dnsms, st.connms, st.reqms, st.speedkbps,
			config->pingurl.url, st.tcppingms,
			st.pingstat.minping, st.pingstat.avgping,
			st.pingstat.maxping,
#if 1
			config->pinglist == NULL ? "(null)" : config->pinglist,
#endif
			st.pinglist[0], st.pinglist[1], st.pinglist[2],
			st.pinglist[3], st.pinglist[4], st.pinglist[5],
			st.pinglist[6], st.pinglist[7], st.pinglist[8],
			st.pinglist[9] 
		);

		rnd_int = interval / 2 + (random() % (interval / 2));
		sleep(rnd_int);

#ifdef _PROFILE
		if (++loops >= 1) {
			break;
		}
#endif
	}

	/* Cleanup */
	if (config->daemon == DAEMON) {
		if (statfile) {
			fclose(statfile);
			statfile = NULL;
		}
		remove(RTST_STAT_FILE);
		remove(RTST_PID_FILE);
	}

	return 0;
}

static void handle_sig(int sig)
{
 exit_requested = 1;
}
