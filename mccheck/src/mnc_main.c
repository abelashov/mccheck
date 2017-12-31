/*
 * mnc_main.c -- Multicast NetCat
 *
 * Andrew Belashov, <Andrey.Belashov@center.rt.ru>
 * Colm MacCarthaigh, <colm@apache.org>
 *
 * Copyright (c) 2011 - 2013, Andrew Belashov, Rostelecom JSC.
 * Copyright (c) 2007, Colm MacCarthaigh.
 * Copyright (c) 2004 - 2006, HEAnet Ltd. 
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
 * Neither the name of the HEAnet Ltd. nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
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

#include "mnc.h"

int daemonmode = 0;
static volatile sig_atomic_t exit_requested = 0;
static FILE * statfile = NULL;

static void mccheck(int len, char *groupname);
static void mccheckInit();
static void mccheckStart();
static void handle_sig(int sig);

static unsigned long stPackets = 0;
static unsigned long stBytes = 0;
#ifdef MNC_CHECK_DUP
static unsigned long stPacketsDup = 0;
#endif
static unsigned long stTotPES = 0;
static unsigned long stDropPES = 0;
static unsigned long stEncPES = 0;
static unsigned long stBadPES = 0;
static unsigned long stES = 0;
static unsigned long stUAS = 0;
static unsigned long stUAES = 0;
static char *cbESpM = NULL;
static char *cbESp5M = NULL;
static int cbMidx = 0;
static int cb5Midx = 0;
static int stESpH = 0;
static int stESp5M = 0;
static unsigned long st0Packets = 0;
static unsigned long st0Bytes = 0;
static unsigned long st0DropPES = 0;
static int bufflen[2] = {0, 0};
static int buffidx = 0;
static char *recvbuff[2] = {NULL, NULL};
static int *pidCC = NULL;
static int flSignal = 0;
static int flErrors = 0;
static int flSourceChanged = 0;
static char *StreamSource = "";
static struct timeval LastRateUpdate;
static struct timeval NextRateUpdate;
static struct timeval ReceiveTimeout;
static struct timeval StartTime;
static struct timeval LastStatUpdate;
static struct timeval NextStatUpdate;
static unsigned long rtPackets = 0;
static unsigned long rtKbps = 0;
static unsigned long rtEpH = 0;
static double rtQuality = 0.0;
static unsigned long rtTime = 0;
static int nosignalseconds = 0;

int main(int argc, char **argv)
{
	/* Utility variables */
	int				sock,
					len;
#ifdef _PROFILE
	int				loops = 0;
#endif

	/* Our main configuration */
	struct mnc_configuration *	config;
	char				statbuff[256];
	char *				pstr;
	pid_t				process_id = 0;
	pid_t				sid = 0;
	FILE *				pidf = NULL;
	long				field = -1;
	struct sigaction		act;

#ifdef WINDOWS
	WSADATA 			wsaData;
 
	if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0)
	{
		mnc_error("This operating system is not supported\n");
	}
#endif
	
	/* Parse the command line */
	config = parse_arguments(argc, argv);

	if (config->daemon == CLIENT) {

		if ((statfile = fopen(MNC_STAT_FILE, "r")) == NULL) {
			mnc_error("Could not open %s: %s\n",
				MNC_STAT_FILE, strerror(errno));
		}

		/* lock */
		if (flock(fileno(statfile), LOCK_SH) < 0) {
			mnc_error("Could not flock stat file: %s\n",
				strerror(errno));
		}

		pstr = fgets(statbuff, sizeof(statbuff)-2, statfile);

		/* unlock */
		if (flock(fileno(statfile), LOCK_UN) < 0) {
			mnc_error("Could not unlock stat file: %s\n",
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
			mnc_error("must be root to run in daemon mode\n");
		}
		process_id = fork();
		if (process_id < 0) {
			mnc_error("fork() failed\n");
		}
		if (process_id > 0) {
			if ((pidf = fopen(MNC_PID_FILE, "w")) != NULL) {
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
			mnc_error("setsid() failed: %s\n", strerror(errno));
		}
		if (chdir("/") < 0) {
			mnc_error("chdir(\"/\") failed: %s\n", strerror(errno));
		}
		if (setpriority(PRIO_PROCESS, 0, -18) < 0) {
			mnc_warning("setpriority() failed: %s\n",
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
	
	/* Create a socket */
	if ((sock = socket(config->group->ai_family, config->group->ai_socktype, 
 	    config->group->ai_protocol)) < 0)
	{
		mnc_error("Could not create socket\n");
	}

	mccheckInit();
	mccheckStart();
	/* Set up the socket for listening */
	if (multicast_setup_listen(sock, config->group, config->source, 
	                 config->iface) < 0)
	{
		mnc_error("Can not listen for multicast packets.\n");
	}

#ifdef MNC_TO_DEBUG
	mnc_warning("TO %ld.%06d\n", (long)ReceiveTimeout.tv_sec,
		(int)ReceiveTimeout.tv_usec);
#endif
        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &ReceiveTimeout, 
                      sizeof(ReceiveTimeout)) < 0) {
               	mnc_error("Can not set receive timeout\n");
       	}

	/* Recieve the packets */
	while ((len = recvfrom(sock, recvbuff[buffidx], MNC_BUFFLEN, 
	  0, NULL, NULL)) >= 0 || (len == -1 && (errno == EAGAIN
	  || errno == EWOULDBLOCK)))
	{	
		if (len < 0) len = 0;
		mccheck(len, config->groupname);
#ifdef _PROFILE
		if (++loops >= 24000) {
			break;
		}
#endif
		if (exit_requested) {
			break;
		}

#ifdef MNC_TO_DEBUG
		mnc_warning("TO %ld.%06d\n",
			(long)ReceiveTimeout.tv_sec,
			(int)ReceiveTimeout.tv_usec);
#endif
		if (nosignalseconds > 60) {
			if (multicast_rejoin(sock,
			 config->group, config->source, 
	                 config->iface) < 0)
			{
			 mnc_warning("Can not rejoin to multicast group.\n");
			}
			nosignalseconds = 0;
		}
	        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
			&ReceiveTimeout, sizeof(ReceiveTimeout)) < 0) {
       	         	mnc_error("Can not set receive timeout\n");
       	 	}
	}
	
	/* Close the socket */
	close(sock);

	/* Cleanup */
	if (config->daemon == DAEMON) {
		if (statfile) {
			fclose(statfile);
			statfile = NULL;
		}
		remove(MNC_STAT_FILE);
		remove(MNC_PID_FILE);
	}

	return 0;
}

static int CheckPES(char *sbuff, int len)
{
 int nopayload = 1;
 int payload;
 int off;
 int pid, cc;
 unsigned char *buff = (unsigned char *)sbuff;

 for (off = 0; off + 187 < len; off += 188) {
  if (buff[off + 0] == 0x47) {
   stTotPES++;
   pid = 256 * (buff[off + 1] & 0x1f) + buff[off + 2];
   cc = buff[off + 3] & 0x0f;
   payload = (buff[off + 3] & 0x10) != 0;
   if (payload && pid != 0x1fff) nopayload = 0;
   if (pid >= 0x10 && pid <= 0x1ffe && pidCC[pid] != -1 && payload
    && (pidCC[pid] + 1) % 16 != cc) {
    stDropPES++;
    flErrors = 1;
   }
   if (((buff[off + 3]) & 0xc0) != 0) {
    stEncPES++;
   }
   pidCC[pid] = cc;
  } else {
   stBadPES++;
   flErrors = 1;
  }
 }
 return nopayload;
}

#ifdef MNC_CHECK_DUP
static int BuffIsEquals(char *b1, char *b2, int len)
{
 int i;

 for (i = 0; i < len; i++) {
  if (b1[i] != b2[i]) return 0;
 }
 return 1;
}
#endif

void mccheckInit()
{
 int i;

 if (recvbuff[0] == NULL) {
  for (i = 0; i < 2; i++) {
   recvbuff[i] = malloc(MNC_BUFFLEN * sizeof(char));
   if (recvbuff[i] == NULL) {
    mnc_error("Can not malloc 64KB\n");
   }
  }
 }

 if (pidCC == NULL) {
  pidCC = malloc(8192 * sizeof(int));
  if (pidCC == NULL) {
   mnc_error("Can not malloc 32KB\n");
  }
 }
 for (i = 0; i < 8192; i++) {
  pidCC[i] = -1;
 }

 if (cbESpM == NULL) {
  cbESpM = malloc(60 * sizeof(char));
  if (cbESpM == NULL) {
   mnc_error("Can not malloc %d bytes\n", 60);
  }
 }
 bzero(cbESpM, 60 * sizeof(char));
 cbMidx = 0;
 stESpH = 0;

 if (cbESp5M == NULL) {
  cbESp5M = malloc(5 * sizeof(char));
  if (cbESp5M == NULL) {
   mnc_error("Can not malloc %d bytes\n", 5);
  }
 }
 bzero(cbESp5M, 5 * sizeof(char));
 cb5Midx = 0;
 stESp5M = 0;

 stPackets = 0;
 stBytes = 0;
#ifdef MNC_CHECK_DUP
 stPacketsDup = 0;
#endif
 stTotPES = 0;
 stDropPES = 0;
 stEncPES = 0;
 stBadPES = 0;
 stES = 0;
 stUAS = 0;
 stUAES = 0;
 st0Packets = 0;
 st0Bytes = 0;
 st0DropPES = 0;
 bufflen[0] = 0;
 bufflen[1] = 0;
 buffidx = 0;
 flSignal = 0;
 nosignalseconds = 0;
 flErrors = 0;
 flSourceChanged = 0;
 timerclear(&LastRateUpdate);
 timerclear(&NextRateUpdate);
 ReceiveTimeout.tv_sec = 1;
 ReceiveTimeout.tv_usec = 0;
 timerclear(&StartTime);
 timerclear(&LastStatUpdate);
 timerclear(&NextStatUpdate);
}

void mccheckStart()
{
 struct timeval ct;
 int i;

 if (gettimeofday(&ct, NULL) != 0) {
  mnc_error("Can not get current time\n");
 }
 memcpy(&StartTime, &ct, sizeof(StartTime));
 memcpy(&LastRateUpdate, &ct, sizeof(LastRateUpdate));
 memcpy(&NextRateUpdate, &ct, sizeof(NextRateUpdate));
 NextRateUpdate.tv_sec++;
 ReceiveTimeout.tv_sec = 1;
 ReceiveTimeout.tv_usec = 0;
 memcpy(&LastStatUpdate, &ct, sizeof(LastStatUpdate));
 memcpy(&NextStatUpdate, &ct, sizeof(NextStatUpdate));
 NextStatUpdate.tv_sec += 60;
 st0Packets = stPackets;
 st0Bytes = stBytes;
 st0DropPES = stDropPES;
 stES = 0;
 stUAS = 0;
 stUAES = 0;
 flErrors = 0;
 flSignal = 0;
 nosignalseconds = 0;
 flSourceChanged = 0;
 StreamSource = "";
 bufflen[0] = 0;
 bufflen[1] = 0;
 for (i = 0; i < 8192; i++) {
  pidCC[i] = -1;
 }
}

static char* gentimestr(struct timeval *ct)
{
 static char timestr[64];

 if (strftime(timestr, sizeof(timestr), "%d.%m.%Y %H:%M:%S",
     localtime(&(ct->tv_sec))) == 0) {
  mnc_error("Can not format timestamp string\n");
 }

 return &timestr[0];
}

static int dumpstat(char * format, ...)
{
 va_list ap;
 int rval = 0;

 /* Do the vararg stuff */
 va_start(ap, format);
 if (daemonmode) {
  if (statfile == NULL) {
   if ((statfile = fopen(MNC_STAT_FILE, "w")) == NULL) {
    mnc_error("Could not fopen stat file: %s\n", strerror(errno));
   }
  }

  /* lock */
  if (flock(fileno(statfile), LOCK_EX) < 0) {
   mnc_error("Could not flock stat file: %s\n", strerror(errno));
  }

  rewind(statfile);
  if (ftruncate(fileno(statfile), 0) < 0) {
   mnc_error("Could not ftruncate stat file: %s\n", strerror(errno));
  }
  rval = vfprintf(statfile, format, ap);
  if (fflush(statfile) == EOF) {
   mnc_error("Could not fflush stat file: %s\n", strerror(errno));
  }

  /* unlock */
  if (flock(fileno(statfile), LOCK_UN) < 0) {
   mnc_error("Could not unlock stat file: %s\n", strerror(errno));
  }

 } else {
  rval = vprintf(format, ap);
 }
 va_end(ap);
 return rval;
}

static void mccheck(int len, char *groupname)
{
 struct timeval ct, timediff;
 int curridx;
#ifdef MNC_CHECK_DUP
 int previdx, complen;
#endif
 int nopayload; /* bool */
 long delta;
 double elapsed;
 char *timestr = NULL;

 if (gettimeofday(&ct, NULL) != 0) {
  mnc_error("Can not get current time\n");
 }

 if (len > 0) {
  stPackets++;
 }

 /* TODO: Check source */

 stBytes += len;
 bufflen[buffidx] = len;
 curridx = buffidx;
#ifdef MNC_CHECK_DUP
 previdx = (buffidx + 2 - 1) % 2;
 complen = bufflen[curridx] < bufflen[previdx] ? bufflen[curridx] :
  bufflen[previdx];
#endif
 nopayload = CheckPES(recvbuff[curridx], len);
 if (!nopayload) {
  flSignal = 1;
 }
#ifdef MNC_CHECK_DUP
 if (!nopayload && complen > 0
     && BuffIsEquals(recvbuff[curridx], recvbuff[previdx], complen)) {
  stPacketsDup++;
  flErrors = 1;
 }
#endif
 if (nopayload) {
  bufflen[curridx] = 0;
 }
 buffidx++; buffidx %= 2;

 /* Check virtual timers */
 timersub(&ct, &LastRateUpdate, &timediff);
 if (timediff.tv_sec > 5 || timediff.tv_sec < -5) {
  mnc_warning("Time leap (%d sec) detected. Reset counters.\n",
   (int)timediff.tv_sec);
  mccheckStart();
  return;
 }
 delta = 1000 * timediff.tv_sec + timediff.tv_usec / 1000; /* milliseconds */
 timersub(&ct, &NextRateUpdate, &timediff);
 if (timediff.tv_sec >= 0 && timediff.tv_usec >= 0) { /* One second */
  rtPackets = 1000 * (stPackets - st0Packets) / delta;
  rtKbps = 8 * (stBytes - st0Bytes) / delta;
  timersub(&ct, &StartTime, &timediff);
  elapsed = (double)timediff.tv_sec * 1000.0
   + ((double)timediff.tv_usec) / 1000.0; /* milliseconds */
  rtEpH = (long)((double)(stDropPES - st0DropPES) / elapsed * 3600000.0);
  st0Packets = stPackets;
  st0Bytes = stBytes;

  if (flErrors) stES++;
  if (!flSignal) {
   stUAS++;
   if (timestr == NULL) {
    timestr = gentimestr(&ct);
   }
   if (daemonmode) {
    mnc_warning("%s %s No Signal\n", timestr, groupname);
   } else {
    printf("%s %s No Signal\n", timestr, groupname);
   }
   nosignalseconds++;
  } else {
   nosignalseconds = 0;
  }
  /* TODO: Log Source Change */
  if (flErrors && flSignal) {
   if (timestr == NULL) {
    timestr = gentimestr(&ct);
   }
   if (daemonmode) {
    mnc_warning("%s %s Some Errors at bitrate %lu Kbps, %lu pkts/s\n",
     timestr, groupname, rtKbps, rtPackets);
   } else {
    printf("%s %s Some Errors at bitrate %lu Kbps, %lu pkts/s\n",
     timestr, groupname, rtKbps, rtPackets);
   }
  }
  if (flErrors || !flSignal) {
   stUAES++;
   cbESpM[cbMidx]++;
   cbESp5M[cb5Midx]++;
  }
  if (elapsed > 10000.0) { /* 10 seconds */
   rtQuality = 100.0 * (elapsed - stUAES * 1000.0) / elapsed;
   rtTime = (long)(elapsed / 1000.0 / 60.0); /* Minutes */
  }

  flErrors = 0;
  flSignal = 0;
  flSourceChanged = 0;
  memcpy(&LastRateUpdate, &ct, sizeof(LastRateUpdate));
  NextRateUpdate.tv_sec++;
  timersub(&NextRateUpdate, &ct, &ReceiveTimeout);
  if (ReceiveTimeout.tv_sec < 0 || ReceiveTimeout.tv_usec < 0) {
   ReceiveTimeout.tv_sec = 0;
   ReceiveTimeout.tv_usec = 1000;
  } else if (ReceiveTimeout.tv_sec > 1) {
   ReceiveTimeout.tv_sec = 1;
   ReceiveTimeout.tv_usec = 0;
  }
 }

 /* Dump Statistics */
 timersub(&ct, &LastStatUpdate, &timediff);
 delta = 1000 * timediff.tv_sec + timediff.tv_usec / 1000; /* milliseconds */
 timersub(&ct, &NextStatUpdate, &timediff);
 if ((timediff.tv_sec >= 0 && timediff.tv_usec >= 0)
     || (daemonmode && statfile == NULL)) { /* 60 seconds */
   if (timestr == NULL) {
    timestr = gentimestr(&ct);
   }
   stESpH += cbESpM[cbMidx];
   stESp5M += cbESp5M[cb5Midx];
   dumpstat("%s %s Statistics: %lu Kbps, %lu pkts/s"
#ifdef MNC_CHECK_DUP
     ", %lu DupUDP"
#endif
     ", %lu BadPES"
     ", %lu CCerr"
     ", %lu ES"
     ", %lu UAS"
     ", %lu Err/h"
     ", %lu min"
     ", %.2f%% Quality"
     ", %.2f%% 5mQuality"
     "\n",
    timestr, groupname, rtKbps, rtPackets,
#ifdef MNC_CHECK_DUP
    stPacketsDup,
#endif
    stBadPES,
    stDropPES,
    stES,
    stUAS,
#if 0
    rtEpH,
#else
    (unsigned long)stESpH,
#endif
    rtTime,
    rtQuality,
    (double)(300-stESp5M)/3.0
   );
   cbMidx = (cbMidx + 1) % 60;
   stESpH -= cbESpM[cbMidx];
   cbESpM[cbMidx] = 0;
   cb5Midx = (cb5Midx + 1) % 5;
   stESp5M -= cbESp5M[cb5Midx];
   cbESp5M[cb5Midx] = 0;
   memcpy(&LastStatUpdate, &ct, sizeof(LastStatUpdate));
   NextStatUpdate.tv_sec += 60;
 }
}

static void handle_sig(int sig)
{
 exit_requested = 1;
}
