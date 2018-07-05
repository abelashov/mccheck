/* vi: set sw=4 ts=4: */
/*
 * Mini ping implementation for busybox
 *
 * Copyright (C) 1999 by Randolph Chung <tausq@debian.org>
 *
 * Adapted from the ping in netkit-base 0.10:
 * Copyright (c) 1989 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Muuss.
 *
 * Licensed under GPLv2 or later, see file LICENSE in this source tree.
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <sys/time.h>
#include <features.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <ctype.h>
#include <unistd.h>
#include <netinet/ip_icmp.h>
#include <setjmp.h>
#include "rtst.h"

/* ---- Endian Detection ------------------------------------ */

#include <limits.h>
#if defined(__digital__) && defined(__unix__)
# include <sex.h>
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) \
   || defined(__APPLE__)
# include <sys/resource.h>  /* rlimit */
# include <machine/endian.h>
# define bswap_64 __bswap64
# define bswap_32 __bswap32
# define bswap_16 __bswap16
#else
# include <byteswap.h>
# include <endian.h>
#endif

#if defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN
# define BB_BIG_ENDIAN 1
# define BB_LITTLE_ENDIAN 0
#elif defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN
# define BB_BIG_ENDIAN 0
# define BB_LITTLE_ENDIAN 1
#elif defined(_BYTE_ORDER) && _BYTE_ORDER == _BIG_ENDIAN
# define BB_BIG_ENDIAN 1
# define BB_LITTLE_ENDIAN 0
#elif defined(_BYTE_ORDER) && _BYTE_ORDER == _LITTLE_ENDIAN
# define BB_BIG_ENDIAN 0
# define BB_LITTLE_ENDIAN 1
#elif defined(BYTE_ORDER) && BYTE_ORDER == BIG_ENDIAN
# define BB_BIG_ENDIAN 1
# define BB_LITTLE_ENDIAN 0
#elif defined(BYTE_ORDER) && BYTE_ORDER == LITTLE_ENDIAN
# define BB_BIG_ENDIAN 0
# define BB_LITTLE_ENDIAN 1
#elif defined(__386__)
# define BB_BIG_ENDIAN 0
# define BB_LITTLE_ENDIAN 1
#else
# error "Can't determine endianness"
#endif

#ifdef __BIONIC__
/* should be in netinet/ip_icmp.h */
# define ICMP_DEST_UNREACH    3  /* Destination Unreachable  */
# define ICMP_SOURCE_QUENCH   4  /* Source Quench    */
# define ICMP_REDIRECT        5  /* Redirect (change route)  */
# define ICMP_ECHO            8  /* Echo Request      */
# define ICMP_TIME_EXCEEDED  11  /* Time Exceeded    */
# define ICMP_PARAMETERPROB  12  /* Parameter Problem    */
# define ICMP_TIMESTAMP      13  /* Timestamp Request    */
# define ICMP_TIMESTAMPREPLY 14  /* Timestamp Reply    */
# define ICMP_INFO_REQUEST   15  /* Information Request    */
# define ICMP_INFO_REPLY     16  /* Information Reply    */
# define ICMP_ADDRESS        17  /* Address Mask Request    */
# define ICMP_ADDRESSREPLY   18  /* Address Mask Reply    */
#endif

enum {
	DEFDATALEN = 56,
	MAXIPLEN = 60,
	MAXICMPLEN = 76,
	MAX_DUP_CHK = (8 * 128),
	MAXWAIT = 10,
	PINGINTERVAL = 1 /* 1 second */
};

/*
static void move_fd(int from, int to)
{
	if (from == to)
		return;
	dup2(from, to);
	close(from);
}
*/

static char rtst_msg_memory_exhausted[] = "No free memory\n";

/* Die if we can't allocate size bytes of memory. */
void* xmalloc(size_t size)
{
	void *ptr = malloc(size);
	if (ptr == NULL && size != 0)
		rtst_error(rtst_msg_memory_exhausted);
	return ptr;
}

/* Die if we can't resize previously allocated memory.  (This returns a pointer
   to the new memory, which may or may not be the same as the old memory.
   It'll copy the contents to a new chunk and free the old one if necessary.)
*/
void* xrealloc(void *ptr, size_t size)
{
	ptr = realloc(ptr, size);
	if (ptr == NULL && size != 0)
		rtst_error(rtst_msg_memory_exhausted);
	return ptr;
}

/* Die if we can't allocate and zero size bytes of memory. */
void* xzalloc(size_t size)
{
	void *ptr = xmalloc(size);
	memset(ptr, 0, size);
	return ptr;
}

/* Die if we can't copy a string to freshly allocated memory. */
char* xstrdup(const char *s)
{
	char *t;

	if (s == NULL)
		return NULL;

	t = strdup(s);

	if (t == NULL)
		rtst_error(rtst_msg_memory_exhausted);

	return t;
}

/* Die with an error message if we can't malloc() enough space and do an
   sprintf() into that space.
*/
char* xasprintf(const char *format, ...)
{
	va_list p;
	int r;
	char *string_ptr;

	va_start(p, format);
	r = vasprintf(&string_ptr, format, p);
	va_end(p);

	if (r < 0)
		rtst_error(rtst_msg_memory_exhausted);
	return string_ptr;
}

/* Like strncpy but make sure the resulting string is always 0 terminated. */
char* safe_strncpy(char *dst, const char *src, size_t size)
{
	if (!size) return dst;
	dst[--size] = '\0';
	return strncpy(dst, src, size);
}

typedef struct len_and_sockaddr {
	socklen_t len;
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
	} u;
} len_and_sockaddr;
enum {
	LSA_LEN_SIZE = offsetof(len_and_sockaddr, u),
	LSA_SIZEOF_SA = sizeof(
		union {
			struct sockaddr sa;
			struct sockaddr_in sin;
		}
	)
};

/* We hijack this constant to mean something else */
/* It doesn't hurt because we will add this bit anyway */
#define IGNORE_PORT NI_NUMERICSERV
static char* sockaddr2str(const struct sockaddr *sa, int flags)
{
	char host[128];
	char serv[16];
	int rc;
	socklen_t salen;

	salen = LSA_SIZEOF_SA;
	rc = getnameinfo(sa, salen,
			host, sizeof(host),
	/* can do ((flags & IGNORE_PORT) ? NULL : serv) but why bother? */
			serv, sizeof(serv),
			/* do not resolve port# into service _name_ */
			flags | NI_NUMERICSERV
	);
	if (rc)
		return NULL;
	if (flags & IGNORE_PORT)
		return xstrdup(host);
	/* For now we don't support anything else, so it has to be INET */
	/*if (sa->sa_family == AF_INET)*/
		return xasprintf("%s:%s", host, serv);
	/*return xstrdup(host);*/
}

char* xmalloc_sockaddr2dotted_noport(const struct sockaddr *sa)
{
	return sockaddr2str(sa, NI_NUMERICHOST | IGNORE_PORT);
}

void set_nport(struct sockaddr *sa, unsigned port)
{
	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *sin = (void*) sa;
		sin->sin_port = port;
		return;
	}
	/* What? UNIX socket? IPX?? :) */
}

/* We hijack this constant to mean something else */
/* It doesn't hurt because we will remove this bit anyway */
#define DIE_ON_ERROR AI_CANONNAME

/* host: "1.2.3.4[:port]", "www.google.com[:port]"
 * port: if neither of above specifies port # */
static len_and_sockaddr* str2sockaddr(
		const char *host, int port,
		int ai_flags)
{
	sa_family_t af = AF_INET;
	int rc;
	len_and_sockaddr *r;
	struct addrinfo *result = NULL;
	struct addrinfo *used_res;
	const char *org_host = host; /* only for error msg */
	const char *cp;
	struct addrinfo hint;
	struct in_addr in4;

	r = NULL;

	cp = strrchr(host, ':');
	if (cp) { /* points to ":" or "]:" */
		int sz = cp - host + 1;

		host = safe_strncpy(alloca(sz), host, sz);
		cp++; /* skip ':' */
		port = (int) strtoul(cp, NULL, 10);
		if (errno || (unsigned)port > 0xffff) {
			if (ai_flags & DIE_ON_ERROR) {
				rtst_error("bad port spec '%s'\n", org_host);
			} else {
				rtst_warning("bad port spec '%s'\n", org_host);
			}
			return NULL;
		}
	}

	/* Next two if blocks allow to skip getaddrinfo()
	 * in case host name is a numeric IP(v6) address.
	 * getaddrinfo() initializes DNS resolution machinery,
	 * scans network config and such - tens of syscalls.
	 */
	/* If we were not asked specifically for IPv6,
	 * check whether this is a numeric IPv4 */
	if (inet_aton(host, &in4) != 0) {
		r = xzalloc(LSA_LEN_SIZE + sizeof(struct sockaddr_in));
		r->len = sizeof(struct sockaddr_in);
		r->u.sa.sa_family = AF_INET;
		r->u.sin.sin_addr = in4;
		goto set_port;
	}

	memset(&hint, 0 , sizeof(hint));
	hint.ai_family = af;
	/* Need SOCK_STREAM, or else we get each address thrice (or more)
	 * for each possible socket type (tcp,udp,raw...): */
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_flags = ai_flags & ~DIE_ON_ERROR;
	rc = getaddrinfo(host, NULL, &hint, &result);
	if (rc || !result) {
		if (ai_flags & DIE_ON_ERROR) {
			rtst_error("bad address '%s'\n", org_host);
		} else {
			rtst_warning("bad address '%s'\n", org_host);
		}
		goto ret;
	}
	used_res = result;
	r = xmalloc(LSA_LEN_SIZE + used_res->ai_addrlen);
	r->len = used_res->ai_addrlen;
	memcpy(&r->u.sa, used_res->ai_addr, used_res->ai_addrlen);

 set_port:
	set_nport(&r->u.sa, htons(port));
 ret:
	if (result)
		freeaddrinfo(result);
	return r;
}

len_and_sockaddr* host_and_af2sockaddr(const char *host, int port, sa_family_t af)
{
	return str2sockaddr(host, port, DIE_ON_ERROR);
}


/* Full(er) version */

enum {
	OPT_QUIET = 1 << 0,
	OPT_VERBOSE = 1 << 1,
	OPT_c = 1 << 2,
	OPT_s = 1 << 3,
	OPT_t = 1 << 4,
	OPT_w = 1 << 5,
	OPT_W = 1 << 6,
	OPT_I = 1 << 7,
	/*OPT_n = 1 << 8, - ignored */
	OPT_IPV4 = 1 << 9
};


struct globals {
	unsigned options;
	unsigned datalen;
	unsigned pingcount; /* must be int-sized */
	unsigned opt_ttl;
	unsigned long ntransmitted, nreceived, nrepeats;
	uint16_t myid;
	unsigned tmin, tmax; /* in us */
	unsigned long tsum; /* in us, sum of all times */
	unsigned deadline;
	unsigned timeout;
	unsigned total_secs;
	unsigned sizeof_rcv_packet;
	char *rcv_packet; /* [datalen + MAXIPLEN + MAXICMPLEN] */
	void *snd_packet; /* [datalen + ipv4/ipv6_const] */
	const char *hostname;
	const char *dotted;
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
	} pingaddr;
	int pingsock;
	sigjmp_buf env_jmp;
	int exitcode;
	struct rtst_pingstat *pingstat;
	unsigned char rcvd_tbl[MAX_DUP_CHK / 8];
};
static struct globals rtst_ping_g;
#define G (rtst_ping_g)
#define options      (G.options     )
#define datalen      (G.datalen     )
#define pingcount    (G.pingcount   )
#define opt_ttl      (G.opt_ttl     )
#define myid         (G.myid        )
#define tmin         (G.tmin        )
#define tmax         (G.tmax        )
#define tsum         (G.tsum        )
#define deadline     (G.deadline    )
#define timeout      (G.timeout     )
#define total_secs   (G.total_secs  )
#define hostname     (G.hostname    )
#define dotted       (G.dotted      )
#define pingaddr     (G.pingaddr    )
#define pingsock     (G.pingsock    )
#define pingstat     (G.pingstat    )
#define exitcode     (G.exitcode    )
#define env_jmp      (G.env_jmp     )
#define rcvd_tbl     (G.rcvd_tbl    )

static void init_global()
{
	memset(&G, 0, sizeof(G));
	datalen = DEFDATALEN;
	timeout = MAXWAIT;
	tmin = UINT_MAX;
	pingsock = -1;
}

static void destroy_global()
{
	if (pingsock >= 0) {
		close(pingsock);
		pingsock = -1;
	}
	if (G.snd_packet) {
		free(G.snd_packet);
		G.snd_packet = NULL;
	}
	if (G.rcv_packet) {
		free(G.rcv_packet);
		G.rcv_packet = NULL;
	}
	if (dotted) {
		free((void *)dotted);
		dotted = NULL;
	}
}


#define BYTE(bit)	rcvd_tbl[(bit)>>3]
#define MASK(bit)	(1 << ((bit) & 7))
#define SET(bit)	(BYTE(bit) |= MASK(bit))
#define CLR(bit)	(BYTE(bit) &= (~MASK(bit)))
#define TST(bit)	(BYTE(bit) & MASK(bit))

static void
create_icmp_socket(void)
#define create_icmp_socket(lsa) create_icmp_socket()
{
	pingsock = socket(AF_INET, SOCK_RAW, 1); /* 1 == ICMP */
	if (pingsock < 0) {
		if (errno != EPERM)
			rtst_error("Can't create raw socket\n");
#if defined(__linux__) || defined(__APPLE__)
		/* We don't have root privileges.  Try SOCK_DGRAM instead.
		 * Linux needs net.ipv4.ping_group_range for this to work.
		 * MacOSX allows ICMP_ECHO, ICMP_TSTAMP or ICMP_MASKREQ
		 */
		pingsock = socket(AF_INET, SOCK_DGRAM, 1); /* 1 == ICMP */
		if (pingsock < 0)
#endif
		rtst_error("Permission denied for raw socket. Are you root?\n");
	}
}

static void print_stats_and_exit(int junk)
{
	unsigned long ul;
	unsigned long nrecv;

	/* Cancel scheduled alarm clock */
	alarm(0);
#ifdef STANDALONE
	signal(SIGINT, SIG_IGN);
#endif

	nrecv = G.nreceived;
#ifdef STANDALONE
	printf("\n--- %s ping statistics ---\n"
		"%lu packets transmitted, "
		"%lu packets received, ",
		hostname, G.ntransmitted, nrecv
	);
	if (G.nrepeats)
		printf("%lu duplicates, ", G.nrepeats);
#endif
	ul = G.ntransmitted;
	if (ul != 0)
		ul = (ul - nrecv) * 100 / ul;
#ifdef STANDALONE
	printf("%lu%% packet loss\n", ul);
#endif
	if (tmin != UINT_MAX) {
		unsigned tavg = tsum / (nrecv + G.nrepeats);
#ifdef STANDALONE
		printf("round-trip min/avg/max = %u.%03u/%u.%03u/%u.%03u ms\n",
			tmin / 1000, tmin % 1000,
			tavg / 1000, tavg % 1000,
			tmax / 1000, tmax % 1000);
#else
	pingstat->minping = (tmin + 500) / 1000;
	pingstat->avgping = (tavg + 500) / 1000;
	pingstat->maxping = (tmax + 500) / 1000;
#endif
	}
#ifdef STANDALONE
	destroy_global();
	/* if condition is true, exit with 1 -- 'failure' */
	exit(nrecv == 0 || (deadline && nrecv < pingcount));
#else
	exitcode = (nrecv == 0 || (deadline && nrecv < pingcount));
	siglongjmp(env_jmp, 1);
#endif
}

static void sendping_tail(void (*sp)(int), int size_pkt)
{
	int sz;

	CLR((uint16_t)G.ntransmitted % MAX_DUP_CHK);
	G.ntransmitted++;

	size_pkt += datalen;

	/* sizeof(pingaddr) can be larger than real sa size, but I think
	 * it doesn't matter */
	sz = sendto(pingsock, G.snd_packet, size_pkt, 0, &pingaddr.sa, sizeof(pingaddr));
	if (sz != size_pkt)
		rtst_warning("Write (sendto) error\n");

	if (pingcount == 0 || deadline || G.ntransmitted < pingcount) {
		/* Didn't send all pings yet - schedule next in 1s */
		signal(SIGALRM, sp);
		if (deadline) {
			total_secs += PINGINTERVAL;
			if (total_secs >= deadline)
				signal(SIGALRM, print_stats_and_exit);
		}
		alarm(PINGINTERVAL);
	} else { /* -c NN, and all NN are sent (and no deadline) */
		/* Wait for the last ping to come back.
		 * -W timeout: wait for a response in seconds.
		 * Affects only timeout in absense of any responses,
		 * otherwise ping waits for two RTTs. */
		unsigned expire = timeout;

		if (G.nreceived) {
			/* approx. 2*tmax, in seconds (2 RTT) */
			expire = tmax / (512*1024);
			if (expire == 0)
				expire = 1;
		}
		signal(SIGALRM, print_stats_and_exit);
		alarm(expire);
	}
}

static void get_mono(struct timeval *ts)
{
	if (gettimeofday(ts, NULL))
		rtst_error("gettimeofday() failed\n");
}

unsigned long monotonic_us(void)
{
	struct timeval ts;
	get_mono(&ts);
	return ts.tv_sec * 1000000UL + ts.tv_usec;
}

uint16_t inet_cksum(uint16_t *addr, int nleft)
{
	/*
	 * Our algorithm is simple, using a 32 bit accumulator,
	 * we add sequential 16 bit words to it, and at the end, fold
	 * back all the carry bits from the top 16 bits into the lower
	 * 16 bits.
	 */
	unsigned sum = 0;
	while (nleft > 1) {
		sum += *addr++;
		nleft -= 2;
	}

	/* Mop up an odd byte, if necessary */
	if (nleft == 1) {
		if (BB_LITTLE_ENDIAN)
			sum += *(uint8_t*)addr;
		else
			sum += *(uint8_t*)addr << 8;
	}

	/* Add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
	sum += (sum >> 16);                     /* add carry */

	return (uint16_t)~sum;
}

static void sendping4(int junk)
{
	struct icmp *pkt = G.snd_packet;

	/*memset(pkt, 0, datalen + ICMP_MINLEN + 4); - G.snd_packet was xzalloced
	*/
	pkt->icmp_type = ICMP_ECHO;
	/*pkt->icmp_code = 0;*/
	pkt->icmp_cksum = 0; /* cksum is calculated with this field set to 0 */
	pkt->icmp_seq = htons(G.ntransmitted); /* don't ++ here, it can be a macro */
	pkt->icmp_id = myid;

	/* If datalen < 4, we store timestamp _past_ the packet,
	 * but it's ok - we allocated 4 extra bytes in xzalloc() just in case.
	 */
	/*if (datalen >= 4)*/
		/* No hton: we'll read it back on the same machine */
		*(uint32_t*)&pkt->icmp_dun = monotonic_us();

	pkt->icmp_cksum = inet_cksum((uint16_t *) pkt, datalen + ICMP_MINLEN);

	sendping_tail(sendping4, ICMP_MINLEN);
}

static const char *icmp_type_name(int id)
{
	switch (id) {
	case ICMP_ECHOREPLY:      return "Echo Reply";
	case ICMP_DEST_UNREACH:   return "Destination Unreachable";
	case ICMP_SOURCE_QUENCH:  return "Source Quench";
	case ICMP_REDIRECT:       return "Redirect (change route)";
	case ICMP_ECHO:           return "Echo Request";
	case ICMP_TIME_EXCEEDED:  return "Time Exceeded";
	case ICMP_PARAMETERPROB:  return "Parameter Problem";
	case ICMP_TIMESTAMP:      return "Timestamp Request";
	case ICMP_TIMESTAMPREPLY: return "Timestamp Reply";
	case ICMP_INFO_REQUEST:   return "Information Request";
	case ICMP_INFO_REPLY:     return "Information Reply";
	case ICMP_ADDRESS:        return "Address Mask Request";
	case ICMP_ADDRESSREPLY:   return "Address Mask Reply";
	default:                  return "unknown ICMP type";
	}
}

static void unpack_tail(int sz, uint32_t *tp,
		const char *from_str,
		uint16_t recv_seq, int ttl)
{
	unsigned char *b, m;
	const char *dupmsg = " (DUP!)";
	unsigned triptime = triptime; /* for gcc */

	if (tp) {
		/* (int32_t) cast is for hypothetical 64-bit unsigned */
		/* (doesn't hurt 32-bit real-world anyway) */
		triptime = (int32_t) ((uint32_t)monotonic_us() - *tp);
		tsum += triptime;
		if (triptime < tmin)
			tmin = triptime;
		if (triptime > tmax)
			tmax = triptime;
	}

	b = &BYTE(recv_seq % MAX_DUP_CHK);
	m = MASK(recv_seq % MAX_DUP_CHK);
	/*if TST(recv_seq % MAX_DUP_CHK):*/
	if (*b & m) {
		++G.nrepeats;
	} else {
		/*SET(recv_seq % MAX_DUP_CHK):*/
		*b |= m;
		++G.nreceived;
		dupmsg += 7;
	}

	if (options & OPT_QUIET)
		return;

	printf("%d bytes from %s: seq=%u ttl=%d", sz,
		from_str, recv_seq, ttl);
	if (tp)
		printf(" time=%u.%03u ms", triptime / 1000, triptime % 1000);
	puts(dupmsg);
	fflush(NULL);
}
static void unpack4(char *buf, int sz, struct sockaddr_in *from)
{
	struct icmp *icmppkt;
	struct iphdr *iphdr;
	int hlen;

	/* discard if too short */
	if (sz < (datalen + ICMP_MINLEN))
		return;

	/* check IP header */
	iphdr = (struct iphdr *) buf;
	hlen = iphdr->ihl << 2;
	sz -= hlen;
	icmppkt = (struct icmp *) (buf + hlen);
	if (icmppkt->icmp_id != myid)
		return;				/* not our ping */

	if (icmppkt->icmp_type == ICMP_ECHOREPLY) {
		uint16_t recv_seq = ntohs(icmppkt->icmp_seq);
		uint32_t *tp = NULL;

		if (sz >= ICMP_MINLEN + sizeof(uint32_t))
			tp = (uint32_t *) icmppkt->icmp_data;
		unpack_tail(sz, tp,
			inet_ntoa(*(struct in_addr *) &from->sin_addr.s_addr),
			recv_seq, iphdr->ttl);
	} else if (icmppkt->icmp_type != ICMP_ECHO) {
		rtst_warning("got ICMP %d (%s)\n",
				icmppkt->icmp_type,
				icmp_type_name(icmppkt->icmp_type));
	}
}

static void ping4(len_and_sockaddr *lsa)
{
	int sockopt;
	const int const_int_1 = 1;

	pingaddr.sin = lsa->u.sin;

	/* enable broadcast pings */
	setsockopt(pingsock, SOL_SOCKET, SO_BROADCAST, &const_int_1, sizeof(const_int_1));

	/* set recv buf (needed if we can get lots of responses: flood ping,
	 * broadcast ping etc) */
	sockopt = (datalen * 2) + 7 * 1024; /* giving it a bit of extra room */
	setsockopt(pingsock, SOL_SOCKET, SO_RCVBUF, &sockopt, sizeof(sockopt));

	if (opt_ttl != 0) {
		setsockopt(pingsock, IPPROTO_IP, IP_TTL, &opt_ttl, sizeof(opt_ttl));
		/* above doesnt affect packets sent to bcast IP, so... */
		setsockopt(pingsock, IPPROTO_IP, IP_MULTICAST_TTL, &opt_ttl, sizeof(opt_ttl));
	}

#ifdef STANDALONE
	signal(SIGINT, print_stats_and_exit);
#endif

	/* start the ping's going ... */
	sendping4(0);

	/* listen for replies */
	while (1) {
		struct sockaddr_in from;
		socklen_t fromlen = (socklen_t) sizeof(from);
		int c;

		c = recvfrom(pingsock, G.rcv_packet, G.sizeof_rcv_packet, 0,
				(struct sockaddr *) &from, &fromlen);
		if (c < 0) {
			if (errno != EINTR)
				rtst_warning("recvfrom: %s\n",
					strerror(errno));
			continue;
		}
		unpack4(G.rcv_packet, c, &from);
		if (pingcount && G.nreceived >= pingcount)
			break;
	}
}

static void ping(len_and_sockaddr *lsa)
{
#ifdef STANDALONE
	printf("PING %s (%s)", hostname, dotted);
	printf(": %d data bytes\n", datalen);
#endif

	create_icmp_socket(lsa);

	G.sizeof_rcv_packet = datalen + MAXIPLEN + MAXICMPLEN;
	G.rcv_packet = xzalloc(G.sizeof_rcv_packet);
	G.snd_packet = xzalloc(datalen + ICMP_MINLEN + 4);
	ping4(lsa);
}

#ifdef STANDALONE
/* Display a usage statement */
void usage(void)
{
	fprintf(stderr, 
		"Usage:\n ping [-q] [-v] [-c count] [-s datalen] [-t ttl] [-w deadline] [-W timeout] host\n"
	);
	destroy_global();
	exit(1);
}

static void common_ping_main(int opt, char **argv)
{
	len_and_sockaddr *lsa;
	int optind;
	char *arg;
	int tmp_int;

	init_global();

	options |= opt;
	/* Loop through the arguments */
	for (optind = 1; argv[optind]; optind++)
	{
		if ( (argv[optind][0] == '-') || (argv[optind][0] == '/') )
		{
			switch(argv[optind][1])
			{

				case 'q':	options |= OPT_QUIET;
						break;

				case 'v':	options |= OPT_VERBOSE;
						break;

				case 'c':	arg = argv[++optind];
						pingcount = atoi(arg);
						break;

				case 's':	arg = argv[++optind];
						tmp_int = atoi(arg);
						if (tmp_int >= 0 && tmp_int <= 1500) {
							datalen = tmp_int;
						}
						break;

				/* TTL */
				case 't':	arg = argv[++optind];
						tmp_int = atoi(arg);
						if (tmp_int >= 0 && tmp_int < 200) {
							opt_ttl = tmp_int;
						}
						break;

				/* Deadline - timeout in seconds */
				case 'w':	arg = argv[++optind];
						tmp_int = atoi(arg);
						if (tmp_int > 0) {
							deadline = tmp_int;
						}
						break;

				/* Time to wait for a response, in seconds */
				case 'W':	arg = argv[++optind];
						tmp_int = atoi(arg);
						if (tmp_int > 0) {
							timeout = tmp_int;
						}
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
	
	hostname = argv[optind++];
	if (hostname == NULL || argv[optind] != NULL) {
		usage();
	}

	myid = (uint16_t) getpid();
	lsa = host_and_af2sockaddr(hostname, 0, AF_INET);

	dotted = xmalloc_sockaddr2dotted_noport(&lsa->u.sa);
	ping(lsa);
	if (lsa) {
		free(lsa);
		lsa = NULL;
	}
	if (dotted) {
		free((void *)dotted);
		dotted = NULL;
	}
	print_stats_and_exit(EXIT_SUCCESS);
	/* NOTREACHED */
	destroy_global();
}

int daemonmode = 0;

int main(int argc, char **argv)
{
	common_ping_main(0, argv);
	return 1;
}
#else
int rtst_ping_main(int opt, const char **argv, struct rtst_pingstat * st)
{
	len_and_sockaddr *lsa;
	int optind;
	const char *arg;
	int tmp_int;

	init_global();

	options |= opt;
	pingstat = st;
	/* Loop through the arguments */
	for (optind = 1; argv[optind]; optind++)
	{
		if ( (argv[optind][0] == '-') || (argv[optind][0] == '/') )
		{
			switch(argv[optind][1])
			{

				case 'q':	options |= OPT_QUIET;
						break;

				case 'v':	options |= OPT_VERBOSE;
						break;

				case 'c':	arg = argv[++optind];
						pingcount = atoi(arg);
						break;

				case 's':	arg = argv[++optind];
						tmp_int = atoi(arg);
						if (tmp_int >= 0 && tmp_int <= 1500) {
							datalen = tmp_int;
						}
						break;

				/* TTL */
				case 't':	arg = argv[++optind];
						tmp_int = atoi(arg);
						if (tmp_int >= 0 && tmp_int < 200) {
							opt_ttl = tmp_int;
						}
						break;

				/* Deadline - timeout in seconds */
				case 'w':	arg = argv[++optind];
						tmp_int = atoi(arg);
						if (tmp_int > 0) {
							deadline = tmp_int;
						}
						break;

				/* Time to wait for a response, in seconds */
				case 'W':	arg = argv[++optind];
						tmp_int = atoi(arg);
						if (tmp_int > 0) {
							timeout = tmp_int;
						}
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
	
	hostname = argv[optind++];
	if (hostname == NULL || argv[optind] != NULL) {
		rtst_error("Internal error: ping arguments\n");
	}

	myid = (uint16_t) getpid();
	lsa = str2sockaddr(hostname, 0, 0);
	if (lsa == NULL) {
		exitcode = 1;
	} else {
		dotted = xmalloc_sockaddr2dotted_noport(&lsa->u.sa);
		if (sigsetjmp(env_jmp, 1) == 0) {
			ping(lsa);
			if (lsa) {
				free(lsa);
				lsa = NULL;
			}
			if (dotted) {
				free((void *)dotted);
				dotted = NULL;
			}
			print_stats_and_exit(EXIT_SUCCESS);
		}
		/* Point to longjmp */
	}
	tmp_int = exitcode;
	destroy_global();
	return tmp_int;
}
#endif
