/*
 *  udplog.h
 *  
 *
 * Created by Matt Warner on 5/17/12.
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 */

#ifndef SSH_UDPLOG_H
#define SSH_UDPLOG_H
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <ctype.h>
#include <sys/types32.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/syslog.h>
#include "log.h"

struct strbuf {
	int     maxlen;         /* no. of bytes in buffer */
	int     len;            /* no. of bytes returned */
	char    *buf;            /* pointer to data */
};

// if your OS doesn't have clock32_t or uchar_t defined, define them here
//typedef int32_t         clock32_t;
//typedef int32_t         time32_t;
//typedef unsigned char   uchar_t;
#define   LOG_MAXPS       1024
#define MESSAGE_FAC LOG_DAEMON
#define MESSAGE_PRI LOG_INFO
#define MAXLINE         1024            /* max message size (but see below) */
#define MAX_TAG         230
#define STRLOG_MAKE_MSGID(fmt, msgid)                                   \
{                                                                       \
uchar_t *__cp = (uchar_t *)fmt;                                 \
uchar_t __c;                                                    \
uint32_t __id = 0;                                              \
while ((__c = *__cp++) != '\0')                                 \
if (__c >= ' ')                                         \
__id = (__id >> 5) + (__id << 27) + __c;        \
msgid = (__id % 899981) + 100000;                               \
}

struct log_ctl {
	short   mid;
	short   sid;
	char    level;          /* level of message for tracing */
	short   flags;          /* message disposition */
#if defined(_LP64) || defined(_I32LPx)
	clock32_t ltime;        /* time in machine ticks since boot */
	time32_t ttime;         /* time in seconds since 1970 */
#else
	clock_t ltime;
	time_t  ttime;
#endif
	int     seq_no;         /* sequence number */
	int     pri;            /* priority = (facility|level) */
} log_ctl_t;

static struct sockaddr_in sa;
static int sock;
static int udp_syslog_was_inited=0;
static SyslogFacility udp_log_facility = LOG_AUTH;
static LogLevel udp_log_level = SYSLOG_LEVEL_INFO;

unsigned long int get_ip_addr(char* str);
unsigned short checksum(unsigned short* addr,char len);
void sendUDPlog(struct strbuf buf);
void do_udplog(LogLevel level, const char *fmt, va_list args, LogLevel log_priority);
void initUDPlog(char *syslogServerIPaddr, LogLevel level, SyslogFacility facility);

#endif
