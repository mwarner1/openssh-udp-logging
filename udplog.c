/*
 *  udplog.c
 *  
 *
 *  Created by Matt Warner on 5/17/12.
 *  Copyright 2012 __MyCompanyName__. All rights reserved.
 *
 */

#include "udplog.h"

//#include <sys/log.h>

// syslog client code originally lifted from http://www.hoobie.net/security/exploits/hacking/syslog_deluxe.c

unsigned long int get_ip_addr(char* str){
	
	struct hostent *hostp;
	unsigned long int addr;
	
	if( (addr = inet_addr(str)) == -1){
        if( (hostp = gethostbyname(str)))
			return *(unsigned long int*)(hostp->h_addr);
        else {
			fprintf(stderr,"unknown host %s\n",str);
			exit(1);
		}
	}
	return addr;
}

unsigned short checksum(unsigned short* addr,char len){
	/* This is a simplified version that expects even number of bytes */
	register long sum = 0;
	
	while(len > 1){
        sum += *addr++;
        len -= 2;
	}
	while (sum>>16) sum = (sum & 0xffff) + (sum >> 16);
	
	return ~sum;
}

void initUDPlog(char *syslogServerIPaddr, LogLevel level, SyslogFacility facility) {
	// we should really determine the max hostname length permitted dynamically, but 1024 seems safe for a max hostname in lieu of that.
	// anyone responsible for a hostname longer than that should be required to support the system themselves.
	char hostname[1024];
	
	gethostname(hostname, sizeof hostname);
	
	if( (sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        perror("socket");
        exit(1);
	}
	
	sa.sin_addr.s_addr = get_ip_addr(syslogServerIPaddr);
	sa.sin_family = AF_INET;
	// 514 is the typical syslog port, but we should probably make this dynamic via a config.
	sa.sin_port = htons(514);
	udp_log_facility=facility;
	udp_log_level=level;
	udp_syslog_was_inited=1;
}

void sendUDPlog(struct strbuf buf) {
    if (udp_syslog_was_inited) {
		if(sendto(sock,buf.buf,buf.len,0,(struct sockaddr*)&sa,sizeof(sa)) < 0){
			perror("Failed to send data via UDP to syslog server.");
		}
	}
}

int convertToSyslog(SyslogFacility facility ,LogLevel level) {
	int returnVal=0;
	switch(facility) {
		case SYSLOG_FACILITY_DAEMON: returnVal=LOG_DAEMON; break;
		case 	SYSLOG_FACILITY_USER: returnVal=LOG_DAEMON; break;
		case SYSLOG_FACILITY_AUTH: returnVal=LOG_AUTH; break;
#ifdef LOG_AUTHPRIV
		case SYSLOG_FACILITY_AUTHPRIV: returnVal=LOG_AUTHPRIV; break;
#endif
		case SYSLOG_FACILITY_LOCAL0: returnVal=LOG_LOCAL0; break;
		case SYSLOG_FACILITY_LOCAL1: returnVal=LOG_LOCAL1; break;
		case SYSLOG_FACILITY_LOCAL2: returnVal=LOG_LOCAL2; break;
		case SYSLOG_FACILITY_LOCAL3: returnVal=LOG_LOCAL3; break;
		case SYSLOG_FACILITY_LOCAL4: returnVal=LOG_LOCAL4; break;
		case SYSLOG_FACILITY_LOCAL5: returnVal=LOG_LOCAL5; break;
		case SYSLOG_FACILITY_LOCAL6: returnVal=LOG_LOCAL6; break;
		case SYSLOG_FACILITY_LOCAL7: returnVal=LOG_LOCAL7; break;
		default: returnVal=LOG_AUTH; break;
	}
	
	switch (level) {
		case SYSLOG_LEVEL_QUIET: returnVal+=LOG_INFO; break;
		case SYSLOG_LEVEL_FATAL: returnVal+=LOG_CRIT; break;
		case SYSLOG_LEVEL_ERROR: returnVal+=LOG_ERR; break;
		case SYSLOG_LEVEL_INFO: returnVal+=LOG_INFO; break;
		case SYSLOG_LEVEL_VERBOSE: returnVal+=LOG_DEBUG; break;
		case SYSLOG_LEVEL_DEBUG1: returnVal+=LOG_DEBUG; break;
		case SYSLOG_LEVEL_DEBUG2: returnVal+=LOG_DEBUG; break;
		case SYSLOG_LEVEL_DEBUG3: returnVal+=LOG_DEBUG; break;
		default: returnVal+=LOG_INFO; break;
	}
	return returnVal;
	
}

void do_udplog(LogLevel level, const char *fmt, va_list args, LogLevel log_priority) {
	if (udp_syslog_was_inited) {
	// assemble the message. Original lifted from http://src.opensolaris.org/source/xref/onnv/onnv-gate/usr/src/lib/libc/port/gen/syslog.c
	char *b, *f, *o;
	char *LogTag="sshd";
	size_t taglen;
	char c;
	uint32_t msgid;
	char buf[MAXLINE + 2];
	int olderrno = errno;
	int clen;
	time_t now;
	struct log_ctl hdr;
	struct strbuf dat;
	char outline[MAXLINE + 256];  /* pad to allow date, system name... */
	struct strbuf ctl;
	char timestr[26];       /* hardwired value 26 due to Posix */
	
	o= outline;

	(void) time(&now);
	// format for syslog by including the 3-digit facility+level at the beginning of the string
	(void) sprintf(o, "<%03d>%.15s ", convertToSyslog(udp_log_facility,level), ctime_r(&now, timestr, 26) + 4);
    o += strlen(o);
	
	if (LogTag) {
		taglen = strlen(LogTag) < MAX_TAG ? strlen(LogTag) : MAX_TAG;
		(void) strncpy(o, LogTag, taglen);
		o[taglen] = '\0';
		o += strlen(o);
	}
	
	(void) sprintf(o, "[%d]", (int)getpid());
	o += strlen(o);
	
	if (LogTag) {
		(void) strcpy(o, ": ");
		o += 2;
	}
	
	STRLOG_MAKE_MSGID(fmt, msgid);
	if (log_facility_name(udp_log_facility) && log_level_name(level)) {
		char text_log_facility[30];
		strcpy(text_log_facility,log_facility_name(udp_log_facility));
		
		char text_log_level[30];
		strcpy(text_log_level,log_level_name(level));

		if (text_log_facility && text_log_level) {
			for (int x=0; x<sizeof(text_log_facility); x++) {
				text_log_facility[x]=tolower(text_log_facility[x]);
			}
			for (int x=0; x<sizeof(text_log_level); x++) {
				text_log_level[x]=tolower(text_log_level[x]);
			}
			(void) sprintf(o, "[ID %u %s.%s] ", msgid,text_log_facility,text_log_level);
		}
	}
	
	o += strlen(o);
	
	b = buf;
	f = (char *)fmt;
	while ((c = *f++) != '\0' && b < &buf[MAXLINE]) {
		char *errmsg;
		if (c != '%') {
			*b++ = c;
			continue;
		}
		if ((c = *f++) != 'm') {
			*b++ = '%';
			*b++ = c;
			continue;
		}
		if ((errmsg = strerror(olderrno)) == NULL)
			(void) snprintf(b, &buf[MAXLINE] - b, "error %d",
							olderrno);
		else {
			while (*errmsg != '\0' && b < &buf[MAXLINE]) {
				if (*errmsg == '%') {
					(void) strcpy(b, "%%");
					b += 2;
				}
				else
					*b++ = *errmsg;
				errmsg++;
			}
			*b = '\0';
		}
		b += strlen(b);
	}
	if (b > buf && *(b-1) != '\n')  /* ensure at least one newline */
		*b++ = '\n';
	*b = '\0';
	/* LINTED variable format specifier */
	(void) vsnprintf(o, &outline[sizeof (outline)] - o, buf, args);
	clen  = (int)strlen(outline) + 1;       /* add one for NULL byte */
	if (clen > MAXLINE) {
		clen = MAXLINE;
		outline[MAXLINE-1] = '\0';
	}
	
	/*
	 * 1136432 points out that the underlying log driver actually
	 * refuses to accept (ERANGE) messages longer than LOG_MAXPS
	 * bytes.  So it really doesn't make much sense to putmsg a
	 * longer message..
	 */
	if (clen > LOG_MAXPS) {
		clen = LOG_MAXPS;
		outline[LOG_MAXPS-1] = '\0';
	}
	
	/* set up the strbufs */
	ctl.maxlen = sizeof (struct log_ctl);
	ctl.len = sizeof (struct log_ctl);
	ctl.buf = (caddr_t)&hdr;
	dat.maxlen = sizeof (outline);
	dat.len = clen;
	dat.buf = outline;
	
	/* output the message to the remote logger */
	sendUDPlog(dat);
	}
}
