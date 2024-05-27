#ifndef _LINUX_SOCKET_H
#define _LINUX_SOCKET_H

#ifdef CONFIG_CSPKERNEL_QOS
#define SO_QOS_PRIORITY 45 /*Sock Setsockopt QOS*/
#endif
#define FLOWRLRULEBASE		600
#define DELFLOWRLRULE		FLOWRLRULEBASE+1
#define SETFLOWRLRULE		FLOWRLRULEBASE+2
#define FLOWRLRULEMAX		FLOWRLRULEBASE+3
#define DEVBWBASE		    	FLOWRLRULEBASE+10
#define ADDBWCLASSIFY		    FLOWRLRULEBASE+11
#define SETBWCLASSIFY		    FLOWRLRULEBASE+12
#define DELBWCLASSIFY		    FLOWRLRULEBASE+13
#define SETBWROUND		    	FLOWRLRULEBASE+14
#define SETBWENABLE		    	FLOWRLRULEBASE+15
#define GETBWSTATS		        FLOWRLRULEBASE+16
#define GETDEVSTATS		    	FLOWRLRULEBASE+17
#define GETBWHARDSTATS		    FLOWRLRULEBASE+18
#define DEVBWMAX		        FLOWRLRULEBASE+19
/*
 * Desired design of maximum size and alignment (see RFC2553)
 */
#define _K_SS_MAXSIZE	128	/* Implementation specific max size */
#define _K_SS_ALIGNSIZE	(__alignof__ (struct sockaddr *))
				/* Implementation specific desired alignment */

typedef unsigned short __kernel_sa_family_t;

struct __kernel_sockaddr_storage {
	__kernel_sa_family_t	ss_family;		/* address family */
	/* Following field(s) are implementation specific */
	char		__data[_K_SS_MAXSIZE - sizeof(unsigned short)];
				/* space to achieve desired size, */
				/* _SS_MAXSIZE value minus size of ss_family */
} __attribute__ ((aligned(_K_SS_ALIGNSIZE)));	/* force desired alignment */

#endif /* _LINUX_SOCKET_H */
