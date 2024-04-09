/**
    $Id: cflowd-v5.h,v 1.1.1.1 2004/01/25 18:41:20 mike Exp $
**/

typedef uint32_t index_type;
typedef uint32_t ipv4addr_t;

/*
    Portions Copyright Cisco.  Taken from "xcfbook.pdf".
*/

typedef struct {
    uint16_t	version;	/* Version and flow count (1-30) */
    uint16_t	cnt;
    uint32_t	uptime;		/* Time since boot, in milliseconds */
    uint32_t	unix_secs;	/* Current seconds since 0000 UTC 1970 */
    uint32_t	unix_nsecs;	/* Residual nanoseconds since 0000 UTC 1970 */
    uint32_t	flow_sequence;	/* Sequence counter of total flows seen */
    uint32_t	unused;		/* reserved Unused (zero) bytes */
} flow_header_t;

#define CISCO_FLOW_HEADER_SIZE 24

/*
    Format of a V5 flow "on the wire".
*/

typedef struct {
    ipv4addr_t  srcIpAddr;	/* 00. Source of flow */
    ipv4addr_t  dstIpAddr;	/* 04. Dest flow */
    ipv4addr_t  ipNextHop;	/* 08. IP address of the next hop router */
    uint16_t	inputIfIndex;	/* 12. Router interface index */
    uint16_t	outputIfIndex;	/* 14. */
    uint32_t	pkts;		/* 16. */
    uint32_t	bytes;		/* 20. */
    uint32_t	startTime;	/* 24. First SysUptime at start of flow */
    uint32_t	endTime;	/* 28. SysUptime when last packet received */
    uint16_t	srcPort;	/* 32. */
    uint16_t	dstPort;	/* 34. */
    uint8_t	pad1;		/* 36  */
    uint8_t	tcpFlags;	/* 37. */
    uint8_t	protocol;	/* 38. */
    uint8_t	tos;		/* 39. Protocol type of service */
    uint16_t	srcAs;		/* 40. Autonomous system numbers */
    uint16_t	dstAs;		/* 42. */
    uint8_t	srcMaskLen;	/* 44. */
    uint8_t	dstMaskLen;	/* 45. */
    uint16_t	pad2;		/* 46. */
} cisco_v5_flow_t;

#define CISCO_V5 5
#define CISCO_V5_FLOW_LEN 48
#define CISCO_MAX_V5_FLOWS 30
#define CISCO_V5_BUFF_SIZE (CISCO_FLOW_HEADER_SIZE + \
	(CISCO_V5_FLOW_LEN * CISCO_MAX_V5_FLOWS))

/*
    Format of a record from a flow file.
    (CFlowd format)

    WARNING: sizeof( flow_t ) != FLOW_LEN.  FLOW_LEN is correct,
    not the sizeof.  Also note that not all CISCO devices send
    version 5 flows in the "documented" length.  You need to
    compute the actual length they are using.
*/

typedef struct {
    index_type	index;		/* 00. Index from UDP packet */
    ipv4addr_t  router;		/* 04. Router reporting information */
    ipv4addr_t  srcIpAddr;	/* 08. Source of flow */
    ipv4addr_t  dstIpAddr;	/* 12. Dest flow */
    uint16_t	inputIfIndex;	/* 16. Router interface index */
    uint16_t	outputIfIndex;	/* 18. */
    uint16_t	srcPort;	/* 20. */
    uint16_t	dstPort;	/* 22. */
    uint32_t	pkts;		/* 24. */
    uint32_t	bytes;		/* 28. */
    ipv4addr_t	ipNextHop;	/* 32. */
    uint32_t	startTime;	/* 36. */
    uint32_t	endTime;	/* 40. */
    uint8_t	protocol;	/* 44. */
    uint8_t	tos;		/* 45. Protocol type of service */
    uint16_t	srcAs;		/* 46. Autonomous system numbers */
    uint16_t	dstAs;		/* 48. */
    uint8_t	srcMaskLen;	/* 50. */
    uint8_t	dstMaskLen;	/* 51. */
    uint8_t	tcpFlags;	/* 52. */
} flow_t;

#define FLOW_LEN 55
#define CFLOWD_V5_BUFF_SIZE (FLOW_LEN * CISCO_MAX_V5_FLOWS)

/**
    End of cflowd-v5.h.
**/
