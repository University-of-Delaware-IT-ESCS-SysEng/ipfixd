"""
From the original C programs:

typedef struct {
    uint16_t    version;        /* Version and flow count (1-30) */
    uint16_t    cnt;            /* Cnt of data records */
    uint32_t    uptime;         /* Time since boot, in milliseconds */
    uint32_t    unix_secs;      /* Current seconds since 0000 UTC 1970 */
    uint32_t    unix_nsecs;     /* Residual nanoseconds since 0000 UTC 1970 */
    uint32_t    flow_sequence;  /* Sequence counter of total flows seen */
    uint32_t    unused;         /* reserved Unused (zero) bytes */
} flow_header_t;

header size is 24

typedef struct {
    ipv4addr_t  srcIpAddr;      /* 00. Source of flow */
    ipv4addr_t  dstIpAddr;      /* 04. Dest flow */
    ipv4addr_t  ipNextHop;      /* 08. IP address of the next hop router */
    uint16_t    inputIfIndex;   /* 12. Router interface index */
    uint16_t    outputIfIndex;  /* 14. */
    uint32_t    pkts;           /* 16. */
    uint32_t    bytes;          /* 20. */
    uint32_t    startTime;      /* 24. First SysUptime at start of flow */
    uint32_t    endTime;        /* 28. SysUptime when last packet received */
    uint16_t    srcPort;        /* 32. */
    uint16_t    dstPort;        /* 34. */
    uint8_t     pad1;           /* 36  */
    uint8_t     tcpFlags;       /* 37. */
    uint8_t     protocol;       /* 38. */
    uint8_t     tos;            /* 39. Protocol type of service */
    uint16_t    srcAs;          /* 40. Autonomous system numbers */
    uint16_t    dstAs;          /* 42. */
    uint8_t     srcMaskLen;     /* 44. */
    uint8_t     dstMaskLen;     /* 45. */
    uint16_t    pad2;           /* 46. */
} cisco_v5_flow_t;

flow_len is 48

"""

# 24 bytes.
#
# WARNING:  The decoding of this header is hardcoded in the
# header module. Changing it here will not change the code in
# header module.
#

netflow_v5_header_list = [
    [ 'exportProtocolVersion', 2 ],
    [ 'xx_cnt', 2 ],
    [ 'xx_sysUpTimeDeltaMilliseconds', 4 ], # Uptime in milliseconds
    [ 'xx_sysUpTime', 4 ],                  # Current secs since 0000 UTC 1970
    [ 'flowStartNanoseconds', 4 ],          # Note sure what to do with it
    [ 'flowId', 4 ],
    [ 'paddingOctets', 4 ]
]

# 48 bytes

netflow_v5_list = [
    [ 'sourceIPv4Address', 4 ],
    [ 'destinationIPv4Address', 4 ],
    [ 'ipNextHopIPv4Address', 4 ],
    [ 'ingressInterface', 2 ],
    [ 'egressInterface', 2 ],
    [ 'packetDeltaCount', 4 ],
    [ 'octetDeltaCount', 4 ],
    [ 'flowStartSysUpTime', 4 ],
    [ 'flowEndSysUpTime', 4 ],
    [ 'sourceTransportPort', 2 ],
    [ 'destinationTransportPort', 2 ],
    [ 'paddingOctets', 1 ],
    [ 'tcpControlBits', 1 ],
    [ 'protocolIdentifier', 1 ],
    [ 'ipClassOfService', 1, ],
    [ 'bgpSourceAsNumber', 2 ],
    [ 'bgpDestinationAsNumber', 2 ],
    [ 'sourceIPv4PrefixLength', 1 ],
    [ 'destinationIPv4PrefixLength',1 ],
    [ 'paddingOctets', 2 ]
]

# End.
