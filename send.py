import sys
import struct
import time
import socket
from collections import namedtuple

import ipfixd_app.netflow_v5
import ipfixd_app.cflowd
import ipfixd_app.util
import ipfixd_app.ipfixd_log

ipfixd_app.ipfixd_log.set_logging( None )       # Basic stderr logging

ipfixd_app.cflowd.netflow_v5_to_cflowd_list = ipfixd_app.cflowd.netflow_v5_init(
        ipfixd_app.cflowd.netflow_v5_header_keys,
        ipfixd_app.cflowd.netflow_v5_keys )

keys = list( range( 0, len( ipfixd_app.cflowd.netflow_v5_header_keys ) ) )
for (f,i) in ipfixd_app.cflowd.netflow_v5_header_keys.items():
    keys[i]=f
NetflowV5Header = namedtuple( 'NetflowV5Header', keys )

keys = list( range( 0, len( ipfixd_app.cflowd.netflow_v5_keys ) ) )
for (f,i) in ipfixd_app.cflowd.netflow_v5_keys.items():
    keys[i]=f
NetflowV5 = namedtuple( 'NetflowV5', keys )

s = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
s.connect( ( '127.0.0.1', 2056 ) )

flow_id = 1

while True:
    nh = NetflowV5Header(
        exportProtocolVersion = 5,
        xx_cnt = 28,
        xx_sysUpTimeDeltaMilliseconds = 1000,
        xx_sysUpTime = int( time.time() ),
        flowStartNanoseconds = 0,
        flowId = flow_id )

    nf0 = NetflowV5(
        sourceIPv4Address = 0x80af0221,
        destinationIPv4Address = 0x80af0223,
        ipNextHopIPv4Address = 0x80af0222,
        ingressInterface = 1,
        egressInterface = 2,
        packetDeltaCount = 1000,
        octetDeltaCount = 10000,
        flowStartSysUpTime = 0,
        flowEndSysUpTime = 1000,
        sourceTransportPort = 22,
        destinationTransportPort = 22,
        tcpControlBits = 0xff,
        protocolIdentifier = 6,
        ipClassOfService = 0,
        bgpSourceAsNumber = 3,
        bgpDestinationAsNumber = 3,
        sourceIPv4PrefixLength = 24,
        destinationIPv4PrefixLength = 24 )

    nf1 = NetflowV5(
        sourceIPv4Address = 0x80af0221,
        destinationIPv4Address = 0x80af0224,
        ipNextHopIPv4Address = 0x80af0222,
        ingressInterface = 1,
        egressInterface = 2,
        packetDeltaCount = 2000,
        octetDeltaCount = 20000,
        flowStartSysUpTime = 1100,
        flowEndSysUpTime = 1400,
        sourceTransportPort = 23,
        destinationTransportPort = 23,
        tcpControlBits = 0xff,
        protocolIdentifier = 6,
        ipClassOfService = 0,
        bgpSourceAsNumber = 3,
        bgpDestinationAsNumber = 3,
        sourceIPv4PrefixLength = 24,
        destinationIPv4PrefixLength = 24 )

    netflow_v5_packet = (ipfixd_app.cflowd.netflow_v5_header_struct.pack(*nh) +
            ipfixd_app.cflowd.netflow_v5_struct.pack(*nf0) +
            ipfixd_app.cflowd.netflow_v5_struct.pack(*nf1) +
            ipfixd_app.cflowd.netflow_v5_struct.pack(*nf0) +
            ipfixd_app.cflowd.netflow_v5_struct.pack(*nf1) +
            ipfixd_app.cflowd.netflow_v5_struct.pack(*nf0) +
            ipfixd_app.cflowd.netflow_v5_struct.pack(*nf1) +
            ipfixd_app.cflowd.netflow_v5_struct.pack(*nf0) +
            ipfixd_app.cflowd.netflow_v5_struct.pack(*nf1) +
            ipfixd_app.cflowd.netflow_v5_struct.pack(*nf0) +
            ipfixd_app.cflowd.netflow_v5_struct.pack(*nf1) +
            ipfixd_app.cflowd.netflow_v5_struct.pack(*nf0) +
            ipfixd_app.cflowd.netflow_v5_struct.pack(*nf1) +
            ipfixd_app.cflowd.netflow_v5_struct.pack(*nf0) +
            ipfixd_app.cflowd.netflow_v5_struct.pack(*nf1) +
            ipfixd_app.cflowd.netflow_v5_struct.pack(*nf0) +
            ipfixd_app.cflowd.netflow_v5_struct.pack(*nf1) +
            ipfixd_app.cflowd.netflow_v5_struct.pack(*nf0) +
            ipfixd_app.cflowd.netflow_v5_struct.pack(*nf1) +
            ipfixd_app.cflowd.netflow_v5_struct.pack(*nf0) +
            ipfixd_app.cflowd.netflow_v5_struct.pack(*nf1) +
            ipfixd_app.cflowd.netflow_v5_struct.pack(*nf0) +
            ipfixd_app.cflowd.netflow_v5_struct.pack(*nf1) +
            ipfixd_app.cflowd.netflow_v5_struct.pack(*nf0) +
            ipfixd_app.cflowd.netflow_v5_struct.pack(*nf1) +
            ipfixd_app.cflowd.netflow_v5_struct.pack(*nf0) +
            ipfixd_app.cflowd.netflow_v5_struct.pack(*nf1) +
            ipfixd_app.cflowd.netflow_v5_struct.pack(*nf0) +
            ipfixd_app.cflowd.netflow_v5_struct.pack(*nf1) )

    s.send( netflow_v5_packet )

    flow_id += 28

    if (flow_id % 1000) == 1:
        print( '%d flows' % flow_id )

    time.sleep( .001 )
