"""
This module defines the fields that are part of ipfix objects
as defined by various RFCs.  See rfc5102 as a start.

Obsoleted by: http://www.iana.org/assignments/ipfix/ipfix.xhtml

ipfix_id_to_info: fields:
        name    - The name of the field
        len     - The standard length
        fmt     - The standard "struct" pack/unpack character(s)
        id      - The id.  This is the same as the index for this
                  list, but the id is useful in ipfix_name_to_info.

ipfix_name_to_info: A dict, indexed by ipfix field name, whose
value is an object with the above named fields.

This data should be view as constant, at least within a given
program run.
"""

from collections import namedtuple

ipfix_id_to_info = [ ( 'RESERVED', 0, 'x' ) for i in range( 0, 512 )]

ipfix_id_to_info[0] = ( 'pad', 1, 'x' )
ipfix_id_to_info[1] = ( 'octetDeltaCount', 8, 'Q' )
ipfix_id_to_info[2] = ( 'packetDeltaCount', 8, 'Q' )
ipfix_id_to_info[4] = ( 'protocolIdentifier', 1, 'B' )
ipfix_id_to_info[5] = ( 'ipClassOfService', 1, 'B' )

"""
          0     1     2     3     4     5     6     7
      +-----+-----+-----+-----+-----+-----+-----+-----+
      |  Reserved | URG | ACK | PSH | RST | SYN | FIN |
      +-----+-----+-----+-----+-----+-----+-----+-----+
"""

ipfix_id_to_info[6] = ( 'tcpControlBits', 1, 'B' )

ipfix_id_to_info[7] = ( 'sourceTransportPort', 2, 'H' )
ipfix_id_to_info[8] = ( 'sourceIPv4Address', 4, 'L' )
ipfix_id_to_info[9] = ( 'sourceIPv4PrefixLength', 1, 'B' )
ipfix_id_to_info[10] = ( 'ingressInterface', 4, 'L' )
ipfix_id_to_info[11] = ( 'destinationTransportPort', 2, 'H' )
ipfix_id_to_info[12] = ( 'destinationIPv4Address', 4, 'L' )
ipfix_id_to_info[13] = ( 'destinationIPv4PrefixLength', 1, 'B' )
ipfix_id_to_info[14] = ( 'egressInterface', 4, 'L' )
ipfix_id_to_info[15] = ( 'ipNextHopIPv4Address', 4, 'L' )
ipfix_id_to_info[16] = ( 'bgpSourceAsNumber', 4, 'L' )
ipfix_id_to_info[17] = ( 'bgpDestinationAsNumber', 4, 'L' )
ipfix_id_to_info[18] = ( 'bgpNexthopIPv4Address', 4, 'L' )
ipfix_id_to_info[19] = ( 'postMCastPacketDeltaCount', 8, 'Q' )
ipfix_id_to_info[20] = ( 'postMCastOctetDeltaCount', 8, 'Q' )
ipfix_id_to_info[21] = ( 'flowEndSysUpTime', 4, 'L' )
ipfix_id_to_info[22] = ( 'flowStartSysUpTime', 4, 'L' )
ipfix_id_to_info[23] = ( 'postOctetDeltaCount', 8, 'Q' )
ipfix_id_to_info[24] = ( 'postPacketDeltaCount', 8, 'Q' )
ipfix_id_to_info[25] = ( 'minimumIpTotalLength', 8, 'Q' )
ipfix_id_to_info[26] = ( 'maximumIpTotalLength', 8, 'Q' )
ipfix_id_to_info[27] = ( 'sourceIPv6Address', 16, '16s' )
ipfix_id_to_info[28] = ( 'destinationIPv6Address', 16, '16s' )
ipfix_id_to_info[29] = ( 'sourceIPv6PrefixLength', 1, 'B' )
ipfix_id_to_info[30] = ( 'destinationIPv6PrefixLength', 1, 'B' )
ipfix_id_to_info[31] = ( 'flowLabelIPv6', 4, 'L' )
ipfix_id_to_info[32] = ( 'icmpTypeCodeIPv4', 2, 'H' )
ipfix_id_to_info[33] = ( 'igmpType', 1, 'B' )
ipfix_id_to_info[36] = ( 'flowActiveTimeout', 2, 'H' )
ipfix_id_to_info[37] = ( 'flowIdleTimeout', 2, 'H' )
ipfix_id_to_info[40] = ( 'exportedOctetTotalCount', 8, 'Q' )
ipfix_id_to_info[41] = ( 'exportedMessageTotalCount', 8, 'Q' )
ipfix_id_to_info[42] = ( 'exportedFlowRecordTotalCount', 8, 'Q' )
ipfix_id_to_info[44] = ( 'sourceIPv4Prefix', 4, 'L' )
ipfix_id_to_info[45] = ( 'destinationIPv4Prefix', 4, 'L' )
ipfix_id_to_info[46] = ( 'mplsTopLabelType', 1, 'B' )
ipfix_id_to_info[47] = ( 'mplsTopLabelIPv4Address', 4, 'L' )
ipfix_id_to_info[52] = ( 'minimumTTL', 1, 'B' )
ipfix_id_to_info[53] = ( 'maximumTTL', 1, 'B' )
ipfix_id_to_info[54] = ( 'fragmentIdentification', 4, 'L' )
ipfix_id_to_info[55] = ( 'postIpClassOfService', 1, 'B' )
ipfix_id_to_info[56] = ( 'sourceMacAddress', 6, '6s' )
ipfix_id_to_info[57] = ( 'postDestinationMacAddress', 6, '6s' )
ipfix_id_to_info[58] = ( 'vlanId', 2, 'H' )
ipfix_id_to_info[59] = ( 'postVlanId', 2, 'H' )
ipfix_id_to_info[60] = ( 'ipVersion', 1, 'B' )

"""
0x00: ingress flow
0x01: egress flow
"""

ipfix_id_to_info[61] = ( 'flowDirection', 1, 'B' )

ipfix_id_to_info[62] = ( 'ipNextHopIPv6Address', 16, '16s' )
ipfix_id_to_info[63] = ( 'bgpNexthopIPv6Address', 16, '16s' )

"""
              0     1     2     3     4     5     6     7
          +-----+-----+-----+-----+-----+-----+-----+-----+
          | Res | FRA1| RH  | FRA0| UNK | Res | HOP | DST |  ...
          +-----+-----+-----+-----+-----+-----+-----+-----+

              8     9    10    11    12    13    14    15
          +-----+-----+-----+-----+-----+-----+-----+-----+
      ... | PAY | AH  | ESP |         Reserved            | ...
          +-----+-----+-----+-----+-----+-----+-----+-----+

             16    17    18    19    20    21    22    23
          +-----+-----+-----+-----+-----+-----+-----+-----+
      ... |                  Reserved                     | ...
          +-----+-----+-----+-----+-----+-----+-----+-----+

             24    25    26    27    28    29    30    31
          +-----+-----+-----+-----+-----+-----+-----+-----+
      ... |                  Reserved                     |
          +-----+-----+-----+-----+-----+-----+-----+-----+

        Bit    IPv6 Option   Description

       0, Res               Reserved
       1, FRA1     44       Fragmentation header - not first fragment
       2, RH       43       Routing header
       3, FRA0     44       Fragment header - first fragment
       4, UNK               Unknown Layer 4 header
                            (compressed, encrypted, not supported)
       5, Res               Reserved
       6, HOP       0       Hop-by-hop option header
       7, DST      60       Destination option header
       8, PAY     108       Payload compression header
       9, AH       51       Authentication Header
      10, ESP      50       Encrypted security payload
      11 to 31              Reserved
"""

ipfix_id_to_info[64] = ( 'ipv6ExtensionHeaders', 4, 'L' )

"""
       0                   1                   2
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                Label                  | Exp |S|
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

      Label:  Label Value, 20 bits
      Exp:    Experimental Use, 3 bits
      S:      Bottom of Stack, 1 bit
"""

ipfix_id_to_info[70] = ( 'mplsTopLabelStackSection', 3, '3s' )

ipfix_id_to_info[71] = ( 'mplsLabelStackSection2', 3, '3s' )
ipfix_id_to_info[72] = ( 'mplsLabelStackSection3', 3, '3s' )
ipfix_id_to_info[73] = ( 'mplsLabelStackSection4', 3, '3s' )
ipfix_id_to_info[74] = ( 'mplsLabelStackSection5', 3, '3s' )
ipfix_id_to_info[75] = ( 'mplsLabelStackSection6', 3, '3s' )
ipfix_id_to_info[76] = ( 'mplsLabelStackSection7', 3, '3s' )
ipfix_id_to_info[77] = ( 'mplsLabelStackSection8', 3, '3s' )
ipfix_id_to_info[78] = ( 'mplsLabelStackSection9', 3, '3s' )
ipfix_id_to_info[79] = ( 'mplsLabelStackSection10', 3, '3s' )
ipfix_id_to_info[80] = ( 'destinationMacAddress', 6, '6s' )
ipfix_id_to_info[81] = ( 'postSourceMacAddress', 6, '6s' )
ipfix_id_to_info[85] = ( 'octetTotalCount', 8, 'Q' )
ipfix_id_to_info[86] = ( 'packetTotalCount', 8, 'Q' )
ipfix_id_to_info[88] = ( 'fragmentOffset', 2, 'H' )

# Note: the real length really needs to come from the field def.
# We should code an exception for anything that gets through over
# 256 bytes.  256 is the real maximum for this value.

ipfix_id_to_info[90] = ( 'mplsVpnRouteDistinguisher', 257, '2567' )

ipfix_id_to_info[128] = ( 'bgpNextAdjacentAsNumber', 4, 'L' )
ipfix_id_to_info[129] = ( 'bgpPrevAdjacentAsNumber', 4, 'L' )
ipfix_id_to_info[130] = ( 'exporterIPv4Address', 4, 'L' )
ipfix_id_to_info[131] = ( 'exporterIPv6Address', 16, '16s' )
ipfix_id_to_info[132] = ( 'droppedOctetDeltaCount', 64, 'Q' )
ipfix_id_to_info[133] = ( 'droppedPacketDeltaCount', 64, 'Q' )
ipfix_id_to_info[134] = ( 'droppedOctetTotalCount', 64, 'Q' )
ipfix_id_to_info[135] = ( 'droppedPacketTotalCount', 64, 'Q' )

"""
      The reason for Flow termination.  The range of values includes the
      following:

      0x01: idle timeout
            The Flow was terminated because it was considered to be
            idle.

      0x02: active timeout
            The Flow was terminated for reporting purposes while it was
            still active, for example, after the maximum lifetime of
            unreported Flows was reached.

      0x03: end of Flow detected
            The Flow was terminated because the Metering Process
            detected signals indicating the end of the Flow, for
            example, the TCP FIN flag.

      0x04: forced end
            The Flow was terminated because of some external event, for
            example, a shutdown of the Metering Process initiated by a
            network management application.
      0x05: lack of resources
            The Flow was terminated because of lack of resources
            available to the Metering Process and/or the Exporting
            Process.
"""
ipfix_id_to_info[136] = ( 'flowEndReason', 1, 'B' )

ipfix_id_to_info[137] = ( 'commonPropertiesId', 8, 'Q' )
ipfix_id_to_info[138] = ( 'observationPointId', 4, 'L' )
ipfix_id_to_info[139] = ( 'icmpTypeCodeIPv6', 2, 'H' )
ipfix_id_to_info[140] = ( 'mplsTopLabelIPv6Address', 16, '16s' )
ipfix_id_to_info[141] = ( 'lineCardId', 4, 'L' )
ipfix_id_to_info[142] = ( 'portId', 4, 'L' )
ipfix_id_to_info[143] = ( 'meteringProcessId', 4, 'L' )
ipfix_id_to_info[144] = ( 'exportingProcessId', 4, 'L' )
ipfix_id_to_info[145] = ( 'templateId', 2, 'H' )
ipfix_id_to_info[146] = ( 'wlanChannelId', 1, 'B' )
ipfix_id_to_info[147] = ( 'wlanSSID', 32, '32s' )
ipfix_id_to_info[148] = ( 'flowId', 64, 'Q' )
ipfix_id_to_info[149] = ( 'observationDomainId', 4, 'L' )
ipfix_id_to_info[150] = ( 'flowStartSeconds', 4, 'L' )
ipfix_id_to_info[151] = ( 'flowEndSeconds', 4, 'L' )
ipfix_id_to_info[152] = ( 'flowStartMilliseconds', 8, 'Q' )
ipfix_id_to_info[153] = ( 'flowEndMilliseconds', 8, 'Q' )
ipfix_id_to_info[154] = ( 'flowStartMicroseconds', 8, 'Q' )
ipfix_id_to_info[155] = ( 'flowEndMicroseconds', 8, 'Q' )
ipfix_id_to_info[156] = ( 'flowStartNanoseconds', 8, 'Q' )
ipfix_id_to_info[157] = ( 'flowEndNanoseconds', 8, 'Q' )
ipfix_id_to_info[158] = ( 'flowStartDeltaMicroseconds', 4, 'L' )
ipfix_id_to_info[159] = ( 'flowEndDeltaMicroseconds', 4, 'L' )
ipfix_id_to_info[160] = ( 'systemInitTimeMilliseconds', 8, 'Q' )
ipfix_id_to_info[161] = ( 'flowDurationMilliseconds', 4, 'L' )
ipfix_id_to_info[162] = ( 'flowDurationMicroseconds', 4, 'L' )
ipfix_id_to_info[163] = ( 'observedFlowTotalCount', 8, 'Q' )
ipfix_id_to_info[164] = ( 'ignoredPacketTotalCount', 8, 'Q' )
ipfix_id_to_info[165] = ( 'ignoredOctetTotalCount', 8, 'Q' )
ipfix_id_to_info[166] = ( 'notSentFlowTotalCount', 8, 'Q' )
ipfix_id_to_info[167] = ( 'notSentPacketTotalCount', 8, 'Q' )
ipfix_id_to_info[168] = ( 'notSentOctetTotalCount', 8, 'Q' )
ipfix_id_to_info[169] = ( 'destinationIPv6Prefix', 1, 'B' )
ipfix_id_to_info[170] = ( 'sourceIPv6Prefix', 16, '16s' )
ipfix_id_to_info[171] = ( 'postOctetTotalCount', 64, 'Q' )
ipfix_id_to_info[172] = ( 'postPacketTotalCount', 64, 'Q' )
ipfix_id_to_info[173] = ( 'flowKeyIndicator', 64, 'Q' )
ipfix_id_to_info[174] = ( 'postMCastPacketTotalCount', 64, 'Q' )
ipfix_id_to_info[175] = ( 'postMCastOctetTotalCount', 64, 'Q' )
ipfix_id_to_info[176] = ( 'icmpTypeIPv4', 1, 'B' )
ipfix_id_to_info[177] = ( 'icmpCodeIPv4', 1, 'B' )
ipfix_id_to_info[178] = ( 'icmpTypeIPv6', 1, 'B' )
ipfix_id_to_info[179] = ( 'icmpCodeIPv6', 1, 'B' )
ipfix_id_to_info[180] = ( 'udpSourcePort', 2, 'H' )
ipfix_id_to_info[181] = ( 'udpDestinationPort', 2, 'H' )
ipfix_id_to_info[182] = ( 'tcpSourcePort', 2, 'H' )
ipfix_id_to_info[183] = ( 'tcpDestinationPort', 2, 'H' )
ipfix_id_to_info[184] = ( 'tcpSequenceNumber', 4, 'L' )
ipfix_id_to_info[185] = ( 'tcpAcknowledgementNumber', 4, 'L' )
ipfix_id_to_info[186] = ( 'tcpWindowSize', 2, 'H' )
ipfix_id_to_info[187] = ( 'tcpUrgentPointer', 2, 'H' )
ipfix_id_to_info[188] = ( 'tcpHeaderLength', 1, 'B' )
ipfix_id_to_info[189] = ( 'ipHeaderLength', 1, 'B' )
ipfix_id_to_info[190] = ( 'totalLengthIPv4', 2, 'H' )
ipfix_id_to_info[191] = ( 'payloadLengthIPv6', 2, 'H' )
ipfix_id_to_info[192] = ( 'ipTTL', 1, 'B' )
ipfix_id_to_info[193] = ( 'nextHeaderIPv6', 1, 'B' )
ipfix_id_to_info[194] = ( 'mplsPayloadLength', 4, 'L' )
ipfix_id_to_info[195] = ( 'ipDiffServCodePoint', 1, 'B' )
ipfix_id_to_info[196] = ( 'ipPrecedence', 1, 'B' )

"""
      Fragmentation properties indicated by flags in the IPv4 packet
      header or the IPv6 Fragment header, respectively.

      Bit 0:    (RS) Reserved.
                The value of this bit MUST be 0 until specified
                otherwise.

      Bit 1:    (DF) 0 = May Fragment,  1 = Don't Fragment.
                Corresponds to the value of the DF flag in the
                IPv4 header.  Will always be 0 for IPv6 unless
                a "don't fragment" feature is introduced to IPv6.

      Bit 2:    (MF) 0 = Last Fragment, 1 = More Fragments.
                Corresponds to the MF flag in the IPv4 header
                or to the M flag in the IPv6 Fragment header,
                respectively.  The value is 0 for IPv6 if there
                is no fragment header.

      Bits 3-7: (DC) Don't Care.
                The values of these bits are irrelevant.

           0   1   2   3   4   5   6   7
         +---+---+---+---+---+---+---+---+
         | R | D | M | D | D | D | D | D |
         | S | F | F | C | C | C | C | C |
         +---+---+---+---+---+---+---+---+
"""

ipfix_id_to_info[197] = ( 'fragmentFlags', 1, 'B' )

ipfix_id_to_info[198] = ( 'octetDeltaSumOfSquares', 8, 'Q' )
ipfix_id_to_info[199] = ( 'octetTotalSumOfSquares', 8, 'Q' )
ipfix_id_to_info[200] = ( 'mplsTopLabelTTL', 1, 'B' )
ipfix_id_to_info[201] = ( 'mplsLabelStackLength', 4, 'L' )
ipfix_id_to_info[202] = ( 'mplsLabelStackDepth', 4, 'L' )
ipfix_id_to_info[203] = ( 'mplsTopLabelExp', 1, 'B' )
ipfix_id_to_info[204] = ( 'ipPayloadLength', 4, 'L' )
ipfix_id_to_info[205] = ( 'udpMessageLength', 2, 'H' )

"""
          +------+------+------+------+------+------+------+------+
          | MCv4 | RES. | RES. |  T   |   IPv6 multicast scope    |
          +------+------+------+------+------+------+------+------+

          Bit  0:    set to 1 if IPv4 multicast
          Bits 1-2:  reserved for future use
          Bit  4:    set to value of T flag, if IPv6 multicast
          Bits 4-7:  set to value of multicast scope if IPv6 multicast
"""
ipfix_id_to_info[206] = ( 'isMulticast', 1, 'B' )

ipfix_id_to_info[207] = ( 'ipv4IHL', 1, 'B' )

"""
           0      1      2      3      4      5      6      7
       +------+------+------+------+------+------+------+------+
       | EOOL | NOP  | SEC  | LSR  |  TS  |E-SEC |CIPSO |  RR  | ...
       +------+------+------+------+------+------+------+------+

           8      9     10     11     12     13     14     15
       +------+------+------+------+------+------+------+------+
   ... | SID  | SSR  | ZSU  | MTUP | MTUR | FINN | VISA |ENCODE| ...
       +------+------+------+------+------+------+------+------+

          16     17     18     19     20     21     22     23
       +------+------+------+------+------+------+------+------+
   ... |IMITD | EIP  |  TR  |ADDEXT|RTRALT| SDB  |NSAPA | DPS  | ...
       +------+------+------+------+------+------+------+------+

          24     25     26     27     28     29     30     31
       +------+------+------+------+------+------+------+------+
   ... | UMP  |  QS  |   to be assigned by IANA  | EXP  |      |
       +------+------+------+------+------+------+------+------+

           Type   Option
       Bit Value  Name    Reference
       ---+-----+-------+------------------------------------
        0     0   EOOL    End of Options List, RFC 791
        1     1   NOP     No Operation, RFC 791
        2   130   SEC     Security, RFC 1108
        3   131   LSR     Loose Source Route, RFC 791
        4    68   TS      Time Stamp, RFC 791
        5   133   E-SEC   Extended Security, RFC 1108
        6   134   CIPSO   Commercial Security
        7     7   RR      Record Route, RFC 791
        8   136   SID     Stream ID, RFC 791
        9   137   SSR     Strict Source Route, RFC 791
       10    10   ZSU     Experimental Measurement
       11    11   MTUP    (obsoleted) MTU Probe, RFC 1191
       12    12   MTUR    (obsoleted) MTU Reply, RFC 1191
       13   205   FINN    Experimental Flow Control
       14   142   VISA    Experimental Access Control
       15    15   ENCODE
       16   144   IMITD   IMI Traffic Descriptor
       17   145   EIP     Extended Internet Protocol, RFC 1385
       18    82   TR      Traceroute, RFC 3193
       19   147   ADDEXT  Address Extension
       20   148   RTRALT  Router Alert, RFC 2113
       21   149   SDB     Selective Directed Broadcast
       22   150   NSAPA   NSAP Address
       23   151   DPS     Dynamic Packet State
       24   152   UMP     Upstream Multicast Pkt.
       25    25   QS      Quick-Start
       30    30   EXP     RFC3692-style Experiment
       30    94   EXP     RFC3692-style Experiment
       30   158   EXP     RFC3692-style Experiment
       30   222   EXP     RFC3692-style Experiment
       ...  ...   ...     Further options numbers
                          may be assigned by IANA
"""
ipfix_id_to_info[208] = ( 'ipv4Options', 4, 'L' )
ipfix_id_to_info[209] = ( 'tcpOptions', 8, 'Q' )
ipfix_id_to_info[214] = ( 'exportProtocolVersion', 1, 'B' )
ipfix_id_to_info[215] = ( 'exportTransportProtocol', 1, 'B' )
ipfix_id_to_info[243] = ( 'dot1qVlanId', 2, 'H' )
ipfix_id_to_info[245] = ( 'dot1qCustomerVlanId', 2, 'H' )
ipfix_id_to_info[256] = ( 'ethernetType', 2, 'H' )

ipff = namedtuple( 'IPFixFields', 'name len fmt id' )

# Now, convert the stuff from above to named tuples.  This allows
# us to reference items by field instead of by index.
# Note that while this might seem inefficient, it is done once
# at import time.  It does not matter.

ipfix_id_to_info = [ ipff._make( tuple( list(t)+[i] ) ) for (i,t) in
                        enumerate( ipfix_id_to_info ) ]

# And index by name.  Note that there is an id field after the
# conversion to the namedtuple.  Note this is a dict comprehension
# and does not run on python 2.6, the current default python on
# this box.  That took about an hour to figure out!

ipfix_name_to_info = { t.name: t
    for t in ipfix_id_to_info if t.name != 'RESERVED'}

# End.
