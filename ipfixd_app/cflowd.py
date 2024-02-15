import sys
import struct
import socket
from collections import namedtuple
import pyximport; pyximport.install()
import ipfixd_app.byte_mover

import ipfixd_app.netflow_v5
import ipfixd_app.netflow_v10
import ipfixd_app.header
import ipfixd_app.ipfix
import ipfixd_app.util
from ipfixd_app.ipfixd_log import log
from ipfixd_app.packet import t_address, t_port, t_p, t_p_len
import collections

log_datarec = False
log_unchanged_templates = False
log_missing_full = False

"""
This is the original C struct for a cflowd record.

typedef struct {
    index_type  index;          /* 00. Index from UDP packet */
    ipv4addr_t  router;         /* 04. Router reporting information */
    ipv4addr_t  srcIpAddr;      /* 08. Source of flow */
    ipv4addr_t  dstIpAddr;      /* 12. Dest flow */
    uint16_t    inputIfIndex;   /* 16. Router interface index */
    uint16_t    outputIfIndex;  /* 18. */
    uint16_t    srcPort;        /* 20. */
    uint16_t    dstPort;        /* 22. */
    uint32_t    pkts;           /* 24. */
    uint32_t    bytes;          /* 28. */
    ipv4addr_t  ipNextHop;      /* 32. */
    uint32_t    startTime;      /* 36. */
    uint32_t    endTime;        /* 40. */
    uint8_t     protocol;       /* 44. */
    uint8_t     tos;            /* 45. Protocol type of service */
    uint16_t    srcAs;          /* 46. Autonomous system numbers */
    uint16_t    dstAs;          /* 48. */
    uint8_t     srcMaskLen;     /* 50. */
    uint8_t     dstMaskLen;     /* 51. */
    uint8_t     tcpFlags;       /* 52. */
} flow_t;

#define FLOW_LEN 55
"""

# Construct a basic set of fields for a template record that will be
# used to create a cflowd record.  Use the ipfix names for the objects
# in the cflowd record.  We will pull these from the netflow v5
# named tuple, and possibly augment with data from the netflow v5 header.

cflowd_field_list = [
    [ 'flowId', 4 ],
    [ 'exporterIPv4Address', 4 ],
    [ 'sourceIPv4Address', 4 ],
    [ 'destinationIPv4Address', 4 ],
    [ 'ingressInterface', 2 ],
    [ 'egressInterface', 2 ],
    [ 'sourceTransportPort', 2 ],
    [ 'destinationTransportPort', 2 ],
    [ 'packetDeltaCount', 4 ],
    [ 'octetDeltaCount', 4 ],
    [ 'ipNextHopIPv4Address', 4 ],
    [ 'flowStartSeconds', 4 ],
    [ 'flowEndSeconds', 4 ],
    [ 'protocolIdentifier', 1 ],
    [ 'ipClassOfService', 1 ],
    [ 'bgpSourceAsNumber', 2 ],
    [ 'bgpDestinationAsNumber', 2 ],
    [ 'sourceIPv4PrefixLength', 1 ],
    [ 'destinationIPv4PrefixLength', 1 ],
    [ 'tcpControlBits', 1 ],
    [ 'paddingOctets', 2 ]
]

"""
cflowd_struct: A Struct that maps the binary struct of a cflowd item.
cflowd_keys: Field name to item index for pack/unpack of a cflowd item
"""

(cflowd_struct, cflowd_keys) = ipfixd_app.util.make_pack_items(
                    cflowd_field_list, network_byte_order=False )

"""
netflow_v5_header_struct: A Struct that maps the binary struct of a
    NetFlow V5 header.
netflow_v5_header_keys: Field name to item index for pack/unpack of a
    NetFlow V5 header.
"""

(netflow_v5_header_struct, netflow_v5_header_keys) = (
    ipfixd_app.util.make_pack_items(
        ipfixd_app.netflow_v5.netflow_v5_header_list  ))

"""
netflow_v5_struct: A Struct that maps the binary struct of a
    NetFlow V5 item.
netflow_v5_keys: Field name to item index for pack/unpack of a
    NetFlow V5 item.
"""

(netflow_v5_struct, netflow_v5_keys) = (
    ipfixd_app.util.make_pack_items( ipfixd_app.netflow_v5.netflow_v5_list  ))

#
# Byte mover class object.  Also, save some indexes into an unpacked
# header.
#

netflow_v5_to_cflowd_byte_mover = 1     # Placeholder name

_header_cnt_index = netflow_v5_header_keys[ 'xx_cnt' ]
_flow_id_index = netflow_v5_header_keys[ 'flowId' ]
_sysUpTimeDeltaMilliseconds_index = (
        netflow_v5_header_keys[ 'xx_sysUpTimeDeltaMilliseconds' ] )
_sysUpTime_index = (
        netflow_v5_header_keys[ 'xx_sysUpTime' ] )

"""
Keeps track of the last netflow v5 id found.  Indexed by sending
IP and server port, as a tuple.
"""

netflow_v5_flow_ids = {}

"""
Similar to netflow_v5_flow_ids.  Different key.
"""

netflow_v10_flow_ids = {}

"""
netflow_v10_header_struct: A Struct that maps the binary struct of a
    NetFlow V10 header.
newflow_v10_header_keys: Field name to item index for pack/unpack of a
    NetFlow V10 header.
"""

(netflow_v10_header_struct, netflow_v10_header_keys) = (
    ipfixd_app.util.make_pack_items(
        ipfixd_app.netflow_v10.netflow_v10_header_list  ))

#
# Get the indexes for some fields we want to reference
# quickly.
#

_v10_header_flow_id = netflow_v10_header_keys[ 'flowId' ]
_v10_header_len = netflow_v10_header_keys[ 'xx_length' ]
_v10_header_obs_domain_id = netflow_v10_header_keys[ 'xx_obs_domain_id' ]

#
# For a set of records in an ipfix packet.
#

(netflow_v10_set_header_struct, netflow_v10_set_header_keys) = (
    ipfixd_app.util.make_pack_items(
        ipfixd_app.netflow_v10.netflow_v10_set_header_list  ))

_v10_set_header_id = netflow_v10_set_header_keys[ 'xx_id' ]
_v10_set_header_setlen = netflow_v10_set_header_keys[ 'xx_len' ]

#
# For a template in a set.  A template consists of the
# header followed by the fields.
#

(netflow_v10_template_header_struct, netflow_v10_template_header_keys) = (
    ipfixd_app.util.make_pack_items(
        ipfixd_app.netflow_v10.netflow_v10_template_header_list  ))

_v10_template_header_id = netflow_v10_template_header_keys[ 'xx_id' ]
_v10_template_header_fcnt = netflow_v10_template_header_keys[ 'xx_field_cnt' ]

(netflow_v10_field_struct, netflow_v10_field_keys) = (
    ipfixd_app.util.make_pack_items(
        ipfixd_app.netflow_v10.netflow_v10_field_list ))
_v10_field_id = netflow_v10_field_keys[ 'xx_id' ]
_v10_field_len = netflow_v10_field_keys[ 'xx_len' ]

#
# And options template.  An options template consists
# of the header, fields that define the scope that
# data emitted using this template applies to, followed
# by the actual data fields.  Data fields and scope fields
# have the same format.
#

(netflow_v10_options_template_header_struct,
    netflow_v10_options_template_header_keys) = (
        ipfixd_app.util.make_pack_items(
            ipfixd_app.netflow_v10.netflow_v10_options_template_header_list  ))

_v10_options_template_header_id = (
    netflow_v10_options_template_header_keys[ 'xx_id' ] )
_v10_options_template_header_fcnt = (
    netflow_v10_options_template_header_keys[ 'xx_field_cnt' ] )
_v10_options_template_header_sfcnt = (
    netflow_v10_options_template_header_keys[ 'xx_scope_field_cnt' ] )

"""
Define the templates dict.  The key is a tuple of ip-address, server-port,
and template id (an int).  The value is 

    {
        'the_struct': class struct.Struct
        'byte_mover': ByteMover object for the template
        'template_bytes': The actual bytes that
            define the template.  We check these
            and omit processing if we've seen the
            template before.
        <and many more other fun fields.!!>
        <If you need it, add it!>
    }
"""

templates = {}
listed_templates = {}       # An error message about template has been output

def set_cflowd_log_options( cmdparse ):

    """
    Copies some logging options into the module.
    """

    global log_datarec
    global log_unchanged_templates
    global log_missing_full

    log_datarec = cmdparse.log_datarec
    log_unchanged_templates = cmdparse.log_unchanged_templates
    log_missing_full = cmdparse.log_missing_full

def netflow_v5_init( netflow_v5_header_keys, template_keys ):

    """
    Initializes some of the data structures that would have been
    inconvienent to init at import time.  For instance, the log()
    routine would not have been available to log errors.
    """

    global netflow_v5_to_cflowd_byte_mover

    ( in_offsets, out_offsets, in_data, out_data, check_for_zero ) = (
        ipfixd_app.util.make_byte_moves(
            netflow_v5_struct, netflow_v5_keys, cflowd_struct, cflowd_keys ))

    netflow_v5_to_cflowd_byte_mover = ipfixd_app.byte_mover.ByteMoverNetflowV5(
        in_offsets, out_offsets, check_for_zero )

    netflow_v5_to_cflowd_byte_mover.in_len = netflow_v5_struct.size
    netflow_v5_to_cflowd_byte_mover.out_len = cflowd_struct.size
    netflow_v5_to_cflowd_byte_mover.in_offset = netflow_v5_header_struct.size

    netflow_v5_to_cflowd_byte_mover.cflowd_offset_to_flowStartSeconds = (
        out_data[ 'flowStartSeconds' ][ 'byte_offset' ] )
    netflow_v5_to_cflowd_byte_mover.cflowd_offset_to_flowEndSeconds = (
        out_data[ 'flowEndSeconds' ][ 'byte_offset' ] )

    netflow_v5_to_cflowd_byte_mover.offset_to_flowStartSysUpTime = (
        in_data[ 'flowStartSysUpTime' ][ 'byte_offset' ] )
    netflow_v5_to_cflowd_byte_mover.offset_to_flowEndSysUpTime = (
        in_data[ 'flowEndSysUpTime' ][ 'byte_offset' ] )

    netflow_v5_to_cflowd_byte_mover.cflowd_offset_to_flowId = (
        out_data[ 'flowId' ][ 'byte_offset' ] )
    netflow_v5_to_cflowd_byte_mover.cflowd_offset_to_exporterIPv4Address = (
        out_data[ 'exporterIPv4Address' ][ 'byte_offset' ] )

    log().info( 'INFO: NetFlow V5 ByteMover: %s' %
            str(netflow_v5_to_cflowd_byte_mover) )

def null_cvt_rtn( cflowd, ipfix, address, port, buff ):

    """
    Null routine.  Returns buff.  Does not change it in
    any way.

    Args:
        Standard
    Returns:
        buff
    """

    return( buff )

def null_rtn( *args ):
    pass

def v5_get_info( t, flow_info ):

    """
    This routine either creates the info stucture for the flow
    or returns it.

    We can avoid redoing some of the messy address conversion code
    if we stash it along with the expected_flow_id information.
    Some things should be thread local so we can avoid possibly
    needing a mutex should Python change how it works or we
    use an implementation that does not have a global lock.
    Are packet threads unique to an address, port combination?
    I need to think on that.  Same with templates in ipfix.
    """

    ( cnt, flow_id ) = flow_info

    k = tuple( [ t[ t_address ][0], t[ t_port ] ] )
    if k in netflow_v5_flow_ids:
        info = netflow_v5_flow_ids[ k ]         # Mutex!!
    else:
        a=socket.inet_pton( socket.AF_INET, t[t_address][0] )
        address_int = (a[0]<<24)+(a[1]<<16)+(a[2]<<8)+a[3]
        info = netflow_v5_flow_ids[ k ] = {}    # Mutex!!
        info[ 'address_int' ] = address_int
        info[ 'expected_flow_id' ] = flow_id
        netflow_v5_to_cflowd_byte_mover.address = address_int

    return( info )
    
def v5_handle_expected_flow_id( t, flow_info, info ):

    """
    This routine looks up the expected flow id and compares it to
    what we received.  Issues an error if there is a gap.  Updates
    the next expected flow id.

    Args:
        t: Standard tuple.  See t_ indexes.
        flow_info: A tuple consisting of cnt and flow_id.
        info: Info dict for the stream of netflow
    """

    ( cnt, flow_id ) = flow_info

#
#

    expected_flow_id = info[ 'expected_flow_id' ]

    if log_missing_full:
        info[ 'expected_flow_id' ] = flow_id + cnt
        if flow_id != expected_flow_id and flow_id > expected_flow_id:
            log().error( 'ERROR: %s:%d - missing flows, expected %d, '
                'got %d, lost %d.' % ( 
                    t[ t_address ][0], t[ t_port ], expected_flow_id,
                              flow_id, flow_id - expected_flow_id))

def netflow_v5_to_cflowd( cflowd, ipfix, t ):

    """
    Converts a complete NetFlow V5 packet to a buffer of cflowd records.

    If cflowd is False, then we don't process anything.
    If ipfix is True, then we just return the input packet

    Args:
        cflowd: Return cflowd data
        ipfix: Return ipfix data
        t: Tuple in standard format.  See the t_ constants in packet.

    Returns:
        A buffer containing cflowd records.
    """

    buff = t[ t_p ]
    buff_len = t[ t_p_len ]

    ret = [ [ None, -1], [ None, buff ] ]

    if not cflowd:
        return( ret[ 0 ][ cflowd ], ret[ 1 ][ ipfix ] )

    offset = ipfixd_app.header.v5_header_len()
    if buff_len < offset:
        raise ValueError

# The header parse will set properties in the byte_mover automatically.

    flow_info = ipfixd_app.header.v5_header( buff,
                                netflow_v5_to_cflowd_byte_mover )
    netflow_v5_to_cflowd_byte_mover.cnt = cnt = flow_info[0]

    if offset + (cnt * netflow_v5_struct.size) > buff_len:
        raise ValueError

    cflowd_buff=bytearray( cnt * cflowd_struct.size )   # Make cflowd buffer
    ret[ 0 ][ 1 ] = cflowd_buff                         # For returns

    info = v5_get_info( t, flow_info )
    v5_handle_expected_flow_id( t, flow_info, info )
    if netflow_v5_to_cflowd_byte_mover.byte_mover(buff, cflowd_buff):
        log().error( 'ERROR: Unexpected non-zero byte in Netflow V5' )

    return( ret[ 0 ][ cflowd ], ret[ 1 ][ ipfix ] )

def v10_get_info( key, flow_id, set_s, set_e ):

    """
    This routine locates the template.  If the template is cflowd
    compatable, then it checks to see if the flow we are receiving
    is the expected flow.  If not, an error message is logged and
    processing continues.

    The byte_mover is located in the template and various setups
    are made.

    Args:
        key: The key used to index the template and last flow information.
            Item zero in the iterable is the address.
        flow_id: The flow_id parsed from the header
        set_s: Starting byte index of the record set
        set_e: Slice style ending byte of the record set

    Returns:
        The byte_mover object associated with the template.
        This object has nothing to do with last flow info, but
        we do need to make changes to it here, so we might as
        well return the object since the caller will need it too.
    """

    try:
        template = templates[ key ]
    except KeyError:
        if key not in listed_templates:
            log().error( 'ERROR: Template %s not yet defined.' %
                str(key) )
            listed_templates[ key ] = 1
        return( None )

    if not template[ 'cflowd_compat' ]:
        return( None )

    try:                                            # Expected flow id
        info = template[ 'last_flow_info' ]
        expected_flow_id = info[ 'expected_flow_id' ]
        address_int = info[ 'address_int' ]

        if log_missing_full:
            if flow_id != expected_flow_id and flow_id > expected_flow_id:
                log().error( 'ERROR: %s - missing flows, '
                    'expected %d, '
                    'got %d, lost %d.' % ( str(key), expected_flow_id,
                                flow_id, flow_id - expected_flow_id))
    except KeyError:
        info = template[ 'last_flow_info' ] = {}
        a=socket.inet_pton( socket.AF_INET, key[0][0] )
        address_int = (a[0]<<24)+(a[1]<<16)+(a[2]<<8)+a[3]
        info[ 'address_int' ] = address_int

    bm = template[ 'byte_mover' ]           # Get template's ByteMover
    bm.address = address_int                # Set the router address
    bm.flow_id = flow_id                    # Set the base flow_id
    bm.in_offset = set_s                    # Offset to input
    bm.cnt = cnt = (set_e - set_s) // bm.in_len # # of input records
    info[ 'expected_flow_id' ] = flow_id + cnt

    return( bm )

def netflow_v10_to_cflowd( cflowd, ipfix, t ):

    """
    Converts a complete NetFlow V10 packet to a buffer of cflowd
    records.

    A proper implementation of ipfix needs to know if the
    templates have been written to the current file or not.
    If not, then the current templates need to be written.
    We have not implemented this yet.

    Args:
        cflowd: If True, output cflowd
        ipfix: If True, output ipfix records
        t: Standard tuple.  See t_ constants.

    Returns:
        A buffer containing cflowd records.

    Globals:
        listed_templates
        templates
    """

    buff = t[ t_p ]
    buff_len = t[ t_p_len ]

    if ipfix:
        ipfix_buff = bytearray( buff_len )
        ipfix_buff_offset = 0
    else:
        ipfix_buff = None

    offset = ipfixd_app.header.v10_header_len()
    if buff_len < offset:
        raise ValueError

    ( version, header_buff_len, flow_start_seconds, flow_id, obs_id ) = (
            ipfixd_app.header.v10_header( buff ) )
    if header_buff_len > buff_len:
        log().error( 'ERROR: packet declared length longer than buffer: '
            '%d > %d' % ( header_buff_len, buff_len ) )
        return( None, None )

    cflowd_buff=bytearray( buff_len * 10 )   # Won't need more than this?
    cflowd_len = cflowd_struct.size
    cflowd_buff_offset = 0
    shl = ipfixd_app.header.v10_set_header_len()

    while offset < buff_len:
        if buff_len < offset + shl:
            raise ValueError

        ( set_id, set_len ) = ipfixd_app.header.v10_set_header( buff, offset )
        
        if offset + set_len > buff_len:
            raise ValueError
        
        set_s = offset+shl
        set_e = offset + set_len    # Set length includes set header

        if set_id > 255:
            bm = v10_get_info( 
                tuple( [ t[ t_address ], t[ t_port ], obs_id, set_id ] ),
                flow_id, set_s, set_e)
            if not bm:                              # Unknown or incompatable
                offset += set_len
                continue
            bm.out_offset = cflowd_buff_offset      # Offset to output

            overflow = bm.byte_mover( buff, cflowd_buff )   # Moves the bytes
            if overflow:
                ipfixd_app.util.find_non_zero_bytes( bm.template, buff )
            cflowd_buff_offset += cflowd_len * bm.cnt

            if ipfix:
                ipfix_buff[ipfix_buff_offset:ipfix_buff_offset+(set_e-set_s)]=(
                    buff[ set_s:set_e ] )
                ipfix_buff_offset += set_e-set_s

        elif set_id == 2:
            new_template = v10_template_set(t[ t_address ],
                                        t[ t_port ], obs_id, buff, set_s, set_e)

            if ipfix and new_template:
                ipfix_buff[ipfix_buff_offset:ipfix_buff_offset+(set_e-set_s)]=(
                    buff[ set_s:set_e ] )
                ipfix_buff_offset += set_e-set_s
        elif set_id == 3:
            new_template = v10_options_template_set(t[ t_address ],
                                        t[ t_port ], obs_id, buff, set_s, set_e)
            if ipfix and new_template:
                ipfix_buff[ipfix_buff_offset:ipfix_buff_offset+(set_e-set_s)]=(
                    buff[ set_s:set_e ] )
                ipfix_buff_offset += set_e-set_s
        offset += set_len

    cflowd_buff[ cflowd_buff_offset: ] = []         # Truncate buffer

    return( cflowd_buff, ipfix_buff )

def check_for_new_template( address, port, obs_id, header_struct,
        buff, start, end ):

    """
    This routine checks to see if a template is new.  We keep a copy
    of the entire template record so we can tell if we've seen it
    before.

    Padding exists and MUST BE zero according to RFC7011.
    However, it appears that we get non-zero padding.  This means
    we have to spin through the fields because field descriptors
    are variable size.  Too bad Juniper couldn't manage to not
    leak data.  Maybe it's exploitable!!

    Args:
        address: Source address
        port: Receiving port
        obs_id: Observation Domain ID
        header_struct: The structure that can unpack the header
        buff: Buffer containing the input
        start: Start of the slice containing all the set's data
        end: End of the slice containing all the set's data
                * Does not include the set header

    Returns:
        The template we are using in dict form.  Some useful keys are:

            new: Is the template new?
            header: Template header tuple
            key: The key we used to look up the template
            id: The template id
    """

    global templates                # Not strictly needed
    global log_unchanged_templates  # Not strictly needed

    template_header = header_struct.unpack_from( buff, offset=start )

# We make use of the fact that the template id is always the first
# object.

    template_id = template_header[ 0 ]
    template_key = tuple( [ address, port, obs_id, template_id ] )
    try:
        template = templates[ template_key ]        # MUTEX
        template[ 'new' ] = False
    except KeyError:
        template = templates[ template_key ] = {    # MUTUX
                'key': template_key,
                'header': template_header,
                'id': template_id,
                'new': True }

    offset = start + header_struct.size
    flen = netflow_v10_field_struct.size

# This could probably be optimized.  Is it worth it?  I don't think so.

    while (offset + flen) <= end:
        id = netflow_v10_field_struct.unpack_from( buff, offset=offset )[0]
        offset += flen
        if (id >= 0x1000) and ((offset + 4) <= end):
            offset += 4

    real_end = offset

# Save the complete bytes that are used to make a template.

    try:
        template_bytes = template[ 'template_bytes' ]
        if template_bytes == buff[ start:real_end ]:
            if log_unchanged_templates:
                log().info('INFO: template key %s is unchanged' %
                    str(template_key))
            return( template )
    except KeyError:
        pass

    template[ 'header' ] = template_header
    template[ 'new' ] = True
    template[ 'template_bytes' ] = buff[ start:real_end ]

    return( template )

def v10_template_set( address, port, obs_id, buff, offset, end ):

    """
    Process a template set.  If the template has already been seen,
    then return False.

    Args:
        address: The sending address (ip and port as a tuple)
        port: The port we received the packet on
        obs_id: Observation Domain ID
        buff: The raw input buffer.
        offset: Slice offset to start of template.
        end: End of template set + plus 1 (standard slice end)

    Global:
        Adds a template to the templates dict.

    Returns:
        True: new template
        False: duplicate template
    """

    template = check_for_new_template( address, port, obs_id,
            netflow_v10_template_header_struct, buff, offset, end )
    if not template[ 'new' ]:
        return( False )

    template_header = template[ 'header' ]
    template_key = template[ 'key' ]
    cnt = template_header[ _v10_template_header_fcnt ]
    flen = netflow_v10_field_struct.size
    offset += netflow_v10_template_header_struct.size

    log().info( 'INFO: Process a template, key=%s,field cnt=%d.' %
        ( str(template[ 'key' ]), cnt ) )

    fields = '!'
    field_list = []

    data_offset = 0
    for i in range( 0, cnt ):
        if (offset >= end):
            raise ValueError

        field = netflow_v10_field_struct.unpack_from( buff, offset=offset )
        id = field[ _v10_field_id ]
        l = field[ _v10_field_len ]

        if field[ _v10_field_id ] > 0x1000:
            en = struct.unpack_from( '!L', buff, offset=offset + flen )
            offset += 4
        else:
            en = -1

        offset += flen

        try:
            fd = ipfixd_app.ipfix.ipfix_id_to_info[id]
        except IndexError:
            fd = ( 'RESERVED', l, '%ds' % l )

        log().info( 'INFO:     field=%s(%d), offset=%d, len=%d, en=%d' %
            ( fd[0], id, data_offset, l, en ) )
        field_list.append( [ fd[0], l, data_offset ] )
        data_offset += l

    template[ 'field_list' ] = field_list

    (the_struct, the_keys) = ipfixd_app.util.make_pack_items( field_list )
    ( in_offsets, out_offsets, in_data, out_data, check_for_zero ) = (
        ipfixd_app.util.make_byte_moves(
            the_struct, the_keys, cflowd_struct, cflowd_keys ))

    if ('flowStartMilliseconds' in the_keys and
        'flowEndMilliseconds' in the_keys ):
        bm = template[ 'byte_mover' ] = (
            ipfixd_app.byte_mover.ByteMoverMilliSeconds(
                                in_offsets, out_offsets, check_for_zero )
            )

        bm.template = template
        bm.offset_to_flowStartMilliseconds = (
            in_data[ 'flowStartMilliseconds' ][ 'byte_offset' ])
        bm.offset_to_flowEndMilliseconds = (
            in_data[ 'flowEndMilliseconds' ][ 'byte_offset' ])
        bm.in_len = the_struct.size
        bm.out_len = cflowd_struct.size

        bm.cflowd_offset_to_flowStartSeconds = (
            out_data[ 'flowStartSeconds' ][ 'byte_offset' ] )
        bm.cflowd_offset_to_flowEndSeconds = (
            out_data[ 'flowEndSeconds' ][ 'byte_offset' ] )
        bm.cflowd_offset_to_flowId = out_data[ 'flowId' ][ 'byte_offset' ]
        bm.cflowd_offset_to_exporterIPv4Address = (
            out_data[ 'exporterIPv4Address' ][ 'byte_offset' ] )
        cflowd_compat = True
    else:
        log().error('ERROR: no compatable template to cflowd conversion found.')
        cflowd_compat = False

    template[ 'the_struct' ] = the_struct
    template[ 'cflowd_compat' ] = cflowd_compat

    log().info( 'INFO: Ending template, key=%s, data size=%d, fields=%s, '
        'cflowd_compat=%s' % ( str(template_key), the_struct.size,
                                    the_struct.format, cflowd_compat ) )
    if cflowd_compat:
        log().info('INFO: ByteMover for %s: %s' %
                                (str(template['key']), str(bm)))

    return( True )

def v10_options_template_set(address, port, obs_id, buff, offset, end):

    """
    Process an options template set.

    Args:
        address: The sending address (ip and port as a tuple)
        port: The port we received the packet on
        obs_id: Observation Domain ID
        buff: The raw input buffer.
        offset: Slice offset to start of template.
        end: End of template set + plus 1 (standard slice end)

    Global:
        Adds a template to the templates dict.

    Returns:
        True: New template
        False: We've seen this template before
    """

    template = check_for_new_template( address, port, obs_id,
            netflow_v10_options_template_header_struct, buff, offset, end )
    if not template[ 'new' ]:
        return( False )

    template_header = template[ 'header' ]
    template_key = template[ 'key' ]
    cnt = template_header[ _v10_options_template_header_fcnt ]
    scnt = template_header[ _v10_options_template_header_sfcnt ]
    offset += netflow_v10_options_template_header_struct.size
    flen = netflow_v10_field_struct.size

    log().info( 'INFO: Process an options template, '
        'key=%s,field cnt=%d,scnt=%d.' % ( str(template_key), cnt, scnt ) )

    fields = '!'

    field_list = []

    data_offset = 0
    for i in range( 0, cnt ):
        if (offset >= end):
            raise ValueError

        field = netflow_v10_field_struct.unpack_from( buff, offset=offset )
        id = field[ _v10_field_id ]
        l = field[ _v10_field_len ]

        if field[ _v10_field_id ] > 0x1000:
            en = struct.unpack_from( '!L', buff, offset=offset + flen )
            offset += 4
        else:
            en = -1

        offset += flen

        try:
            fd = ipfixd_app.ipfix.ipfix_id_to_info[id]
        except IndexError:
            fd = ( 'RESERVED', l, '%ds' % l )

        if i < scnt:
            scope='SCOPE: '
        else:
            scope=''

        log().info( 'INFO:     %sfield=%s(%d), offset=%d, len=%d, en=%d' %
            ( scope, fd[0], id, data_offset, l, en ))
        field_list.append( [ fd[0], l, data_offset ] )
        data_offset += l

    template[ 'field_list' ] = field_list

    (the_struct, the_keys) = ipfixd_app.util.make_pack_items( field_list )

    the_keys[ 'flowId' ] = len( the_keys )
    the_keys[ 'exporterIPv4Address' ] = len( the_keys )

    """
    try:
        template_to_cflowd_list = netflow_v10_init(
            netflow_v10_header_keys, the_keys )
    except KeyError as e:
        log().error( 'ERROR: issue with %s' % e )
    """

    template[ 'the_struct' ] = the_struct
    template[ 'cflowd_compat' ] = False

    log().info( 'INFO: Ending options template, key=%s, '
        'data size=%d, fields=%s, cflowd_compat=%s' %
        ( str(template_key), the_struct.size, the_struct.format, False ) )

    return( True )

if __name__ == '__main__':
    ipfixd_app.ipfixd_log.set_logging( None )
    log().info( 'test' )

    netflow_v5_init( netflow_v5_header_keys, netflow_v5_keys )

    print( 'cflowd size = %d, format = %s' %
        (cflowd_struct.size, cflowd_struct.format ) )
    print( 'netflow v5 header size = %d, format = %s' %
        (netflow_v5_header_struct.size, netflow_v5_header_struct.format ) )
    print( 'netflow v5 size = %d, format = %s' %
        (netflow_v5_struct.size, netflow_v5_struct.format ) )

# TODO:
# Make a namedtuple for netflow v5 header and packet, set values,
# pack, and then unpack cflowd.

    b = bytearray( 24+110)
    struct.pack_into( '!HHLLLLxxxxL', b, 0, 5, 2, 0, 0, 0, 500,
        0x01020304 )
    cfd = netflow_v5_to_cflowd( ( '128.175.2.33', 33450 ), b )

    cfd_names=' '.join( [ f[0] for f in cflowd_field_list
                                            if f[0]!='paddingOctets'] )
    cfd_t = namedtuple( 'CFlowd', cfd_names )
    a_cfd = cfd_t._make( cflowd_struct.unpack_from( cfd ) )
    print( a_cfd )

# End.
