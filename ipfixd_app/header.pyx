"""
Cython module that provides routines for breaking up headers and
returning tuples.

Netflow headers are typically small and easy to take apart.  Why
use the overhead of Python struct since we are already using
cython anyhow?  Probably not a huge CPU savings, but not too
bad, either.

Note: this code is littered with hardcoded offsets and lengths.
If you change the field defs in the main code, you need to make
changes here, too.

Only routines for headers that occur in high frequency loops are
declared here.  For instance, template headers are not here.

Also, not everything is returned about the header.  Only
information we probably want/need.
"""

import cython

from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t
from libc.string cimport memcpy

cdef extern from "arpa/inet.h":
    uint32_t ntohl( uint32_t )
cdef extern from "arpa/inet.h":
    uint16_t ntohs( uint16_t )

cimport ipfixd_app.byte_mover

def netflow_version( uint8_t * buff ):
    """
    Returns the packet version.  This is always 2 bytes.
    """

    return( ntohs( (<uint16_t *>buff)[0] ) )

def v5_header_len():
    """
    Returns the length of the header.
    """

    return( 24 )

def v5_header( uint8_t * buff, ipfixd_app.byte_mover.ByteMoverNetflowV5 bm ):

    """
    This routine parses a Netflow version 5 header.  It also sets
    the properties used by a Version 5 byte_mover object.

    Args:
        buff: The input buffer.

    Returns:

        A tuple of:

        cnt: Number of data records
        flow_id: The flow id of the first data record

        We also set properties in the byte_mover.
    """

    cdef uint16_t version
    cdef uint16_t cnt
    cdef uint32_t xx_sysUpTimeDeltaMilliseconds
    cdef uint32_t xx_sysUpTime
    cdef uint32_t flowStartNanoseconds
    cdef uint32_t flow_id
    cdef uint32_t pad1

#    version = ntohs( (<uint16_t *>buff)[0] )
    buff += sizeof( version )
    cnt = ntohs( (<uint16_t *>buff)[0] )
    buff += sizeof( cnt )

    xx_sysUpTimeDeltaMilliseconds = ntohl( (<uint32_t *>buff)[0] )
    bm._sysUpTimeDeltaMilliseconds = xx_sysUpTimeDeltaMilliseconds
    buff += sizeof( xx_sysUpTimeDeltaMilliseconds )

    xx_sysUpTime = ntohl( (<uint32_t *>buff)[0] )
    bm._sysUpTime = xx_sysUpTime
    buff += sizeof( xx_sysUpTime )

#    flowStartNanoseconds = ntohl( (<uint32_t *>buff)[0] )
    buff += sizeof( flowStartNanoseconds )
    flow_id = ntohl( (<uint32_t *>buff)[0] )
    bm._flow_id = flow_id

    return( cnt, flow_id )

def v10_header_len():
    """
    Returns the length of the header.
    """

    return( 16 )

def v10_header( uint8_t * buff ):

    """
    This routine parses a version 10 header.

    Returns:

    A tuple of:

    version: 10
    packet_length: Total bytes in packet
    flow_start_seconds: Current secs since 0000 UTC 1970
    flow_id: The flow id of the first data flow record
    obs_domain_id: I dunno
    """

    cdef uint16_t version
    cdef uint16_t packet_length
    cdef uint32_t flow_start_seconds
    cdef uint32_t flow_id
    cdef uint32_t obs_domain_ud

    version = ntohs( (<uint16_t *>buff)[0] )
    buff += sizeof( version )
    packet_length = ntohs( (<uint16_t *>buff)[0] )
    buff += sizeof( packet_length )
    flow_start_seconds = ntohl( (<uint32_t *>buff)[0] )
    buff += sizeof( flow_start_seconds )
    flow_id = ntohl( (<uint32_t *>buff)[0] )
    buff += sizeof( flow_id )
    obs_domain_id = ntohl( (<uint32_t *>buff)[0] )

    return( version, packet_length, flow_start_seconds, flow_id,
        obs_domain_id )

def v10_set_header_len():
    """
    Returns the length of a set header.
    """
    return( 4 )

def v10_set_header( uint8_t * buff, offset=0 ):

    """
    Parses a v10 set header.

    Args:
        Buffer
    Returns:
        A tuple of:

        ( id, set_len )

        where set_len includes the header length.
    """

    cdef uint16_t set_id
    cdef uint16_t set_len

    buff += offset
    set_id = ntohs( (<uint16_t *>buff)[0] )
    buff += sizeof( set_id )
    set_len = ntohs( (<uint16_t *>buff)[0] )

    return( set_id, set_len )

# End.
