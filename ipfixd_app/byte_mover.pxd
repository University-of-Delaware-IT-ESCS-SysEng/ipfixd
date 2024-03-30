"""
This is cython definition file.  It needs to be cimported.
"""

import cython
from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t


cdef class ByteMover:

    """
    This class is used to move a series of bytes between an input
    and an output buffer.  It also contains support for a few
    hard coded moves related to cflowd.  Multiple input buffers
    can be passed as a single array.  Each piece of the input
    is processed seperately.  The size of the input and output
    buffers is defined so we can step through the memory, moving
    bytes as we go.  This results in far fewer Python to C calls,
    which are expensive.

    Note the method byte_mover is a cpdef, which means it can
    be called directly from Python (with argument work), or
    efficiently from C.  So, we can easily call it from the more
    specialized byte_mover routines such as byte_mover_cflowd.
    """

#
# Save the offset arrays for moving data and some summary
# information about the arrays.
#

    cdef unsigned int _in_offsets[ 100 ]
    cdef unsigned int _out_offsets[ 100 ]
    cdef unsigned int _num_offsets

    cdef unsigned int _check_for_zero[ 100 ]
    cdef unsigned int _num_check_for_zero

    cdef unsigned int _in_offset
    cdef unsigned int _in_len       # Size of an input buffer
    cdef unsigned int _out_len      # Size of an output buffer
    cdef unsigned int _out_offset   # Offset into output buffer
    cdef unsigned int _cnt          # The number of input buffers to process
    cdef unsigned int max_in_offset
    cdef unsigned int max_out_offset
    cdef uint32_t _address           # Needed for cflowd
    cdef uint32_t _flow_id           # Needed for cflowd

# Offsets into cflowd buffer.

    cdef unsigned int _cflowd_offset_to_flowStartSeconds
    cdef unsigned int _cflowd_offset_to_flowEndSeconds
    cdef unsigned int _cflowd_offset_to_flowId
    cdef unsigned int _cflowd_offset_to_exporterIPv4Address

    cdef object _template


    cdef int _byte_mover( self,
        uint8_t * in_buffer,
        uint8_t * out_buffer ) noexcept nogil


cdef class ByteMoverNetflowV5( ByteMover ):

    """
    This class is used to handle NetFlow V5.
    """

    cdef uint32_t _sysUpTimeDeltaMilliseconds
    cdef uint32_t _sysUpTime

    cdef unsigned int _offset_to_flowStartSysUpTime
    cdef unsigned int _offset_to_flowEndSysUpTime

    cpdef int byte_mover( self,
        uint8_t * in_buffer,
        uint8_t * out_buffer )

cdef class ByteMoverMilliSeconds( ByteMover ):

    """
    This class is used to handle cases where the flow start and
    stop times are given in mlliseconds.  Call the appropriate
    routines to provide the offsets to the timestamps.

    You must all make all the required calls for ByteMover itself.
    """

    cdef unsigned int _offset_to_flowStartMilliseconds
    cdef unsigned int _offset_to_flowEndMilliseconds

    cpdef int byte_mover( self,
        uint8_t * in_buffer,
        uint8_t * out_buffer )

# End.
