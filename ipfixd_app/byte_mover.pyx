"""
This is cython module.  It needs to be converted to C and compiled before use.
"""

import cython

cimport byte_mover

from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t
from libc.string cimport memcpy

cdef extern from "arpa/inet.h":
    uint16_t ntohs( uint16_t ) nogil
    uint32_t ntohl( uint32_t ) nogil

cdef class ByteMover:

    """
    This class is used to move a series of bytes between an input
    and an output buffer.  It also contains suppor for a few
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

    property in_offsets:
        """The list of offsets into the input buffer."""
        def __get__( self ):
            cdef unsigned int i
            return([ self._in_offsets[i] for i in range( self._num_offsets )])

    property out_offsets:
        """The list of offsets into the output buffer."""
        def __get__( self ):
            cdef unsigned int i
            return([ self._out_offsets[i] for i in range( self._num_offsets )])

#
# Save the offset array for bytes to check in input buffer that
# shoud be zero.  If they are not, then we are likely overflowing
# when trying to move a larger field to a smaller field.  This
# happens when we have 8 byte octet counts in ipfix, and a four byte
# field in cflowd, for instance.
#

    property check_for_zero:
        """The list of offsets into the input buffer that should be zero."""
        def __get__( self ):
            cdef unsigned int i
            return([ self._check_for_zero[i] for i in
                                range( self._num_check_for_zero )])

        def __set__( self, check_for_zero ):
            if len( check_for_zero ) > 100:
                raise( ValueError( 'Number of check_for_zero > 100' ))
            cdef unsigned int i
            cdef unsigned int b
            for ( i, b ) in enumerate( check_for_zero ):
                self._check_for_zero[ i ] = b
            self._num_check_for_zero = len( check_for_zero )

#
# Byte mover can process multiple input buffers in a single call.
# Therefore, we need to define the offset to the input and the
# size of the input and output buffers.  Not the overall size,
# but the size of each objects.
#

    property in_offset:

        """
        Offset to data in the buffer.  Useful for skipping headers.
        """

        def __get__(self):
            return( self._in_offset )
        def __set__(self, value):
            self._in_offset = value

    property in_len:
        """
        Sets the size of the input buffer.
        """

        def __get__( self ):
            return( self._in_len )
        def __set__( self, value ):
            self._in_len = value

    property out_len:
        """
        Sets the size of the output buffer.
        """

        def __get__( self ):
            return( self._out_len )
        def __set__( self, value ):
            self._out_len = value

    property out_offset:
        """
        Sets the offet into the output buffer.  Useful for
        skipping headers or prior data.
        """

        def __get__( self ):
            return( self._out_offset )
        def __set__( self, value ):
            self._out_offset = value

    property cnt:

        """
        The number of records to process
        """

        def __get__( self ):
            return( self._cnt )
        def __set__( self, value ):
            self._cnt = value

#
# These can be used to do bounds checks, but currently they
# are not used.
#

    property address:
        """
        Sets the router IP address.
        """

        def __get__( self ):
            return( self._address )
        def __set__( self, value ):
            self._address = value

    property flow_id:
        """
        Sets the base flow id value.  This value is incremented
        as input packets are processed, so the caller only needs
        to call this when the value drifts due to dropped packets.
        """
        def __get__( self ):
            return( self._flow_id )
        def __set__( self, value ):
            self._flow_id = value

    property cflowd_offset_to_flowStartSeconds:
        """Sets the cflowd offset to flowStartSeconds"""
        def __get__( self ):
            return( self._cflowd_offset_to_flowStartSeconds )
        def __set__( self, value ):
            self._cflowd_offset_to_flowStartSeconds = value
    property cflowd_offset_to_flowEndSeconds:
        """Sets the cflowd offset to flowEndSeconds"""
        def __get__( self ):
            return( self._cflowd_offset_to_flowEndSeconds )
        def __set__( self, value ):
            self._cflowd_offset_to_flowEndSeconds = value
    property cflowd_offset_to_flowId:
        """Sets the cflowd offset to flowId"""
        def __get__( self ):
            return( self._cflowd_offset_to_flowId )
        def __set__( self, value ):
            self._cflowd_offset_to_flowId = value
    property cflowd_offset_to_exporterIPv4Address:
        """Sets the cflowd offset to exporterIPv4Address"""
        def __get__( self ):
            return( self._cflowd_offset_to_exporterIPv4Address )
        def __set__( self, value ):
            self._cflowd_offset_to_exporterIPv4Address = value

    property template:
        def __get__( self ):
            return( self._template )
        def __set__( self, value ):
            self._template = value

    def __cinit__( self, in_offsets, out_offsets, check_for_zero,
        *args, **kwargs ):

        """
        When we create the class, pass in the offsets that will
        be used to move the data around.  Generally, you create
        one of these objects for each template of fixed input
        type (Netflow V5, for instance)

        Args:
            in_offsets: Offsets into an input buffer to fetch bytes
            out_offsets: Offsets into an output buffer to store bytes
            check_for_zero: Offsets whose bytes should be zero or we
                have an overflow.
        """

        if len( in_offsets ) > 100:
            raise( ValueError( 'Number of in_offsets > 100' ))
        elif len( check_for_zero ) > 100:
            raise( ValueError( 'Number of check_for_zero > 100' ))
        elif len( in_offsets ) != len( out_offsets ):
            raise( ValueError( 'Number of input offsets != '
                'number of output offsets' ))
        elif len( in_offsets ) < 1:
            raise( ValueError( 'No input offsets provided in enumeration' ))
        elif len( out_offsets ) < 1:
            raise( ValueError( 'No output offsets provided in enumeration' ))

# Stash the offsets into a "C" array.

        cdef unsigned int i
        for ( i, b ) in enumerate( in_offsets ):
            self._in_offsets[ i ] = b
        for ( i, b ) in enumerate( out_offsets ):
            self._out_offsets[ i ] = b
        for ( i, b ) in enumerate( check_for_zero ):
            self._check_for_zero[ i ] = b

# Initialize the rest.

        self.max_in_offset = max( in_offsets )
        self.max_out_offset = max( out_offsets )
        self._num_offsets = len( in_offsets )
        self._num_check_for_zero = len( check_for_zero )
        self.address = 0
        self.flow_id = 0
        self.in_len = 0
        self.out_len = 0
        self.in_offset = 0
        self.out_offset = 0

        self.cflowd_offset_to_flowStartSeconds = 0
        self.cflowd_offset_to_flowEndSeconds = 0
        self.cflowd_offset_to_flowId = 0
        self.cflowd_offset_to_exporterIPv4Address = 0
        self._template = None

    cdef int _byte_mover( self,
        uint8_t * in_buffer,
        uint8_t * out_buffer ) nogil:

        """
        This routine actually moves the bytes from the input buffers
        to the output buffers.  This routine can be called from
        Python or C (efficiently).

        It does not handle the flowId, times, or the
        exportorIPAddress.  This is usually handled in a subclass
        since computing the start and stop times is different
        for each subclass.

        Args:
            in_buffer: The input buffer to copy bytes from
            out_buffer: The output buffer to store bytes in

        Returns:
            True: If an overflow in a field occured
            False: If no overflow was detected

        Notes:
            The buffer sizes are defined by calls to self.in_len and
            self.out_len.  These are required calls if cnt > 1.

        Required calls:

        self.in_len
        self.cnt
        self.in_offset
        self.out_offset
        self.out_len
        self.cflowd_offset_to_flowStartSeconds
        self.cflowd_offset_to_flowEndSeconds
        self.cflowd_offset_to_flowId
        self.cflowd_offset_to_exporterIPv4Address
        self.address
        self.flow_id
        """

        cdef unsigned int i
        cdef unsigned int j
        cdef unsigned int in_len = self._in_len
        cdef unsigned int out_len = self._out_len
        cdef uint8_t overflow = False
        cdef unsigned int * in_offsets = self._in_offsets
        cdef unsigned int * out_offsets = self._out_offsets
        cdef unsigned int num_offsets = self._num_offsets
        cdef unsigned int cnt = self._cnt

        cdef unsigned int num_check_for_zero = self._num_check_for_zero
        cdef unsigned int * check_for_zero = self._check_for_zero

        in_buffer += self._in_offset
        out_buffer += self._out_offset

        for i in range( cnt ):
            for j in range( num_offsets ):
                out_buffer[out_offsets[j]] = in_buffer[in_offsets[j]]
                for j in range( num_check_for_zero ):
                    if overflow:
                        break
                    else:
                        overflow = in_buffer[check_for_zero[j]]

            in_buffer += in_len         # Next input buffer
            out_buffer += out_len       # Next output buffer

        return( overflow )

    def __str__( self ):

        """
        This routine returns the class information as a string.
        """

        results=[ '--- Base ByteMover Class Data ---' ]

        for (i,o) in zip( self.in_offsets, self.out_offsets ):
            results.append( 'out[%d]<-in[%d]' % ( o,i ) )

        results.append( 'Must be zero input bytes: %s' %
                ','.join( [ str(i) for i in self.check_for_zero ] ) )

        results.append( 'address = %x' % self.address )
        results.append( 'flow_id = %d' % self.flow_id )
        results.append( 'in_len = %d' % self.in_len )
        results.append( 'out_len = %d' % self.out_len )
        results.append( 'in_offset = %d' % self.in_offset )
        results.append( 'out_offset = %d' % self.out_offset )
        results.append( 'cnt = %d' % self._cnt )

        results.append( 'cflowd_offset_to_flowStartSeconds = %d' %
                self.cflowd_offset_to_flowStartSeconds )
        results.append( 'cflowd_offset_to_flowEndSeconds = %d' %
                self.cflowd_offset_to_flowEndSeconds )
        results.append( 'cflowd_offset_to_flowId = %d' %
                self.cflowd_offset_to_flowId )
        results.append( 'cflowd_offset_to_exporterIPv4Address = %d' %
                self.cflowd_offset_to_exporterIPv4Address )

        return( '\n'.join( results ) )


cdef class ByteMoverNetflowV5( ByteMover ):

    property sysUpTimeDeltaMilliseconds:
        """Sets sysUpTimeDeltaMilliseconds"""
        def __get__( self ):
            return( self._sysUpTimeDeltaMilliseconds )
        def __set__( self, value ):
            self._sysUpTimeDeltaMilliseconds = value
    property sysUpTime:
        """Sets sysUpTime"""
        def __get__( self ):
            return( self._sysUpTime )
        def __set__( self, value ):
            self._sysUpTime = value
    property offset_to_flowStartSysUpTime:
        """Sets offset_to_flowStartSysUpTime in the input buffer"""
        def __get__( self ):
            return( self._offset_to_flowStartSysUpTime )
        def __set__( self, value ):
            self._offset_to_flowStartSysUpTime = value
    property offset_to_flowEndSysUpTime:
        """Sets offset_to_flowEndSysUpTime in the input buffer"""
        def __get__( self ):
            return( self._offset_to_flowEndSysUpTime )
        def __set__( self, value ):
            self._offset_to_flowEndSysUpTime = value

    def __cinit__( self, in_offsets, out_offsets, *args, **kwargs ):

        """
        Note: the base class __cinit__ is automatically called first.
        """

        self.sysUpTimeDeltaMilliseconds = 0
        self.sysUpTime = 0
        self.offset_to_flowStartSysUpTime = 0
        self.offset_to_flowEndSysUpTime

    cpdef int byte_mover( self,
        uint8_t * in_buffer,
        uint8_t * out_buffer ):

        """
        This routine handles setting various computed values
        for netflow v5 input and cflowd output.  The flow_id,
        router address and flow stop/start time are computed.

        This routine can also be used for any ipfix routine
        that uses flowStartSysUpTime and flowEndSysUpTime in
        the template.

        This routine will process all the buffers.  It also depends
        on a variety of calls that set varius offsets and values
        taken from the header.

        This code might look complex, but it is very fast.

        Required Calls.  These are all template or v5 initialization
        time:

        All calls for ByteMover.byte_mover

        self.sysUpTimeDeltaMilliseconds
        self.sysUpTime
        self.offset_to_flowStartSysUpTime
        self.offset_to_flowEndSysUpTime
        """

        cdef:
            unsigned int i

            uint8_t * p_in_st = &(in_buffer[self._in_offset +
                                            self._offset_to_flowStartSysUpTime])
            uint8_t * p_in_et = &(in_buffer[self._in_offset +
                                            self._offset_to_flowEndSysUpTime])
            uint32_t in_st
            uint32_t in_et
            uint32_t out_st
            uint32_t out_et

            uint8_t * p_out_st = &(out_buffer[self._out_offset +
                                    self._cflowd_offset_to_flowStartSeconds])
            uint8_t * p_out_et = &(out_buffer[self._out_offset +
                                    self._cflowd_offset_to_flowEndSeconds])

            uint8_t * p_out_fi = &(out_buffer[self._out_offset +
                                    self._cflowd_offset_to_flowId])
            uint8_t * p_out_a = &(out_buffer[self._out_offset +
                                    self._cflowd_offset_to_exporterIPv4Address])

            unsigned int in_len = self._in_len
            unsigned int out_len = self._out_len
            unsigned int cnt = self._cnt
            uint32_t address = self._address
            uint32_t flow_id = self._flow_id
            int overflow
            int sysUpTimeDeltaMilliseconds=self._sysUpTimeDeltaMilliseconds
            int sysUpTime = self._sysUpTime

        with nogil:
            overflow = ByteMover._byte_mover( self, in_buffer, out_buffer )

            for i in range( cnt ):
                memcpy( p_out_fi, &flow_id, sizeof( flow_id ) )
                p_out_fi += out_len
                flow_id += 1

                memcpy( p_out_a, &address, sizeof( address ) )
                p_out_a += out_len

                memcpy( &in_st, p_in_st, sizeof( in_st ) )
                memcpy( &in_et, p_in_et, sizeof( in_et ) )
                in_st = ntohl( in_st )                  # In network byte order
                in_et = ntohl( in_et )                  # In network byte order
                p_in_st += in_len
                p_in_et += in_len

# Watch your casts here.  Need a negative sometimes.

                out_st = (((<int>in_st - sysUpTimeDeltaMilliseconds) //
                            1000) + sysUpTime )
                out_et = (((<int>in_et - sysUpTimeDeltaMilliseconds) //
                            1000) + sysUpTime )

                memcpy( p_out_st, &out_st, sizeof( out_st ) )
                memcpy( p_out_et, &out_et, sizeof( out_et ) )

                p_out_st += out_len
                p_out_et += out_len

            self._flow_id = flow_id
        return( overflow )

    def __str__( self ):

        """
        Adds to the default string.
        """

        results = [ ByteMover.__str__( self ) ]

        results.append( '--- Netflow V5 Specific ---' )

        results.append( 'offset_to_flowStartSysUpTime = %d' %
                self.offset_to_flowStartSysUpTime )
        results.append( 'offset_to_flowEndSysUpTime = %d' %
                self.offset_to_flowEndSysUpTime )
        results.append( 'sysUpTimeDeltaMilliseconds = %d' %
                self.sysUpTimeDeltaMilliseconds )
        results.append( 'sysUpTime = %d' % self.sysUpTime )

        return( '\n'.join( results ) )


cdef class ByteMoverMilliSeconds( ByteMover ):

    """
    This class is used to handle cases where the flow start and
    stop times are given in mlliseconds.  Call the appropriate
    routines to provide the offsets to the timestamps.

    You must all make all the required calls for ByteMover itself.
    """

    property offset_to_flowStartMilliseconds:
        """Sets offset_to_flowStartMilliseconds in the input packet"""
        def __get__( self ):
            return( self._offset_to_flowStartMilliseconds )
        def __set__( self, value ):
            self._offset_to_flowStartMilliseconds = value
    property offset_to_flowEndMilliseconds:
        """Sets offset_to_flowEndMilliseconds in the input packet"""
        def __get__( self ):
            return( self._offset_to_flowEndMilliseconds )
        def __set__( self, value ):
            self._offset_to_flowEndMilliseconds = value

    def __cinit__( self, in_offsets, out_offsets, *args, **kwargs ):

        """
        Note: the base class __cinit__ is automatically called first.
        """

        self.offset_to_flowStartMilliseconds = 0
        self.offset_to_flowEndMilliseconds = 0

    cpdef int byte_mover( self,
        uint8_t * in_buffer,
        uint8_t * out_buffer ):

        """
        This routine handles setting various computed values for
        netflow millisecs time stamps on input and cflowd output.
        The flow_id, router address and flow stop/start time
        are computed.

        This routine can also be used for any ipfix routine that
        uses flowStartMilliseconds and flowStartMilliseconds in
        the template and makes the required calls.

        This routine will process all the buffers.  It also depends
        on a variety of calls that set varius offsets and values
        taken from the header.

        This code might look complex, but it is very fast.

        Required Calls.  These are all template or v10
        initialization time:

        All calls needed for ByteMover.byte_mover

        self.offset_to_flowStartMilliseconds
        self.offset_to_flowEndMilliseconds
        """

        cdef:
            unsigned int i

# Pointers to input start and end times.

            uint8_t * p_in_st = &(in_buffer[self._in_offset +
                                        self._offset_to_flowStartMilliseconds])
            uint8_t * p_in_et = &(in_buffer[self._in_offset +
                                        self._offset_to_flowEndMilliseconds])
            uint32_t in_st[ 2 ]
            uint32_t in_et[ 2 ]
            uint64_t in_st64
            uint64_t in_et64
            uint32_t out_st
            uint32_t out_et

# Pointers to output start and end times.

            uint8_t * p_out_st = &(out_buffer[self._out_offset +
                                    self._cflowd_offset_to_flowStartSeconds])
            uint8_t * p_out_et = &(out_buffer[self._out_offset +
                                    self._cflowd_offset_to_flowEndSeconds])

# Pointers to the flowId and router address in the output buffer.

            uint8_t * p_out_fi = &(out_buffer[self._out_offset +
                                    self._cflowd_offset_to_flowId])
            uint8_t * p_out_a = &(out_buffer[self._out_offset +
                                    self._cflowd_offset_to_exporterIPv4Address])

            unsigned int in_len = self._in_len     # Input buffer len
            unsigned int out_len = self._out_len   # Output buffer len
            unsigned int cnt = self._cnt
            uint32_t address = self._address       # Copy the address
            uint32_t flow_id = self._flow_id       # and flowId

            int overflow

# Call the superclass byte mover.

        with nogil:
            overflow = ByteMover._byte_mover( self, in_buffer, out_buffer )

            for i in range( cnt ):                      # For each buffer
                memcpy( p_out_fi, &flow_id, sizeof( flow_id ) ) # Set flowId
                p_out_fi += out_len
                flow_id += 1

                memcpy( p_out_a, &address, sizeof( address ) )  # Router addr
                p_out_a += out_len

                memcpy( in_st, p_in_st, sizeof( in_st ) )   # Get in times
                memcpy( in_et, p_in_et, sizeof( in_et ) )

                in_st[0] = ntohl( in_st[0] )                # Mangle ntohq
                in_st[1] = ntohl( in_st[1] )
                in_st64  = <uint64_t>in_st[0] << 32 | <uint64_t>in_st[1]

                in_et[0] = ntohl( in_et[0] )                # Mangle ntohq
                in_et[1] = ntohl( in_et[1] )
                in_et64  = <uint64_t>in_et[0] << 32 | <uint64_t>in_et[1]

                out_st = in_st64 // 1000                    # Convert to seconds
                out_et = in_et64 // 1000

                p_in_st += in_len                           # Move in time ptrs
                p_in_et += in_len

                memcpy( p_out_st, &out_st, sizeof( out_st ) )   # Store times
                memcpy( p_out_et, &out_et, sizeof( out_et ) )

                p_out_st += out_len                         # Move out time ptrs
                p_out_et += out_len

            self._flow_id = flow_id
        return( overflow )
        
# End.
