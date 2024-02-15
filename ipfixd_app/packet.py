"""
General packet handling module.  Use the general class Packet
to start a thread that processes a packet.  Packets are decoded
into templates, option templates and data.  Appropriate dispatches
are then called.
"""

import sys
import struct
import time
import queue
import traceback
import ipfixd_app.header
from ipfixd_app.ipfixd_log import log
import ipfixd_app.ipfixd_thread
from collections import namedtuple
import cProfile

#
# Indexes used into the standard tuple we retrieve from the input queue.
# cflowd needs these.
#

t_address = 0       # Address tuple for sending router
t_port = 1          # Port we are listening on
t_p = 2             # The packet buffer
t_p_len = 3         # The packet length

import ipfixd_app.cflowd

class Packet( ipfixd_app.ipfixd_thread.IPFixdThread ):

    def __init__( self, cmdparse, src_obj, socket_thread_name,
        cflowd_writer, ipfix_writer ):

        """
        Starts a thread that processes a particular src_obj using the
        queue method as a queue object.
        """

        self._cmdparse = cmdparse

        self._src_obj = src_obj
        self._queue = src_obj.queue()   # Input (socket) queue

        if cflowd_writer:               # cflowd format gets written here
            self._cflowd_queue = cflowd_writer.queue()
            self.cflowd = True
        else:
            self._cflowd_queue = None
            self.cflowd = False

        if ipfix_writer:            # ipfix "raw" data gets written here
            self._ipfix_queue = ipfix_writer.queue()
            self.ipfix = True
        else:
            self._ipfix_queue = None
            self.ipfix = False

        self._max_qsize = 0
        self._data_list_max = 10000
        self._max_time_in_list = 10

        name = "Packet processor for: %s" % socket_thread_name

        ipfixd_app.ipfixd_thread.IPFixdThread.__init__(
            self, profile=cmdparse.profile, name=name,
            target=self.process_loop )
        self.daemon = True
        self.header_fmt = struct.Struct( '!H' )

        log().info( 'INFO: Created thread %s' % self.name )

# Scope and data

    def process_loop( self ):

        """
        Processes data on the queue.  This just traps and prints
        exceptions to the log.  Sometimes they seem to get lost.
        """

        try:
            self._process_loop()
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            f = traceback.format_exception( exc_type, exc_value, exc_traceback )
            del exc_traceback
            [ log().error( x ) for x in f ]
            log().error( 'Thread aborted: %s' % self.name )
            raise exc_type

    def _do_stop( self, ipfix_data_list, cflowd_data_list ):

        """
        This routine handles the thread stop actions.  It does
        not actually cause the thread to stop, though.  The
        main routine for the thead should return.
        """

        log().info( 'INFO: Thread %s stopping by request',
            self.name )

        if ipfix_data_list:
            self._ipfix_queue.put( ipfix_data_list )
            ipfix_data_list[:] = []
        if cflowd_data_list:
            self._cflowd_queue.put( cflowd_data_list )
            cflowd_data_list[:] = []

        if self._cflowd_queue:
            self._cflowd_queue.put( [ bytearray(0) ] )
        if self._ipfix_queue:
            self._ipfix_queue.put( [ bytearray(0) ] )

        if self._profile:
            self._profile.disable()
            self._profile.dump_stats( "stats/" + self.name )

    def _process_loop( self ):

        """
        Process packets on the input queue, figure out what
        routine should handle it, call the processing code,
        and add the output to the output queue.

        We buffer items to add to the output queue in
        cflowd_data_list and ipfix_data_list.  The queue type we
        are using expects an iterable object to provide the items
        to add to the queue.  Since the buffers are covered by
        mutexs, adding items in groups saves a lot of locking and
        unlocked time.  We keep track of the time when an item is
        first added to a list, and limit the amount of time an item
        can be in the list as well as the list length.  We don't
        want stale data hanging around and not being written.
        """

        if self._profile:
            self._profile.enable()

        dispatch = [0] * 20
        dispatch[ 5 ] = ipfixd_app.cflowd.netflow_v5_to_cflowd
#        dispatch[ 5 ] = ipfixd_app.cflowd.null_cvt_rtn     # Debugging
        dispatch[ 10 ] = ipfixd_app.cflowd.netflow_v10_to_cflowd

        dispatch_arg_list = [0] * 3
        dispatch_arg_list[ 0 ] = self.cflowd
        dispatch_arg_list[ 1 ] = self.ipfix

        ipfix_data_list = []
        cflowd_data_list = []
        ipfix_data_list_time = 0
        cflowd_data_list_time = 0

        while True:
            if cflowd_data_list or ipfix_data_list:
                now = time.time()           # Compute minimum timeout
                if cflowd_data_list:
                    t1 = now - cflowd_data_list_time
                else:
                    t1 = 0
                if ipfix_data_list:
                    t2 = now - ipfix_data_list_time
                else:
                    t2 = 0
                timeout = self._max_time_in_list - max( [t1, t2] )

                if timeout > 0:
                    try:
                        items = self._queue.get( block=True, timeout=timeout )
                    except queue.Empty:
                        items = []
                else:
                    items = []
            else:
                items = self._queue.get( block=True )

            now = time.time()
            if ipfix_data_list:
                if (len(ipfix_data_list) > self._data_list_max or
                        (now - ipfix_data_list_time > self._max_time_in_list)
                    ):
                    self._ipfix_queue.put( ipfix_data_list )
                    ipfix_data_list = []

            if cflowd_data_list:
                if (len(cflowd_data_list) > self._data_list_max or
                        (now - cflowd_data_list_time > self._max_time_in_list)
                    ):
                    self._cflowd_queue.put( cflowd_data_list )
                    cflowd_data_list = []

            if not items:
                continue

            for t in items:
                p = t[ t_p ]
                p_len = t[ t_p_len ]

                if p_len == 0 and self.should_stop():
                    self._do_stop( ipfix_data_list, cflowd_data_list )
                    return
                elif p_len < 2:
                    log().info( 'INFO: main: short packet, len=%d', p_len )
                    continue

                self._max_qsize = max( self._max_qsize, self._queue.qsize() )

                try:
                    rtn = dispatch[ ipfixd_app.header.netflow_version( p ) ]
                except IndexError:
                    self._unknown_packet( t )
                    continue
                if rtn == 0:
                    self._unknown_packet( t )
                    continue

                dispatch_arg_list[ 2 ] = t
                ( cflowd_data, ipfix_data ) = rtn( *dispatch_arg_list ) # CALL!

                if cflowd_data:
                    if not cflowd_data_list:
                        cflowd_data_list_time = time.time()
                    cflowd_data_list.append( cflowd_data )
                if ipfix_data:
                    if not ipfix_data_list:
                        ipfix_data_list_time = time.time()
                    ipfix_data_list.append( ipfix_data )

            self._src_obj.return_buffs( items )

    def _unknown_packet( self, t ):

        """
        Handles the unknown packet case.

        Args:
            t: Tuple in standard format.  See the t_* constants at the
                top of this module.
        """

        h=self.header_fmt.unpack_from( t[ t_p ] )
        p = t[ t_p ]
        p_len = t[ t_p_len ]

        log().info( 'ERROR: Received a packet from %s, type: %d, '
            'len = %d, unknown type.' % ( t[ t_address ], h[0], p_len ) )

    def qsize( self ):
        m = self._max_qsize
        self._max_qsize = 0
        return( self._queue.qsize(), m )

    def queue( self ):

        """
        Returns the queue associated with the port.
        """

        return( self._queue )

# End.
