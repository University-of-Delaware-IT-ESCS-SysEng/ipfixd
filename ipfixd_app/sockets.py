"""
Main socket handling code.  The listen or each port we want to
listen on runs in its own thread.  Packets are read from the
network and dumped on the associated Queue.  Very little work in
done here.

Packets are read into a free allocated bytearray obtained from
the free_queue.  After the buffer is processed, it must be re-added
to the free queue or we will run out of buffers.

The nice advantage of this is that we end up with a pre-allocated
set of buffers that we can use and not have to garbage collect
wen done.  Also, we don't end up with different sized chunks
of memory all over the place like we if we read varying length
objects from the network.
"""

import socket
import time
import sys
import threading
import queue
from ipfixd_app.ipfixd_log import log
import ipfixd_app.ipfixd_thread
import ipfixd_app.ipfixd_queue

import enum

class ReadListReasons(enum.Enum):
    large_list = 1,
    timeout = 2,
    blocked_io = 3,
    none = 4

class FreeListReasons(enum.Enum):
    large_list = 1,
    blocked_io = 2,
    empty = 3,
    none = 4

class Socket( ipfixd_app.ipfixd_thread.IPFixdThread ):

    """
    Handles a UDP socket.  Starts up a thread that listens for
    data on the port.  The queue that data is placed on is
    available via the queue method.

    To get this thread to stop, call stop() and write a 0 length
    packet to the port.
    """

    def __init__( self, port, profile=False, max_queue_size=50000 ):

        """
        Returns a thread object.  Call start on it to cause it
        to listen for packets on the port.  Use the queue method
        to learn what queue packets will be placed on.

        Be careful about making the queue too large. If you do,
        then the packet processing thread can get hold of a large
        chunk preventing this thread from regaining control.

        Args:
            port: The port to listen on.
        """

        name = 'Port %d socket reader' % port
        self.port = port
        self._queue_size = max_queue_size

        ipfixd_app.ipfixd_thread.IPFixdThread.__init__(
                    self, name=name, profile=profile, target=self.read_loop )
        self.daemon = True
        log().info( 'INFO: Created thread %s' % name )

# _free_len is a general guidance as to whether it makes sense to
# see if there is anything available in the free queue.  We use
# this so we can avoid taking out a mutex on the queue.

        self._free_queue = ipfixd_app.ipfixd_queue.IterQueue(
                                    maxsize = max_queue_size )
        self._free_len = 0

        self._queue = ipfixd_app.ipfixd_queue.IterQueue(
                                    maxsize = max_queue_size )
        self._max_qsize = 0
        self._buff_size = 1024*4

        self._free_queue.put( [ bytearray( self._buff_size )
                                    for i in range( max_queue_size ) ] )
        self._free_len = max_queue_size

    def qsize( self ):

        """
        Returns a tuple: the current qsize and the max since the last
        call.
        """

        m = self._max_qsize
        self._max_qsize = 0

        return( self._queue.qsize(), m )

    def qempty( self ):

        """
        Empties the queue immediately.  This is usually done as part of
        a fast shutdown.
        """

        while True:
            try:
                self._queue.get( block=False, timeout=0 )
            except queue.Empty:
                break

    def queue( self ):

        """
        Returns the queue associated with the port.
        """

        return( self._queue )

    def _make_socket( self ):

        """
        This method sets up the socket.  Sets the instance attribute 's'
        and 'sel'.
        """

        self.s = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
        self.s.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 )
        self._set_socket_buffer()

        try:
            self.s.bind( ('', self.port) )
        except OSError as e:
            log().error( 'ERROR: bind, errno=%d: %s' % ( e.errno, e.strerror ))
            ipfixd_app.main.stop_all_threads()
            time.sleep(2)       # Race conditions...
            self._queue.put( [[('0.0.0.0','0'), self.port, bytearray( 0 ), 0]] )
            log().info( 'ERROR: Thread %s stopping because of error.',
                self.name )
            raise

        self.s.settimeout( 2 )

    def _set_socket_buffer( self ):

        """
        This routine attempts to maximize the size of the OS buffer
        associated with the socket.
        """

        size = 2<<24            # 16MB

        while size > 2048:
            try:
                self.s.setsockopt( socket.SOL_SOCKET, socket.SO_RCVBUF, size )
                break
            except KeyError:    # bogus
                size /= 2

        if size == 2048:
            log().error( 'ERROR: Error setting SO_RCVBUF.  Got to 2K.' )
            return

        log().info( 'INFO: Set receive buffer for port %d to %d.' %
                        (self.port, size ) )

    def free_list_management( self, free_list, reason ):

        """
        This routine is used to obtain buffers from the free
        queue and add them to the free list.  Recall that
        the free queue is covered by a mutex, so we want
        to keep a free_list which avoids getting the mutex
        except when we are going to get a bunch of buffers
        or we don't have any in the list.

        Args:
            free_list: The list to add buffers to.
            reason: An enum from class FreeListReason.  With value
                FreeListReason.none, the counters are reset to zero
                and the routine exits.  This is how to init info.
        """

        if reason == FreeListReasons.none:
            self.metric_free_list_large_list = 0
            self.metric_free_list_blocked_io = 0
            self.metric_free_list_empty = 0
            self.metric_free_list_exhausted = 0
            self.first_time = True
            return
        elif reason == FreeListReasons.large_list:
            self.metric_free_list_large_list += 1
        elif reason == FreeListReasons.blocked_io:
            self.metric_free_list_blocked_io += 1
        elif reason == FreeListReasons.empty:
            self.metric_free_list_empty += 1
            
        try:
            free_list.extend( self._free_queue.get( block=False ) )
            self._free_len = 0
            if free_list:
                self.first_time = False
        except queue.Empty:     # This really shouldn't happen. Meh.
            pass

        if not free_list:           # Exhausted free list
            if not self.first_time: # Shouldn't generally happen
                log().warn( 'WARN: Exhausted socket free list %s' %
                                                self.name )

            free_list.extend( self._free_queue.get( block=True ) )
            self._free_len = 0

            if not self.first_time:
                log().info( 'INFO: Exhausted socket free list '
                        'relieved %s' % self.name )
                self.metric_free_list_exhausted += 1
            else:
                self.first_time = False

    def read_list_management( self, read_list, reason ):

        """
        This routine is used to manage copying information from the
        temporary read_list to the appropriate queue.

        Args:
            read_list: The list of buffers to add to the queue.
                Note: this list will be modified
            reason: An enum from class ReadListReasons.  With value
                ReadListReasons.none, the counters are reset to zero
                and the routine exits.  This is how to init info.
        """

        if reason == ReadListReasons.none:
            self.metric_read_list_cnt = 0
            self.metric_read_list_total = 0
            self.metric_read_list_large_list = 0
            self.metric_read_list_timeout = 0
            self.metric_read_list_blocked_io = 0
            self.metric_io_non_blocking = 0
            self.metric_io_timeout = 0
            self.metric_io_blocking = 0
            self.metric_io_read_result = 0
            self.metric_io_non_blocking_result = 0
            self.metric_io_timeout_result = 0
            return

        self.metric_read_list_cnt += 1
        self.metric_read_list_total += len(read_list)

        if reason == ReadListReasons.large_list:
            self.metric_read_list_large_list += 1
        elif reason == ReadListReasons.timeout:
            self.metric_read_list_timeout += 1
        elif reason == ReadListReasons.blocked_io:
            self.metric_read_list_blocked_io += 1

        self._queue.put( read_list )
        read_list[:] = []
        self._max_qsize = max( self._queue.qsize(),
                                            self._max_qsize)

    def print_metrics( self ):

        """
        This routine will prints some stats that help tune the code.
        """

        log().info( 'INFO: %s: Read list outputs: %d, large_list: %d, '
            'timeout: %d, blocked_io: %d, total: %d, average %d' %
            ( self.name,
                self.metric_read_list_cnt,
                self.metric_read_list_large_list,
                self.metric_read_list_timeout,
                self.metric_read_list_blocked_io,
                self.metric_read_list_total,
                self.metric_read_list_total // self.metric_read_list_cnt ))

        log().info( 'INFO: %s: Free list counts: large_list: %d, '
            'blocked_io: %d, empty: %d' %
            ( self.name,
                self.metric_free_list_large_list,
                self.metric_free_list_blocked_io,
                self.metric_free_list_empty ))

        log().info( 'INFO: %s: IO Types non_blocking/timeout/blocking: '
            '%d/%d/%d, Results non_blocking/timeout/read: '
            '%d/%d/%d' %
            ( self.name,
                self.metric_io_non_blocking,
                self.metric_io_timeout,
                self.metric_io_blocking,
                self.metric_io_non_blocking_result,
                self.metric_io_timeout_result,
                self.metric_io_read_result ) )

        self.read_list_management( [], ReadListReasons.none )
        self.free_list_management( [], FreeListReasons.none )

    def request_stop( self, read_list ):

        """
        This routine is called when we want the thread to
        terminate normally.  It outputs some messages and
        copies the read_list to the queue.
        """

        if read_list:
            self._queue.put( read_list )
            self._max_qsize = max(self._queue.qsize(), self._max_qsize)

        log().info( 'INFO: Thread %s stopping by request', self.name )

    def return_buffs( self, m_objs ):

        """
        Returns the list of object that were added to the queue
        to the free queue so we can use it to receive new data.
        Obviously, it is a good idea to return all used buffers
        to the free list when done with their data.

        Args:
            m_objs: A list of lists.  The index 2 object contains
                the buffer we want to re-add to the free list.
                The other objects are things like the port, sending
                address, etc.
        """

        self._free_queue.put( [ m[2] for m in m_objs ] )
        self._free_len += len( m_objs )

    def read_loop( self ):

        """
        This routine implements the main read loop.  If opens
        a waits for packets on a port.  When data is received,
        a tuple consisting of the ( address, port, buffer )
        is added to the "read_list".  All items are read from
        the socket until a block, and then all are added to the
        queue for processing.

        If should_stop is True and a zero length packet
        is received, then the thread will gracefully stop.
        Additionally, a tuple with a zero length buffer is added
        to the queue to tell other threads to stop.
        """

        if self._profile:
            self._profile.enable()

        try:
            self._make_socket()     # Sets self.s and self.sel
        except OSError:
            return( 0 )

#
# The 'read_list' is a local list of buffers that have been read
# from the socket.  To avoid excess mutex and thread work, we only
# copy the read_list to the output queue when it has grown too big
# or we get a socket.timeout, indicating that there is nothing to read.
# Note that we have subclassed deque so that an entire list can
# be added to the queue with one mutex fetch.
#
# Try to avoid dumping the read_list and free_list management in the
# same loop pass unless absolutely necessary.  We use a socket timeout to
# check for buffers in the read_list so they don't get stuck there
# if input stops arriving or if the router just isn't sending much
# netflow/ipfix.
#
# The concept of checking for I/O using non-blocking I/O and working
# on either the free_list or read_list keeps us from having to possibly
# work on these lists when we've received a burst of traffic.  This
# change resulted in the program dropping far fewer packets.
#
# Init some stuff here.
#

        read_list = []
        free_list = []
        read_list_reason = ReadListReasons.none
        free_list_reason = FreeListReasons.none
        self.read_list_management( read_list, read_list_reason )
        self.free_list_management( free_list, free_list_reason )

        while True:
            if len(read_list) >= (self._queue_size // 2):
                read_list_reason = ReadListReasons.large_list
            if not free_list:
                free_list_reason = FreeListReasons.empty
            elif self._free_len >= (self._queue_size // 2):
                free_list_reason = FreeListReasons.large_list
            
#
# Avoid working on both free list and read list in same pass.
# The free list must take priority or else we need a special
# case to handle an empty free list.  Can't let that happen.
#

            if free_list_reason != FreeListReasons.none:
                self.free_list_management( free_list, free_list_reason )
                free_list_reason = FreeListReasons.none
            elif read_list_reason != ReadListReasons.none:
                self.read_list_management( read_list, read_list_reason )
                read_list_reason = ReadListReasons.none

            if self._free_len > self._queue_size // 16:
                maybe_free_list_reason = FreeListReasons.blocked_io
                maybe_read_list_reason = read_list_reason
                self.metric_io_non_blocking += 1
                self.s.settimeout( 0.0 )        # Try for opportunistic work
                                                # Non-blocking I/O
            elif len( read_list ) > self._queue_size // 16:
                maybe_read_list_reason = ReadListReasons.blocked_io
                maybe_free_list_reason = free_list_reason
                self.metric_io_non_blocking += 1
                self.s.settimeout( 0.0 )        # Try for opportunistic work
                                                # Non-blocking I/O
            elif read_list:
                self.s.settimeout( 2.0 )        # Don't want to buffer too long
                self.metric_io_timeout += 1
            else:
                self.s.settimeout( None )       # Just wait normal-like
                                                # Blocking I/O
                self.metric_io_blocking += 1

            try:
                (nbytes, address) = self.s.recvfrom_into(free_list[-1],
                                            self._buff_size )
                self.metric_io_read_result += 1
            except BlockingIOError:
                free_list_reason = maybe_free_list_reason
                read_list_reason = maybe_read_list_reason
                self.metric_io_non_blocking_result += 1
                continue
            except socket.timeout:
                read_list_reason = ReadListReasons.timeout
                self.metric_io_timeout_result += 1
                continue

            buff = free_list.pop()
            read_list.append( [ address, self.port, buff, nbytes ] )
            if nbytes == 0 and self.should_stop():  # Stopping
                self.request_stop( read_list )
                if self._profile:
                    self._profile.disable()
                    self._profile.dump_stats( "stats/" + self.name )
                return( 0 )

# End.
