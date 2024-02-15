"""
Main writer handling code.  Watches for packets on a queue and writes
them.  Takes a mutex on the file so that it can be moved by the
file moving thread.
"""

import sys
import threading
import os
import time
import queue
from ipfixd_app.ipfixd_log import log
import ipfixd_app.ipfixd_queue
import ipfixd_app.ipfixd_thread
from ipfixd_app.util import set_exit

_file_names = {
    'cflowd': 'flows',      # Tradition
    'ipfix': 'ipfix-flows'  # New kid on the block
}

class Writer( ipfixd_app.ipfixd_thread.IPFixdThread ):

    """
    Handles a queue.  Starts up a thread that listens for data
    on the queue that this object provides.  The data is written
    to the current temp file.

    To get this thread to stop, call stop() and write a 0 length
    packet to the queue.

    Use <obj>.queue to determine what queue to write objects on.
    """

    def __init__( self,
            temp_directory,
            write_timeout,
            dest_directory,
            profile=False,
            cflowd=False,
            ipfix=False,
            port=0,
            max_queue_size=100000 ):

        """
        Returns a thread object.  Call start on it to cause it
        to listen for packets on the queue and write them to
        a temp file.  Use the queue method to learn what queue
        packets will be placed on.

        The temp file is created here.

        Args:
            temp_directory: The directory to create the temp file in.
            write_timeout: How often to move the temp file to a perm.  file.
            dest_directory: The directory for the perm. file.
            profile: If True, profile
            cflowd: If true, writing a cflowd file
            ipfix: If true, writing an ipfix file.  Mutually exclusive w/cflowd
            port: The port the data came from
            max_queue_size: The maximum length we will allow the queue
                to grow to.
        """

        if not (bool(cflowd) ^ bool(ipfix)):
            raise ValueError( 'One and only one of cflowd,ipfix can be True.' )
        if cflowd:
            self._writer_type = 'cflowd'
        elif ipfix:
            self._writer_type = 'ipfix'

        name = 'Writer (%s) for %s->%s:%d' % ( self._writer_type,
            temp_directory, dest_directory, write_timeout )

        if temp_directory[:-1] != '/':
            temp_directory += '/'
        self._temp_directory = temp_directory

        if dest_directory[:-1] != '/':
            dest_directory += '/'
        self._dest_directory = dest_directory

        ipfixd_app.ipfixd_thread.IPFixdThread.__init__(
                self, profile=profile, name=name, target=self.write_loop )
        self.daemon = True
        log().info( 'INFO: Created thread %s' % name )

        self._queue = ipfixd_app.ipfixd_queue.IterQueue(
                                                maxsize = max_queue_size )
        self._max_qsize = 0

# Setup and call the file renamer.  It won't do anything to the file
# since there is no file.  But, it will start a timer thread.

        self._write_timeout = write_timeout
        self._temp_file_name = None
        self._temp_file = None
        self._rename_thread = None
        self._temp_file_name = (self._temp_directory +
            _file_names[ self._writer_type ] + '.current' )

        self._file_lock = threading.Lock()
        self._file_rename()

    def _actual_file_rename( self ):

        """
        Does the actual rename.
        """

        dest_file_name = (self._dest_directory + 
            _file_names[ self._writer_type ] + '.%Y%m%d_%H:%M:%S')

        gmt_offset = int(
            (
                time.mktime(time.localtime()) -
                time.mktime(time.gmtime())
            )/(60*60))
        gmt_offset='{0:=+03}'.format( gmt_offset )+'00'

        dest_file_name = time.strftime( dest_file_name ) + gmt_offset

        try:
            log().info( 'INFO: %s: renaming %s to %s' % ( 
                self.name, self._temp_file_name, dest_file_name ) )
            os.rename( self._temp_file_name, dest_file_name )
            log().info( 'INFO: %s: rename successful.' % self.name )
        except OSError as e:
            log().error( 'ERROR: renaming "%s" to "%s" failed: %s' %
                (self._temp_file_name, dest_file_name, e ) )
            raise

    def _file_rename( self, new_thread = True ):

        """
        Renames the current temp file into the dest directory.
        Will not create a new temp file.  That happens when the
        first packet is obtained.  Also, if there is no temp file,
        then nothing is renamed/created.

        The timer thread is created if needed and restarted.
        """

        with self._file_lock:
            if (self._temp_file):
                try:
                    self._temp_file.close()
                    self._temp_file = None
                except OSError as p:
                    log().error( 'ERROR: closing "%s": %s' %
                        (self._temp_file_name, p ) )
                    set_exit(1)
                    return
                try:
                    self._actual_file_rename()
                except OSError:
                    set_exit(1)
                    return
            else:
                log().info( 'INFO: %s: No temp file to rename', self.name )
            # Renaming file end
        # Lock context

        if new_thread:
            self._rename_thread = threading.Timer(
                interval=self._write_timeout,
                function=self._file_rename )
            self._rename_thread.name = self.name + ':rename_thread'
            self._rename_thread.start()

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
        Returns the queue associated with the directory.
        """

        return( self._queue )

    def write_loop( self ):

        """
        Runs the writer loop.  For each item we receive on our
        queue, write it to a file.  Every so often, rename the file
        and start a new temp file.  Watch for zero length objects
        on the queue and assume they mean to stop.  Rename the
        current temp file on a stop, and cancel relavent timer
        threads.

        Make sure the file lock is owned when working with
        the file.  A rename will also acquire the lock, so do
        not call the renamer within the locked section of the code.
        """

        if self._profile:
            self._profile.enable()

        stuck = False           # Not stuck due to I/O error
        stuck_time = 0          # When we got stuck
        stuck_wait = 60         # How long to wait before trying I/O again
        stopping = False        # Are we stopping the thread?

        while not stopping:
            items = self._queue.get( block=True )
            if stuck and ((time.time() - stuck_time) > stuck_wait):
                stuck = False

            with self._file_lock:       # Get the lock
                if not stuck:
                    try:
                        if not self._temp_file:
#                            self._temp_file = open( self._temp_file_name, 'wb')
                            self._temp_file = open( self._temp_file_name,
                                'wb', 2**20 )
                    except OSError as p:
                        log().error( 'ERROR: %s: %s' % (p, self.name))
                        log().error( 'ERROR: %s: will try again in %d secs.  '
                            'If you can fix the error, no need to restart.' %
                                (self.name, stuck_wait))
                        stuck = True
                        stuck_time = time.time()

                for item in items:
                    if len(item) == 0:
                        stopping = True
                        break
                    elif stuck:
                        break

                    try:
                        self._temp_file.write(item)
                    except OSError as p:
                        log().error( 'ERROR: %s: %s' % (self.name, p) )
                        log().error( 'ERROR: %s: will try again in %d '
                            'secs.  If you can fix the error, no need to '
                            'restart.' % (self.name, stuck_wait ))
                        stuck = True
                        stuck_time = time.time()
                        break

# Rename can't be called within with context because of the file
# lock.

        log().info( 'INFO: %s: Thread stopping by request', self.name )
        self._rename_thread.cancel()        # Cancel current rename thread
        self._file_rename( new_thread = False )
        if self._profile:
            self._profile.disable()
            self._profile.dump_stats( "stats/" + self.name.replace('/','-') )
        return

# End.
