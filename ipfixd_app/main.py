"""
This is the main module for ipfixd.  It processes the arguments,
calls the routines that create the threads and waits for a signal.

This program responds to:

    SIGUSR1: Print a status report
    SIGHUP: Graceful shutdown.  Finishes processing the queues and closes files
    SIGTERM: Empties the queues and then gracefully closes the files.

The overall structure of this program is pretty simple.  It is
thread based.

    a) Socket reader threads
    b) Packet processing threads
    c) Writer threads
        d) Rename threads

First, we have socket reader threads.  They are bound to a
particular UDP port.  They maximize their UDP buffer, and create
a Queue object from the threading module.  Packets read from the
network are written to the Queue object.  We can expand these to
support TCP as well.  If we expand to support TCP, we will need to
break into appropriate sized buffers to drop on the packet queue.
TCP is obviously stream based, so something will need to chunk
the stream into packet.

Packet processing threads read from the Socket queue (input queue),
process the data into a possibly different format and then write
it to a Writer thread queue (output queue).  The packet processing
thread does not own any queues.  When a packet processing object
is created, the input and output queues are provided.

A packet processing thread could write the data onto multiple
output queues.  We would need to add support for this, but I
don't see why not.

The writer thread processes and inbound thread.  It writes all
data received on the queue to a temp file.  Every so many seconds,
a Rename thread takes the lock on the file, and renames the temp
file into a destination directory.  It then arranges things so a
new temp file will be created when data is received.  Of course,
before writing to the file, the Writer thread must acquire a Lock
on the file.

Socket threads are unique to the port being listen on.  Writer
threads are unique to the temp/dest dir tuple.  Note that a temp
dir can not have multiple dest dirs.  This is checked for during
argument processing.

In theory, this program could support a lot of threads.  But, do
recall that currently the Python machine takes a global lock when
it is entered and does not release the lock unless a wait condition
is entered.  So, it possible that if enough inbound traffic occurs,
the socket reader will never release long enough for the packet
or writer threads to do anything.  If we see this happening, I
intend to make time(0) calls every so often or something similar.
We could write an overall management thread that looks at the
queue lengths and causes delays or something similar to even
out processing.  However, for now, let's just see how it works.
"""

import sys
import pwd
import time
import threading
import socket
import os
import signal
import daemon
import pidfile
import traceback
#import gc

import ipfixd_app.args
import ipfixd_app.sockets
import ipfixd_app.packet
import ipfixd_app.writer
from  ipfixd_app.ipfixd_log import log
from  ipfixd_app.util import set_exit, get_exit

IPFIXD_MAJOR = 1
IPFIXD_MINOR = 0
IPFIXD_PATCH = 2

VERSION = '%d.%02d.%02d' % ( IPFIXD_MAJOR, IPFIXD_MINOR, IPFIXD_PATCH )
RCS = '$Id: main.py,v 1.13 2016/02/24 22:18:58 mike Exp mike $'

sockets = []
packets = []
all_threads = []

def main():

    """
    Main routine.  Call the option parser, and then start the
    various threads.  Set the signal handlers and sleep.

    We trap the exit exception, if bad, so it can be logged to
    a syslog, etc.
    """

    ipfixd_app.ipfixd_log.set_logging( None )       # Basic stderr logging
    cmdparse = ipfixd_app.args.parse_args()

#    gc.disable()                                    # I hope we don't need this

    if not cmdparse.nofork:
        daemon_args = {}
        daemon_args[ 'umask' ] = 0o027
        daemon_args[ 'prevent_core' ] = True
        daemon_args[ 'pidfile' ] = pidfile.PidFile('/var/run/ipfixd.pid')

        if cmdparse.user:
            daemon_args[ 'uid' ] = pwd.getpwnam( cmdparse.user ).pw_uid
        if cmdparse.group:
            daemon_args[ 'gid' ] = pwd.getpwnam( cmdparse.group ).pw_gid

        with daemon.DaemonContext( **daemon_args ):
            try:
                _main( cmdparse )
            except SystemExit:
                pass
            except:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                f = traceback.format_exception( exc_type, exc_value,
                    exc_traceback )
                del exc_traceback
                for x in f: log().error( x )
                log().error( 'Daemon aborted.' )
                raise exc_type
                set_exit( 1 )
        exit( get_exit() )
    else:
        _main( cmdparse )

def _main( cmdparse ):

    """
    This is the main code that runs after we decide to fork as a
    daemon or not.  Does not matter to this code.
    """

    ipfixd_app.ipfixd_log.set_logging( cmdparse )   # Logging set by args

# Log our setup.

    log().info( 'IPFixd Version: %s, %s' % ( VERSION, RCS ) )
    for p in list(cmdparse.ports.values()):
        log().info( 'INFO: port %d, timeout=%d, temp dir=%s, dest dir=%s' %
            ( p[ 'port' ], p[ 'write_timeout' ], p[ 'temp_directory' ],
                p[ 'dest_directory' ] ) )

    signal.signal( signal.SIGUSR1, usr1_handler )   # Set info request
    signal.signal( signal.SIGHUP, hup_handler )     # Gracefull shutdown
    signal.signal( signal.SIGINT, hup_handler )     # Gracefull shutdown
    signal.signal( signal.SIGTERM, term_handler )   # Fast shutdown

#
# This basically sets up a fixed template for parsing NetFlow V5.
# Compare to the dynamic templates in ipfix.
#

    ipfixd_app.cflowd.set_cflowd_log_options( cmdparse )

    ipfixd_app.cflowd.netflow_v5_to_cflowd_tuple = (
        ipfixd_app.cflowd.netflow_v5_init(
            ipfixd_app.cflowd.netflow_v5_header_keys,
            ipfixd_app.cflowd.netflow_v5_keys ) )

#
# Start all the writers.
#

    writers = {}
    for (t,v) in list(cmdparse.temp_directories.items()):
        ipfix = v[ 'ipfix' ]
        cflowd = v[ 'cflowd' ]
        v[ 'profile' ] = cmdparse.profile

        if v[ 'cflowd' ]:
            v[ 'ipfix' ] = False
            writer = ipfixd_app.writer.Writer( **v )
            writers[ t + '-cflowd' ] = writer
            writer.start()
            all_threads.append( writer )
            v[ 'ipfix' ] = ipfix

        if ipfix:
            v[ 'cflowd' ] = False
            writer = ipfixd_app.writer.Writer( **v )
            writers[ t + '-ipfix' ] = writer
            writer.start()
            all_threads.append( writer )
            v[ 'cflowd' ] = cflowd

#
# Start the socket and packet threads.
#

    for (p,v) in list(cmdparse.ports.items()):
        s = ipfixd_app.sockets.Socket( p, profile=cmdparse.profile )
        s.start()
        sockets.append( s )
        all_threads.append( s )

        try:
            writer_cflowd = writers[ v['temp_directory'] + '-cflowd' ]
            writer = writer_cflowd
        except KeyError:
            writer_cflowd = None

        try:
            writer_ipfix = writers[ v['temp_directory'] + '-ipfix' ]
            writer = writer_ipfix
        except KeyError:
            writer_ipfix = None

        packet = ipfixd_app.packet.Packet(
            cmdparse, s, s.name, writer_cflowd, writer_ipfix )
        packet.start()
        packets.append( packet )
        all_threads.append( packet )

        log().info('INFO: Port %d is sending to thread "%s"' % (p, writer.name))

#
# Let's check for startup errors.
#

    time.sleep( 5 )
    for s in sockets:
        if s.should_stop():
            hup_handler( None, None )
    
    while True:
        time.sleep( 24*60*60 )      # Now, main thread responds to signals

    exit( get_exit() )

def usr1_handler( signum, frame ):

    """
    This handler prints some info output at the thread states.

    Returns:
        True: Some threads still live
        False: All threads dead
    """

    any_alive = False

    for t in all_threads:
        if t.is_alive():
            alive = 'is alive'
            any_alive = True
        else:
            alive = 'is DEAD'

        if signum == signal.SIGHUP or signum == signal.SIGTERM:
            if not t.is_alive() and not t.do_we_know_it_stopped():
                log().info( 'INFO: Thread Name: %s has stopped.' % ( t.name ) )
                t.know_it_stopped()
                continue
        elif not t.is_alive():
            log().error( 'ERROR: Thread Name: %s is NOT alive.' % ( t.name ) )
        else:
            ( z, m ) = t.qsize()
            log().info( 'INFO: Thread name: %s %s, '
                'queue cnt/max: %d/%d' % ( t.name, alive, z, m ) )
            try:
                t.print_metrics()
            except AttributeError:
                pass

    return( any_alive )

def stop_all_threads():

    """
    Requests all current threads to stop.  Probably an error.
    """

    for t in all_threads:
        t.stop()        # Tell all threads we want to stop

def hup_handler( signum, frame ):

    """
    This handler needs to convince the threads to stop, insure
    that they did, and then call exit(0).
    """

    log().info( "INFO: It's my time to be going!" )

    for t in all_threads:
        t.stop()        # Tell all threads we want to stop

    for s in sockets:
        if not s.is_alive():
            log().error( 'ERROR: Thread %s is already dead.' % s.name )
            continue

#
# Make a socket and send a 0 length packet to the server socket.
# This will cause the socket thread and threads depending on it
# to stop.
#

        ws = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
        ws.sendto( bytearray(0), ('localhost', s.port ) )
        ws.close()

    while usr1_handler( signal.SIGHUP, None ):
        time.sleep( 2 )

    log().info( 'INFO: All threads have stopped.  Shutdown complete.' )

    exit( get_exit() )

def term_handler( signal, frame ):

    """
    This is a faster termination.  It attempts to close cleanly by
    clearing all the queues and then just calling the standard hup
    handler.
    """

    log().info( 'INFO: Fast stop, clearing all queues.' )

    for t in all_threads:
        try:
            t.qempty()          # Not all threads have queues to empty.
        except AttributeError:
            pass

    hup_handler( signal, frame )

# End.
