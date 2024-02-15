import sys
import time
import threading
import ipfixd_app.ipfixd_profile
if ipfixd_app.ipfixd_profile.profile():
    import cProfile

from  ipfixd_app.ipfixd_log import log

class IPFixdThread( threading.Thread ):

    """
    Parent class we use in the various threads in this program.
    Primarily contains the code for stopping the thread in a
    graceful manner.

    Generally, to cause a stop, call method stop and write a zero
    length packet on the queue the thread is watching.  It should
    always check should_stop before doing anything with a zero
    length packet.
    """

    def __init__( self, profile=False, **kwargs ):

        """
        Calls the Thread constructor with any arguments needed
        and creates the stop Event.

        Args:
            Any argument, by keyword, to the threading.Thread class.
        """

        threading.Thread.__init__( self, **kwargs )
        self._stop_event = threading.Event()
        self._know_it_stopped = False

        if ipfixd_app.ipfixd_profile.profile():
            if profile:
                import time
                self._profile = cProfile.Profile( time.process_time )
            else:
                self._profile = None
        else:
            self._profile = None

    def should_stop( self ):

        """
        Returns True if the thread should stop.
        """

        return( self._stop_event.is_set() )

    def i_do_not_want_to_stop( self ):
        self._stop_event.clear()

    def stop( self ):

        """
        Call when the thread should stop.  The thread will attempt a
        graceful cleanup.  You probably want to call this for all
        threads derived from this class.  They should actually stop
        when a 0 length queue item is found.
        """

        self._stop_event.set()

    def know_it_stopped( self ):

        """
        This function can be used to mark a thread as stopped and perhaps
        some error message issued about the thread stopping.  The
        caller can make use of "do_we_know_it_stopped" when deciding
        if a message should be issued.

        Args:
            None.
        Returns:
            None.
        """

        self._know_it_stopped = True

    def do_we_know_it_stopped( self ):

        """
        This function can be used to return if we know the thread has
        stopped because we marked it so.  Useful when emitting a
        single set of errors for a thread instead of lots.

        Args:
            None.
        Returns:
            True if we know the thread is stopped.
        """

        return( self._know_it_stopped )

# End.
