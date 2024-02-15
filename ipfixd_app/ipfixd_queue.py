import queue
import collections

class IterQueue( queue.Queue ):

    """
    This class returns the entire queue on any of the get* calls.
    The queue will always be empty after the calls.  The result
    returned by the get* call is iterable and generally has the
    characteristics of a list.  At this time, is is actually
    a collections.deque() object.

    On put* calls, the argument is assumed to be iterable, and
    all objects will be added to the queue.

    The primary advantage of these routines is that the necessary
    locks will only be taken once, and all the changes made.

    Note: maxsize can be exceeded on put.
    """

    def _put( self, items ):
        self.queue.extend( items )

    def _get( self ):
        q = self.queue
        self.queue = collections.deque()
        return( q )

# End.
