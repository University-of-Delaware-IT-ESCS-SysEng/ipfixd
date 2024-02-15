"""
This module contains the routine that sets up logging and a
routine that provides the current logging object.  The logging
object is derived from the system base module of logging.
"""



import logging
import logging.handlers

#
# _theconsole and _thesyslog handlers are kept accessable so we
# can modify them as needed, or remove them.
#

_thelog = None
_theo2log = None
_theconsole = None
_thesyslog = None

def log():
    """
    This routine returns the current log object.  This object
    is derived from the logging class.

    Args:
        None

    Returns:
        An object of class logging.
    """

    return( _thelog )

def set_logging( cmdparse ):

    """
    Sets up logging.  Creates the logging object returned by log().

    Args:
        cmdparse    -- The results of argument processing.  Attributes
                       such as log, which is used to set up syslog
                       logging, and verbose controls the logging
                       level.

    Returns
        None
    """

    global _thelog
    global _theo2log
    global _theconsole
    global _thesyslog

    _thelog = logging.getLogger( __name__ )
    _theo2log = logging.getLogger( 'oauth2client.util' )

    if hasattr( cmdparse, 'log' ) and cmdparse.log:
        if not _thesyslog:
            _thesyslog = logging.handlers.SysLogHandler( 
                address = '/dev/log',
                facility = logging.handlers.SysLogHandler.LOG_LOCAL1
            )

            syslog_format = logging.Formatter(
                fmt = '%(processName)s[%(process)d] %(message)s' )
            _thesyslog.setFormatter( syslog_format )

        _thesyslog.setLevel( logging.INFO )
        _thelog.addHandler( _thesyslog )
        _theo2log.addHandler( _thesyslog )
    elif _thesyslog:
        _thelog.removeHandler( _thesyslog )
        _theo2log.removeHandler( _thesyslog )
        _thesyslog = None

    if not _theconsole:
        _theconsole = logging.StreamHandler()
        _thelog.addHandler( _theconsole )
        _theo2log.addHandler( _theconsole )

    if hasattr( cmdparse, 'verbose' ) and cmdparse.verbose:
        _theconsole.setLevel( logging.INFO )
    else:
        _theconsole.setLevel( logging.WARN )

    _thelog.setLevel( logging.INFO )
    _theo2log.setLevel( logging.INFO )

def log_user_info( u, action ):

    """
    'u' is a Users Resource JSON converted to a dict, and action
    is a string like 'added' or 'updated'.  The main reason to
    use this routine is that input values are converted from the
    Unicode in the JSON based dict to iso_8859_1.

    Args:
        u: A dict containing a standard membersResource JSON -> Python
            object.
        action: What's the message about?

    Returns:
        None.
    """

    log().info( 'INFO: %s: %s user %s, %s' %
            ( u[ 'primaryEmail' ].encode( 'iso_8859_1' ),
              action,
              u[ 'name' ][ 'familyName' ].encode( 'iso_8859_1' ),
              u[ 'name' ][ 'givenName' ].encode( 'iso_8859_1' )
            ) )

# End.
