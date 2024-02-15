"""
TO DO:
2055:/tmp:/tmp2 -p 2056:/tmp:/tmp3

can't be allowed.  We can't have the same temp dir going to different
dest dirs.  The dest dir should be allowed to default if specified
on a temp before, or it must match.
"""

import sys
import os
import argparse
import ipfixd_app.ipfixd_profile
from  ipfixd_app.ipfixd_log import log

last_write_timeout=300
ports = {}
temp_directories = {}
dest_directories = {}

class ParsePorts(argparse.Action):
    def __init__(self, option_strings, dest, nargs=None, **kwargs ):
        argparse.Action.__init__( self, option_strings, dest, **kwargs )

        if nargs is not None:
            raise ValueError

    def __call__(self, parse, namespace, values, option_string=None):

        global last_write_timeout

        last_cflowd = True
        last_ipfix = False

        l = values.split(':')

        if len(l) > 1:
            try:
                port = int(l[0])
                if port < 1 or port > 65535:
                    raise ValueError( 'port must be in the range 1-65535' )
            except ValueError:
                raise ValueError( 'port must be in the range 1-65535' )

        if len(l) < 2:
            raise ValueError( 'port:directory must be specified' )
        else:
            temp_directory = l[1]

        if len(l)>2:
            if l[2]:
                dest_directory = l[2]
            else:
                dest_directory = temp_directory     # Place holder
        else:
            dest_directory = temp_directory

        if len(l)>3:
            if l[3]:
                write_timeout=int(l[3])
                last_write_timeout = write_timeout
            else:
                write_timeout=last_write_timeout        # place holder
        else:
            write_timeout=last_write_timeout

        if len(l)>4:
            f = l[4].split(',')
            if f:
                last_cflowd = False
                last_ipfix = False
                for fmt in f:
                    if fmt == 'cflowd':
                        last_cflowd = True
                    elif fmt == 'ipfix':
                        last_ipfix = True
                    else:
                        raise ValueError( 'Unknown file format: %s' % fmt )
            
        cflowd=last_cflowd
        ipfix=last_ipfix

        if temp_directory[:-1] != os.sep:
            temp_directory += os.sep
        if dest_directory[:-1] != os.sep:
            dest_directory += os.sep

        temp_directory=os.path.normpath( os.path.normcase( temp_directory ))
        dest_directory=os.path.normpath( os.path.normcase( dest_directory ))

        if (temp_directory in temp_directories and
            temp_directories[ temp_directory ][ 'dest_directory' ] !=
                dest_directory):
            raise ValueError

        ports[port] = { 'port': port,
            'temp_directory': temp_directory,
            'dest_directory': dest_directory,
            'write_timeout': write_timeout,
            'cflowd': cflowd,
            'ipfix': ipfix }

        temp_directories[ temp_directory ] = ports[port]
        dest_directories[ dest_directory ] = ports[port]

def parse_args():

    """
    Parse the arguments.  Silly comment time.
    """

    p = argparse.ArgumentParser( description = 
        "Daemon that reads ipfix data from routers and switches and "
        "writes output files every so many minutes." )

    p.add_argument( '--ports', '-p',
        required=True,
        metavar='port:tempdir[:destdir[:write-timeout[:ipfix,cflowd]]]',
        action=ParsePorts,
        help='Specifies a UDP port to listen on, a temp directory '
            'to write the flow file output, a destination directory '
            'to move the temp file to, and a timeout for how often '
            'move the temp file to the destiniation directory.  The '
            'default destination directory is the same as the temp '
            'directory and the default write-timeout is the same as '
            'the last one specified.  The format of the output files '
            'may also be given as a comma seperated list.  The format '
            'defaults to "cflowd", and inherits from prior port '
            'arguments if not specified.  '
            'This option may be specified '
            'more than once.' )

    p.add_argument( '--nofork', '-f',
        action='store_true',
        help='Does not fork a daemon process.  Program runs in foreground.')

    p.add_argument( '--user',
        help='The user to run the daemon as.  Must be started as root '
            'and as a daemon.' )

    p.add_argument( '--group',
        help='The group to run the daemon as.  Must be start as root '
            'and as a daemon.' )

    p.add_argument( '--log',
        help = 'Specifies the syslog fac and level to use.' )

    p.add_argument( '--log-missing-full',
        action='store_true',
        default=False,
        help = 'Logs full info about missing flows instead of summary.' )

    p.add_argument( '--verbose', '-v',
        action='count',
        help="Turns on verbose output." )

    p.add_argument( '--log-unchanged-templates', '-T',
        action='store_true',
        help="When --verbose is used, log messages about unchanged templates "
            "being received." )

    p.add_argument( '--log_datarec', '-d',
        action='store_true',
        help="Display information on data records when --verbose" )

    if ipfixd_app.ipfixd_profile.profile():
        p.add_argument( '--profile',
            action='store_true',
            help="Profiles the program.  Since this program uses threads, "
                "it is easier to embed the profiling." )

    try:
        cmdparse = p.parse_args()
    except ValueError as e:
        e = str(e)
        log().error( 'ERROR: %s' % e )
        exit( 1 )

    setattr( cmdparse, 'ports', ports )
    setattr( cmdparse, 'temp_directories', temp_directories )
    setattr( cmdparse, 'dest_directories', dest_directories )
    if not ipfixd_app.ipfixd_profile.profile():
        setattr( cmdparse, 'profile', False )

    return( cmdparse )

# End.
