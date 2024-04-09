/**
    $Id: readflows.c,v 1.19 2005/05/25 17:20:14 mike Exp $.

    This program reads CISCO V5 netflow records flows from one or
    more UDP ports.  It checks the received datagram to make sure
    the length is correct, etc, and then reformats the CISCO
    netflow V5 flow into "cflowd" format.  After "interval"
    seconds, the current flow is re-linked with a new name into a
    "saved" directory and a new current file started.  It is
    expected that some external program will process the saved flow
    file.  Or maybe the installation just wants to leave it there.
    A sample processing script, called flowscan.sh, is included.

    The program uses threads in order to manage state.  There are
    Reader threads that allocate free buffers and read datagrams
    into these buffers, and move the buffer onto a write buffer
    queue.  There is a writer thread that looks for buffers that
    the readers queued.  After the write occurs, the buffers are
    returned to the free list.

    The most important thread, in many respects, is the
    WriterThread.  A cancel thread handler covers the thread.  A
    SIGTERM handler is used to catch a normal kill.  When caught,
    the WriteThread is canceled.  A cancel handler is in effect for
    the WriteThread.  This handler cleans up by closing any files,
    and moving the current file into the save area.

    A "Done" flag is also set in the SIGTERM handler.  This flag
    doesn't really cause anything to happen, but it can be used to
    supress error messages that might happen when the process is
    ending.  Note in particular LogThread.

    The only reason why this program ever stops (except for
    errors), is a SIGTERM causes the Sigterm handler to run.  This
    handler cancels the WriteThread.  The WriteThread cleans up and
    exits.  main was pthread_joined to WriteThread, so the
    pthread_join ends, and then main ends after doing a bit more
    cleanup.  See the final message from main() and see it in the
    log file.

    There is a problem that happens when we've run out of buffers.
    The write thread eventually consumes a buffer.  This makes a
    reader dispatchable.  It uses the buffer and we log "out of
    buffs".  The writer then writes it, etc.  We sort of get into a
    thread thrashing.  So, I wrote GetArrayOfBuffs, which might
    help.  However, it has not been tested and it is not in use.
    The idea is probably good, but the code might not be since it
    has never executed.

    Another idea: when binding to the port and getting INUSE, sleep
    and try again.  Log attempts and log when we finally get the
    port.  This is useful when attempting to restart the server.  The
    old process might not have terminated yet.
**/

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <pwd.h>
#include <getopt.h>

#include <pthread.h>

#include "cflowd-v5.h"
#include "hash.h"

#define VERSION_MAJOR	1
#define VERSION_MINOR	1
#define VERSION_PATCH	0

/*
    Command line parameters parse results.
*/

#define MAX_PORTS 256

typedef struct {
    int port[ MAX_PORTS ];	/* Port(s) to listen on */
    int nodropped[ MAX_PORTS ];	/* Don't do dropped flows checking on port */
    int num_ports;		/* Number of ports */
    int max_drop;		/* Maximum flows to drop wo/logging */
    int save_secs;		/* Secs to wait before relink current to */
				/* saved */
    int num_buffs;		/* Number of socket IO buffers to allocate */

    int nodaemon;		/* Do not fork for daemon mode */

    char logfac[ 20 ];		/* Name of logging facility */
				/* If == "", then -> stderr */
    int logint;			/* logfac converted to int - not by user */

    char new_user[ L_cuserid ];		/* User name for setuid */

    int  current_mode;			/* (ch)mod for 'current' file */
    int  saved_mode;			/* (ch)mod for 'saved' files */

    char current[ PATH_MAX + 1 ];	/* Place to store current flows */
    char saved[ PATH_MAX + 1 ];		/* Place to store saved flows */
} cmdparse_t;

/*
    Define defaults for the parameters.
*/

#define DEFAULT_PORT 2056
#define DEFAULT_MAX_DROP 0
#define DEFAULT_SAVE_SECS 300
#define DEFAULT_NUM_BUFFS 500

#define DEFAULT_NODAEMON 0
#define DEFAULT_LOGFAC   "local6"

#define DEFAULT_NEW_USER  ""

#define DEFAULT_CURRENT_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)
#define DEFAULT_SAVED_MODE DEFAULT_CURRENT_MODE

#define DEFAULT_CURRENT "/netflow/flows.current"
#define DEFAULT_SAVED   "/netflow/prefetch/flows."

static cmdparse_t c;

/*
    Keeps track of the last sequence number we saw from a
    particular router.  We want this information so we know if we
    are dropping flows.
*/

typedef struct {
    ipv4addr_t	router;		/* Hash table key.  Don't move! */
    uint32_t    expected_seq;	/* Sequence number we expect to see */
} LastSeq_t;

static PTHashOpenTable LastSeqTable;	/* Hash table for 'LastSeq_t'. */

#define MAX_ROUTERS 1000
						/* LastSeqTable hash table. */

static int MakeLastSeqTable( void );		/* Make table */
static void FindLastSeq( ipv4addr_t router,	/* Manipulate table */
			 uint32_t CurrSeq, uint32_t NumFlows, int * dropped );
static int DeleteLastSeqTable( void );		/* Delete the table */

/**
    Queues.

    Primitive queue routines.  Queue adds a Queue_t object to the
    head of the queue.  Dequeue removes an object from the tail of
    the queue.  The caller is responsible for finding the actual
    blocks that will be added, etc.  Basically, all these routines
    do is a bit of pointer manipulation.
**/

typedef struct Queue {
    struct Queue * next;
    struct Queue * prev;
    void    * obj;
} Queue_t;

static void InitQueue( Queue_t * head );
static void Queue( Queue_t * head, Queue_t * new );
static Queue_t * Dequeue( Queue_t * head );

/**
    Buffers.

    The mutexes are used to cover any operations on the free_q or
    the buff_q.

    AddFreeBuff is used to add a Queue_t object to the free buffer
    list.  GetFreeBuff is used to get a free buffer to work with.
    GetFreeBuff can block if there aren't any free buffers and the
    second argument, waitfree, is true.  If waitfree is false, then
    GetFreeBuff will remove an entry from buff_q and use that as a
    free buff.  You would do this if you want to drop old objects
    that are queued instead of dropping new items to put in the
    buffer.  Depends on the behavior you want.

    The actual data object object is available from Queue_t->obj.
    When done working with the buffer, queue it for further work
    using AddBuff.  When this is done, pthread_cond_signal is
    issued for the 'buff_q_cond' waiter.  GetBuff is used to pull a
    buffer off the buff_q.  When processed, it should be added back
    to the free_q by calling AddFreeBuff.  GetBuff will block until
    there is a buffer available using pthread_cond_wait.
*/

typedef struct {
    pthread_mutex_t buff_q_mutex;	/* Mutex that covers buff_q. */
    pthread_mutex_t free_q_mutex;	/* Mutex that covers free_q. */
    pthread_cond_t  buff_q_cond;	/* Cond for available ent in buff_q */
    pthread_cond_t  free_q_cond;	/* Cond for available ent in free_q */

    Queue_t free_q;		/* Queue of free buffers */
    Queue_t buff_q;		/* Queue of buffers that need writing */
    int     free_q_cnt;		/* # of elements in free_q */
    int     buff_q_cnt;		/* # of elements in buff_q */

    const char * name;		/* Name of buffer - used in messages. */
} Buff_t;

static void AddFreeBuff( Buff_t *, Queue_t * );
static Queue_t * GetFreeBuff( Buff_t *, int waitfree );
static void AddBuff( Buff_t *, Queue_t * );
static Queue_t * GetBuff( Buff_t * );

/*
    Allocate the CISCO buffer header.
*/

Buff_t CISCOBuffs;

/*
    Define the actual obj type we are working with in the buffer
    queue.
*/

typedef struct {
    int len;			/* Length of the buffer */
    ipv4addr_t router;		/* Router that sent the buffer */
    int nodropped;		/* Don't do dropped flow checks */
    char CISCOBuff[ CISCO_V5_BUFF_SIZE ];
} CISCOBuff_t;

/*
    Structures passed to the threads.
*/

typedef struct {
    int port;		/* Port the reader should start on */
    int nodropped;	/* Don't do dropped flows checks */
} ReadThread_t;

/*
    Network routines.
*/

static int Bind( int port );
static ssize_t ReadCISCOFlow( int s, void * buff, ipv4addr_t * router );
static int ValidateCISCOFlow( void * buff, ssize_t len, ipv4addr_t router,
	int nodropped, int * dropped );
static ssize_t CvtCISCOV5ToCflowd( char * CISCOBuff, char * CflowdBuff,
	ipv4addr_t router );
static char * PrintIP( char * buff, ipv4addr_t );

/*
    Couple of globals.
*/

static const char * argv0;

/*
    This flag is used to suppress error messages when shutting
    down.
*/

static volatile int Done;
static volatile int DoneAndGone;

/*
    We want to protect the write thread.  Need to make sure
    that all flows are processed, buffers flushed and files
    moved.  This thread is canceled from the SIGTERM handler,
    which is why it is exposed here.
*/

static pthread_t writeThread;

static void Sigterm( int sig );

/**
    End of globals.
**/

static void
Info( const char * fmt, ... )

/**
    Log routine.  Uses syslog if c.logfac[0] != '\0', else stdout.
**/

{
    va_list args;

    va_start( args, fmt );

    if (c.logfac[ 0 ] == '\0') {
	fprintf( stdout, "%s: ", argv0 );
	vfprintf( stdout, fmt, args );
    } else {
	vsyslog( c.logint | LOG_INFO, fmt, args );
    }
}

/**
    End of Info.
**/

static void
Log( const char * fmt, ... )

/**
    Log routine.  Uses syslog if c.logfac[0] != '\0', else stderr.
**/

{
    va_list args;

    va_start( args, fmt );

    if (c.logfac[ 0 ] == '\0') {
	fprintf( stderr, "%s: ", argv0 );
	vfprintf( stderr, fmt, args );
    } else {
	vsyslog( c.logint | LOG_ERR, fmt, args );
    }
}

/**
    End of Log.
**/

static void *
Malloc( size_t size )

/**
    Simple malloc with error checking.
**/

{
    void * ptr;

    ptr = malloc( size );

    if (ptr == NULL) {
	Log( "failed to malloc %u bytes: %s\n", size, strerror( errno ));
	exit( 1 );
    }

    return( ptr );
}

/**
    End of Malloc.
**/

static void
Help( FILE * f )

/**
    Prints help.  When invoked via -h, f should be stdout.  When
    invoked because of an error, f should be stderr.
**/

{
    if (c.num_ports == 0) {
	c.port[ 0 ] = DEFAULT_PORT;
	c.num_ports = 1;
    }

    strcpy( c.logfac, DEFAULT_LOGFAC );

    fprintf( f, "Version %d.%d.%d of ReadFlows.\n",
	VERSION_MAJOR, VERSION_MINOR,VERSION_PATCH );
    fprintf( f, "\n\
Listens for CISCO V5 NetFlow packets on UDP port(s).  Converts to \"cflowd\"\n\
format and saves to file \"current\".  Every \"save\" seconds, rename\n\
the file to \"saved\" with a date-time appended.\n\
Specify logging facility, modes for the related files, *not* to fork\n\
as a daemon, and user name to change to.  Note that umask is set to 0\n\
and the cwd is set to \"\\\" unless -d is used.\n\n\
-p can be specified more than once, allowing multiple ports to be processed\n\
into one output file.\n\n"
);

    fprintf( f, "%s: [args]\n", argv0 );
    fprintf( f, "    -p <udp-port> UDP port to listen on [%d]\n",
	c.port[ 0 ] );
    fprintf( f, "    -n            No dropped flow checks for last -p []\n" );
    fprintf( f, "    -i <secs>     Save current file ever n secs [%d]\n",
	c.save_secs );
    fprintf( f, "    -b <#>        Number of socket buffers [%d]\n",
	c.num_buffs );
    fprintf( f, "    -m <num-flows> Max flows/save dropped wo/logging [%d]\n",
	c.max_drop );
    fprintf( f, "    -d            Do NOT fork and run in background [%s]\n",
	c.nodaemon ? "yes" : "no" );
    fprintf( f, "    -u <new-user> Change uid to this user [%s]\n",
	c.new_user );
    fprintf( f, "    -U            Clears <new-user>\n" );
    fprintf( f, "    -l <log-fac>  Syslog using this facility [%s]\n",
	c.logfac );
    fprintf( f, "    -L            Clears <log-fac>, uses stderr\n" );
    fprintf( f, "    -c <path>     Path to \"current\" file [%s]\n",
	c.current );
    fprintf( f, "    -s <path>     Prefix of path to \"saved\" files [%s]\n",
	c.saved );
    fprintf( f, "    -x <current: mode> Mode for \"current\" file [%o]\n",
	c.current_mode );
    fprintf( f, "    -y <saved: mode>   Mode for \"saved\" files [%o]\n",
	c.saved_mode );
}

/**
    End of Help.
**/

static int
Cvtlogfac( const char * logfac )

/**
    Converts a log facility name to an integer.  Make sure that
    c.logfac[ 0 ] == '\0' before calling this routine.
**/

{
    int i;

    typedef struct {
	const char * name;
	int logint;
    } logmap_t;

    logmap_t logmap[] = {
	"auth", LOG_AUTH, "cron", LOG_CRON, "daemon", LOG_DAEMON,
	"kern", LOG_KERN,
	"local0", LOG_LOCAL0, "local1", LOG_LOCAL1, "local2", LOG_LOCAL2,
	"local3", LOG_LOCAL3, "local4", LOG_LOCAL4, "local5", LOG_LOCAL5,
	"local6", LOG_LOCAL6, "local7", LOG_LOCAL7,
	"lpr", LOG_LPR, "mail", LOG_MAIL, "news", LOG_NEWS,
	"syslog", LOG_SYSLOG, "user", LOG_USER, "uucp", LOG_UUCP, NULL, 0
    };

    for( i = 0; logmap[i].name != NULL; i++ ) {
	if (strcmp( logmap[i].name, logfac ) == 0) {
	    c.logint = logmap[i].logint;
	    strcpy( c.logfac, logfac );
	    return( 0 );
	}
    }

    Log( "unable to find syslog facility %s.\n", logfac );

    return( 1 );

}

/**
    End of Cvtlogfac.
**/

static int
Changeuid( void )

/**
    If c.new_user[ 0 ] != 0, change the uid and gid to
    the specified user.
**/

{
    struct passwd * pw;

    if (c.new_user[ 0 ] == '\0') return( 0 );

    pw = getpwnam( c.new_user );

    if (pw == NULL ) {
	Log( "unable to find information on user '%s': %s\n",
	    c.new_user, strerror( errno ) );
	return( -1 );
    }

    if (setgid( pw->pw_gid )) {
	Log( "unable to setgid( %d ), where gid is default for %s: %s\n",
	    pw->pw_gid, c.new_user, strerror( errno ) );
	return( -1 );
    }

    if (setuid( pw->pw_uid )) {
	Log( "unable to setuid( %d ), where uid is uid of %s: %s\n",
	    pw->pw_uid, c.new_user, strerror( errno ));
	return( -1 );
    }

    return( 0 );
}

/**
    End of Changeuid.
**/

static int
Cmdparse( int argc, char * argv[] )

/**
    Parse command line.  Returns 0 if all OK, else exit.
**/

{
    int default_logfac = 1;
    int port;

    char current[ PATH_MAX + 1 ];	/* Place to store current flows */
    char saved[ PATH_MAX + 1 ];		/* Place to store saved flows */


    argv0 = (argc >= 1) ? argv[ 0 ] : "<unknown>";

    c.save_secs	= DEFAULT_SAVE_SECS;
    c.num_buffs	= DEFAULT_NUM_BUFFS;
    c.nodaemon	= DEFAULT_NODAEMON;
    c.max_drop  = DEFAULT_MAX_DROP;

    strcpy( c.new_user, DEFAULT_NEW_USER );

    c.current_mode = DEFAULT_CURRENT_MODE;
    c.saved_mode   = DEFAULT_SAVED_MODE;

    strcpy( c.current, DEFAULT_CURRENT );
    strcpy( c.saved, DEFAULT_SAVED );

    while( 1 ) {
	int r;

	r = getopt( argc, argv, "b:c:dhi:l:Lm:np:s:u:Ux:y:" );
	if (r == -1) break;

	switch( r ) {
	    case 'p':
		port = strtol( optarg, NULL, 10 );	/* Get port # */
		if (port < 1 || port >= 1<<16) {
		    Log( "0 < port < %d, was %d.\n", 1<<16, port);
		    return( -1 );
		}

		if (c.num_ports == MAX_PORTS) {
		    Log( "can only monitor %d ports.  Failed on port %d.\n",
			MAX_PORTS, port );
		    return( -1 );
		}

		c.nodropped[ c.num_ports ]  = 0;
		c.port[ c.num_ports++ ] = port;

		break;

	    case 'n':
		if (c.num_ports < 1) {
		    Log( "for -n, must specify a port first with -p.\n" );
		    exit( 1 );
	  	}
		c.nodropped[ c.num_ports - 1 ]  = 1;
		break;

	    case 'i':
		c.save_secs = strtol( optarg, NULL, 10 );
		break;

	    case 'b':
		c.num_buffs = strtol( optarg, NULL, 10 );
		break;

	    case 'm':
		c.max_drop = strtol( optarg, NULL, 10 );
		break;

	    case 'x':
		c.current_mode = strtol( optarg, NULL, 8 ) & 0777;
		break;

	    case 'y':
		c.saved_mode = strtol( optarg, NULL, 8 ) & 0777;
		break;

	    case 'd':
		c.nodaemon = 1;
		break;

	    case 'c':
		c.current[ sizeof c.current - 1 ] = '\0';
		strncpy( c.current, optarg, sizeof c.current - 1 );
		break;

	    case 's':
		c.saved[ sizeof c.saved - 1 ] = '\0';
		strncpy( c.saved, optarg, sizeof c.saved - 1 );
		break;

	    case 'u':
		c.new_user[ sizeof c.new_user - 1 ] = '\0';
		strncpy( c.new_user, optarg, sizeof c.new_user - 1 );
		break;

	    case 'U':
		c.new_user[ 0 ] = '\0';
		break;

	    case 'l':
		if (Cvtlogfac( optarg )) {
		    exit( 1 );
		}
		default_logfac = 0;
		break;

	    case 'L':
		c.logfac[ 0 ] = '\0';
		default_logfac = 0;
		break;

	    case 'h':
		Help( stdout );
		exit( 0 );

	    case '?':
		Help( stderr );
		exit( 1 );


	}
    }

    if (default_logfac) {
	Cvtlogfac( DEFAULT_LOGFAC );
    }

    if (c.num_ports == 0) {
	c.port[ 0 ] = DEFAULT_PORT;
	c.num_ports = 1;
    }

    Changeuid();		/* If one was passed via -u */

    return( 0 );
}

/**
    End of Cmdparse.
**/

static char *
PrintIP( char * buff, ipv4addr_t ip )
                                                                                
/**
    Prints an ip...
**/
                                                                                
{
    inet_ntop( AF_INET, &ip, buff, INET_ADDRSTRLEN );
                                                                                
    return( buff );
}
 
/**
    End of print_ip.
**/

static int
Bind( int port )

/**
    Get socket, set it up, etc.  Returns the socket or -1.
**/

{
    struct sockaddr_in sinfo;	/* Socket info */
    struct in_addr saddr;	/* Address and port info */

    int s;

/*
    Get the socket.
*/

    s = socket( PF_INET, SOCK_DGRAM, IPPROTO_UDP );
    if (s == -1) {
	Log( "socket(): %s.\n", strerror( errno ));
	return( -1 );
    }

/*
    Bind to the UDP port we want to listen on.
*/

    memset( &saddr, 0, sizeof saddr );
    saddr.s_addr     = htonl( (uint32_t) INADDR_ANY );

    memset( &sinfo, 0, sizeof sinfo );
    sinfo.sin_family = AF_INET;
    sinfo.sin_port   = htons( (uint16_t) port );

    memcpy( &sinfo.sin_addr, &saddr, sizeof saddr );

    if (bind( s, (struct sockaddr *) &sinfo, sizeof sinfo ) == -1) {
	Log( "bind(): %s.\n", strerror( errno ));
	return( -1 );
    }

/*
    Starting with a MB, find the largest buffer we can set for the
    socket.  If we get all the way down to 2KB bytes, give up.
    Something must be wrong.

    On Solaris, you can do:

	ndd -set /dev/udp   udp_max_buf 2097152

    to get a larger buffer size.
*/

    {
	int n = 2<<20;	/* 2MB */

	while( 1 ) {
	    if (setsockopt( s, SOL_SOCKET, SO_RCVBUF, &n, sizeof(n)) != 0) {
		if (errno == ENOBUFS && n > 2048) {
		    n = n / 2;
		} else {
		    Log( "setsockopt( ..., SO_RCVBUF, ...): %s.\n",
			strerror( errno ));
		    return( -1 );
		}
	    } else {
		Info( "Set setsockopt( ..., SO_RCVBUF, ... ) to %d.\n", n );
		break;
	    }
	}
    }

    return( s );
}

/**
    End of Bind.
**/

static ssize_t
ReadCISCOFlow( int s, void * buff, ipv4addr_t * router )

/**
    Reads a (hopefully) V5 CISCO format flow into buff (which must be
    CISCO_V5_BUFF_SIZE bytes long).  Returns the number of bytes
    read or -1.

    recvmsg seems to do a little better than recvfrom.  We still
    have the problem of dropped datagrams, though.  We know
    datagrams are dropped because we note missing sequence numbers
    in the flows.  See later routines for more information.

    I tried using either more buffers or longer buffers.  Neither
    had an effect.  I also tried setting SO_REUSEADDR, which with
    UDP allows multiple binds to the same port at the same time
    (UDP is different than TCP).  However, this didn't help
    either.  Other bound sockets didn't pick up the "slack", so to
    speak.

    We return the IP address of the sender - or at least what the
    UDP packet says...
**/

{
    struct sockaddr_in sinfo;	/* Socket info */
    ssize_t len;		/* Length of datagram we read */

    struct iovec vec[1];
    struct msghdr msg;

    vec[0].iov_base = (void *) buff;
    vec[0].iov_len  = CISCO_V5_BUFF_SIZE;

    msg.msg_name    = (void *) &sinfo;
    msg.msg_namelen = sizeof sinfo;
    msg.msg_iov	    = vec;
    msg.msg_iovlen  = 1;

    while( 1 ) {
	len = recvmsg( s, &msg, 0 );
	if (len == -1 && errno == EINTR) {
	    continue;
	} else {
	    break;
	}
    }

    if (len == -1) {
	Log( "recvmsg() failed: %s\n", strerror( errno ));
	exit( 1 );
    } else {
	*router  = (ipv4addr_t) sinfo.sin_addr.s_addr;
	return( len );
    }
}

/**
    End of ReadCISCOFlow.
**/

static int
ValidateCISCOFlow( void * buff, ssize_t len, ipv4addr_t router, int nodropped,
	int * dropped )

/**
    Validates the contents of the CISCO flow packet.  Returns 0 if
    the datagram is good, else -1 if bad.  buff is a pointer to a
    supposed CISCO V5 flow record, including header.  Len is the
    length of the packet received from the "wire", not the length
    of buffer 'buff'.
**/

{
    static int version_noted;
    flow_header_t * fh;

    if (len < sizeof( flow_header_t )) {
	Log( "packet len (%d) less than header len (%d).\n",
	     len, sizeof( flow_header_t ) );
	return( -1 );
    }

    fh = (flow_header_t *) buff;

    if ( ntohs( fh->version ) != CISCO_V5) {
	if (!version_noted) {
	    Log( "seeing flows for version %d.\n", ntohs( fh->version ) );
	    version_noted = 1;
	}
	return( -1 );
    }

/*
    Make sure the sizes match up.
*/

    if ((sizeof( flow_header_t ) +
		(ntohs( fh->cnt ) * CISCO_V5_FLOW_LEN)) != len) {
	Log( "packet length of %d doesn't make sense with cnt=%d.\n",
	    len, ntohs( fh->cnt ) );
	return( -1 );
    }


/*
    See if the sequence numbers work out for a given router.
*/

    if (!nodropped) {
	FindLastSeq( router, ntohl( fh->flow_sequence ), 
		ntohs( fh->cnt ), dropped );
    }

    return( 0 );
}

/**
    End of ValidateCISCOFlow.
**/

static ssize_t
CvtCISCOV5ToCflowd( char * CISCOBuff, char * CflowdBuff, ipv4addr_t router )

/**
    Convert the CISCO V5 buffer to cflowd format.  Returns the
    length of the cflowd buffer.
**/

{

/*
    Input pointers.  Header and a pointer to move through the
    input records.
*/

    flow_header_t * fh   = (flow_header_t *) CISCOBuff;
    cisco_v5_flow_t * cf = (cisco_v5_flow_t *)
				&(CISCOBuff[ sizeof( flow_header_t ) ]);

/*
    Output pointer.  Don't use sizeof flow_t because the result is
    not correct.  Also, not aligned, so we have to use a little
    buffer on the stack.
*/

    flow_t * pf         = (flow_t *) CflowdBuff;
    flow_t    f;

    uint32_t unix_secs;	/* Router's time */
    int uptime;		/* Time router has been up in milliseconds */
    int i;		/* Loop counter */
    int NumFlows;	/* Number of flows in datagram CISCOBuff */
    int FlowSeq;	/* Current flow sequence index */

    unix_secs	= ntohl( fh->unix_secs );
    uptime	= ntohl( fh->uptime );
    NumFlows	= ntohs( fh->cnt );
    FlowSeq	= ntohl( fh->flow_sequence );

/*
    For all flows in the datagram.
*/

    for( i = 0; i < NumFlows; i++ ) {
	f.router	= ntohl( router );
	f.index		= FlowSeq++;
	f.srcIpAddr	= ntohl( cf->srcIpAddr );
	f.dstIpAddr	= ntohl( cf->dstIpAddr );
	f.ipNextHop	= ntohl( cf->ipNextHop );
	f.inputIfIndex	= ntohs( cf->inputIfIndex );
	f.outputIfIndex	= ntohs( cf->outputIfIndex );
	f.pkts		= ntohl( cf->pkts );
	f.bytes		= ntohl( cf->bytes );

/*
    This code is flawed because it does not take into account
    counter wraps that would happen at 23 days of uptime.  Well, if
    it does, it is an accident.
*/

	f.startTime	= (((int) ntohl( cf->startTime ) - uptime)/1000) +
								unix_secs;
	f.endTime	= (((int) ntohl( cf->endTime )   - uptime)/1000) +
								unix_secs;

	f.srcPort	= ntohs( cf->srcPort );
	f.dstPort	= ntohs( cf->dstPort );
	f.tcpFlags	= cf->tcpFlags;
	f.protocol	= cf->protocol;
	f.tos		= cf->tos;
	f.srcAs		= ntohs( cf->srcAs );
	f.dstAs		= ntohs( cf->dstAs );
	f.srcMaskLen	= cf->srcMaskLen;
	f.dstMaskLen	= cf->dstMaskLen;

	memcpy( pf, &f, FLOW_LEN );

	pf  = (flow_t *) (((char *) pf) + FLOW_LEN);
	cf = (cisco_v5_flow_t *) (((char *) cf) + CISCO_V5_FLOW_LEN);
    }

    return( NumFlows * FLOW_LEN );
}

/**
    End of CvtCISCOV5ToCflowd.
**/

static int
MakeLastSeqTable( void )

/**
    Makes the hash table used to keep track of the last sequence
    number for a given router's IP address.
**/

{
    LastSeqTable = HashOpenFixedNew( 0, sizeof( ipv4addr_t ) );
    if (LastSeqTable == NULL) {
	Log( "HashOpenFixedNew failed.\n" );
	return( -1 );
    }

    return( 0 );
}

/**
    End of MakeLastSeqTable.
**/

static void
FindLastSeq( ipv4addr_t router, uint32_t CurrSeq, uint32_t NumFlows,
    int * dropped )

/**
    Finds the last sequence number we saw for a given router.  If
    the last sequence number != CurrSeq, output an error message if
    dropped > c.max_dropped.  Update LastSeq, taking into account
    any overflow that might happen.

    If we don't have any information for the router, then just
    add an entry.
**/

{
    static int LastSeqCnt;		/* Cnt of entries in LastSeq */
    static LastSeq_t LastSeq[ MAX_ROUTERS ];	/* Backing array indexed by */

    LastSeq_t * lsp;
    int rc;

    lsp = &(LastSeq[ LastSeqCnt ]);

/*
    Set up the entry as if we are going to add it.  We should be OK
    with wrapping because the router will wrap, too.  We only need
    to get a bit tricky if we happen to drop a packet during a wrap
    and wish to accurately report the number of dropped packets.
    Dropping packet testing is easy - just Ctrl-Z the process when
    in foreground and resume it.

    Note that on rc == -2, HashOpenAdd2 returns a pointer to the
    'lsp' it finds, and not the original pointer we passed.
*/

    lsp->router = router;
    lsp->expected_seq = CurrSeq + NumFlows;

    rc = HashOpenAdd2( LastSeqTable, (const void **) &lsp, NULL, 0 );
    if (rc == -2) {		/* Duplicate, we have ptr in 'lsp'. */
	if (lsp->expected_seq != CurrSeq) {
	    uint32_t this_drop;
	    char IPBuff[ INET_ADDRSTRLEN ]; 

	    if (CurrSeq < lsp->expected_seq) {	/* Wrapped sequence #s */
		this_drop = (uint32_t) 0xffffffff - lsp->expected_seq + 1 +
				CurrSeq;
	    } else {
		this_drop = CurrSeq - lsp->expected_seq;
	    }

	    *dropped += this_drop;

	    if (*dropped >= c.max_drop) {
		Info( "dropped %u flows (%u - %u) from router %s.\n",
		    this_drop, lsp->expected_seq, CurrSeq - 1,
		    PrintIP( IPBuff, router ) );
	    }
	}

	lsp->expected_seq = CurrSeq + NumFlows;
    } else if (rc == 0) {	/* Added entry */
	LastSeqCnt++;		/* Update counter */
    } else {
	Log( "HashOpenAdd2: memory error.\n" );
	exit( 1 );
    }
}

/**
    End of FindLastSeq.
**/

static int
DeleteLastSeqTable( void )

/**
    Deletes the hash table for LastSeq.  Returns 0 if it worked.
**/

{
    if (LastSeqTable == NULL) return( 1 );

    LastSeqTable = HashOpenFree( LastSeqTable );

    return( !(LastSeqTable == NULL) );
  
}

/**
    DeleteLastSeqTable.
**/

/**
    Thread manipulation.  Check for errors.
**/

static void
Pthread_create( pthread_t * thread, pthread_attr_t * attr,
    void * (*start_routine)(void *), void * arg )

{
    int err;

    if ((err = pthread_create( thread, attr, start_routine, arg ))) {
	Log( "error creating thread (%d): %s\n", err, strerror( err ) );
	exit( 1 );
    }
}

static void
Pthread_join( pthread_t thread, void ** trtn )

{
    int err;

    if ((err = pthread_join( thread, trtn ))) {
	Log( "error in pthread_join: %s\n", strerror( err ) );
	exit( 1 );
    }
}

static void
Pthread_mutex_init( pthread_mutex_t * mutex )

{
    int err;

    if ((err = pthread_mutex_init( mutex, NULL ))) {
	Log( "error in pthread_mutex_init: %s\n", strerror( err ) );
	exit( 1 );
    }
}

static void
Pthread_mutex_lock( pthread_mutex_t * mutex )

{
    int err;

    if ((err = pthread_mutex_lock( mutex ))) {
	Log( "error in pthread_mutex_lock: %s\n", strerror( err ) );
	exit( 1 );
    }
}

static void
Pthread_mutex_unlock( pthread_mutex_t * mutex )

{
    int err;

    if ((err = pthread_mutex_unlock( mutex ))) {
	Log( "error in pthread_mutex_unlock: %s\n", strerror( err ) );
	exit( 1 );
    }
}

static void
Pthread_cond_init( pthread_cond_t * cond )

{
    int err;

    if ((err = pthread_cond_init( cond, NULL ))) {
	Log( "error in pthread_cond_init: %s\n", strerror( err ) );
	exit( 1 );
    }
}

static void
Pthread_cond_wait( pthread_cond_t * cond, pthread_mutex_t * mutex )

{
    int err;

    if ((err = pthread_cond_wait( cond, mutex ))) {
	Log( "error in pthread_cond_wait: %s\n", strerror( err ) );
	exit( 1 );
    }
}

static void
Pthread_cond_signal( pthread_cond_t * cond )

{
    int err;

    if ((err = pthread_cond_signal( cond ))) {
	Log( "error in pthread_cond_signal: %s\n", strerror( err ) );
	exit( 1 );
    }
}

static void
Pthread_cancel( pthread_t tt )

{
    int err;

    if ((err = pthread_cancel( tt ))) {
	Log( "error in pthread_cancel: %s\n", strerror( err ) );
	exit( 1 );
    }
}
    

/**
    End of Pthread routines.
**/

static void
InitQueue( Queue_t * head )

/**
    Init a queue.
**/

{
    head->next = head;
    head->prev = head;
    head->obj  = NULL;
}

/**
    End of InitQueue.
**/

static void
Queue( Queue_t * h, Queue_t * new )

/**
    Add a queue object to the tail of the list.
**/

{
    new->prev = h->prev;
    new->next = h;

    h->prev->next = new;
    h->prev   = new;
}

/**
    End of Queue.
**/

static Queue_t *
Dequeue( Queue_t * head )

/**
    Remove an object from the head of the list.
**/

{
    Queue_t * obj = head->next;

    obj->next->prev	= obj->prev;
    obj->prev->next	= obj->next;

    obj->next = NULL;	/* Mickey says "Safety First" */
    obj->prev = NULL;

    return( obj );
}

/**
    End of Dequeue.
**/

static void
BuffInit( Buff_t * b, int num_buffs, size_t obj_size, const char * name )

/**
    Initialize a buffer.
**/

{
    Queue_t (*q)[];
    void * obj;
    int i;

    memset( b, '\0', sizeof( Buff_t ) );

    b->name = name;		/* Used in messages */

    Pthread_mutex_init( &(b->buff_q_mutex) );
    Pthread_mutex_init( &(b->free_q_mutex) );
    Pthread_cond_init( &(b->buff_q_cond) );
    Pthread_cond_init( &(b->free_q_cond) );

    InitQueue( &(b->free_q) );
    InitQueue( &(b->buff_q) );

/*
    Get the queue array and the array of actual buffers.  Set the
    buffer pointer for each queue entry, and then add the queue
    entry (with it's associated buffer) to the free queue.
*/

    q	= Malloc( num_buffs * sizeof( Queue_t ) );
    obj	= Malloc( num_buffs * obj_size );

    for( i = 0; i < num_buffs; i++ ) {
	(*q)[i].obj = obj;
	AddFreeBuff( b, &((*q)[i]) );

	obj = (void *) ( ((char *)obj) + obj_size );
    }
}

/**
    End of BuffInit.
**/

static void
AddFreeBuff( Buff_t * b, Queue_t * q )

/**
    Add a buffer to the free queue.  We'll signal free_q_cond in case
    anything was waiting for a free buffer.
**/

{
    Pthread_mutex_lock( &(b->free_q_mutex) );
    Queue( &(b->free_q), q );
    b->free_q_cnt++;
    Pthread_cond_signal( &(b->free_q_cond) );
    Pthread_mutex_unlock( &(b->free_q_mutex) );
}

/**
    End of AddFreeBuff.
**/

static Queue_t *
GetFreeBuff( Buff_t * b, int wait_free )

/**
    Gets a Queue_t * from the free queue.  Waits if there aren't
    any free buffers and waitfree is true.  Otherwise, drop a
    regular buffer.  In other words, either wait for a new free
    buffer, or get an inuse buffer, effectively dropping queued but
    unprocessed work.
**/

{
    Queue_t * q;
    int dropping = 0;


    Pthread_mutex_lock( &(b->free_q_mutex) );

    while( b->free_q_cnt == 0 ) {
	if (wait_free) {
	    if (!dropping) {
		Info( "The free buffer list for %s is empty.  "
		     "Will wait for a buffer.\n", b->name );
		dropping = 1;
	    }

	    Pthread_cond_wait( &(b->free_q_cond), &(b->free_q_mutex) );
	} else {
	    Pthread_mutex_unlock( &(b->free_q_mutex) );	/* avoid deadlocks! */

	    if (!dropping) {
		Info( "The free buffer list for %s is empty.  "
		     "Will drop an inuse buffer.\n", b->name );
		dropping = 1;
	    }

	    q = GetBuff( b );				/* Get a buffer */

	    Pthread_mutex_lock( &(b->free_q_mutex) );	/* Get lock back */
	    Queue( &(b->free_q), q );			/* Place on queue */
	    b->free_q_cnt++;				/* Update counter */
	}

/* 
    We need to have the mutex and ideally we'll have a buffer.
    We'll check above again.
*/

    }

    if (dropping) {
	Info( "The free buffer list for %s now has %d free buffers.\n",
	    b->name, b->free_q_cnt );
	dropping = 0;
    }

    q = Dequeue( &(b->free_q) );
    b->free_q_cnt--;

    Pthread_mutex_unlock( &(b->free_q_mutex) );
    return( q );
}

/**
    End of GetFreeBuff.
**/

static void
AddBuff( Buff_t * b, Queue_t * q )

/**
    Add a buffer to the buff_q.  Signal using buff_q_cond in case
    someone is waiting for a buffer to process (hopefully there is
    or will be!)
**/

{
    Pthread_mutex_lock( &(b->buff_q_mutex) );
    Queue( &(b->buff_q), q );
    b->buff_q_cnt++;
    Pthread_cond_signal( &(b->buff_q_cond) );
    Pthread_mutex_unlock( &(b->buff_q_mutex) );
}

/**
    End of AddBuff.
**/

static Queue_t *
GetBuff( Buff_t * b )

/**
    Gets a Queue_t * from the buff_q.  The thread will wait until
    we get a buffer.
**/

{
    Queue_t * q;

    Pthread_mutex_lock( &(b->buff_q_mutex) );

    while( b->buff_q_cnt == 0 ) {
	Pthread_cond_wait( &(b->buff_q_cond), &(b->buff_q_mutex) );
    }

    q = Dequeue( &(b->buff_q) );
    b->buff_q_cnt--;

    Pthread_mutex_unlock( &(b->buff_q_mutex) );
    return( q );
}

/**
    End of GetBuff.
**/

static int
GetArrayOfBuffs( Buff_t * b, Queue_t * (*qa)[ 1 ], ssize_t cnt )

/**
    Gets at least one Queue_t * from the buff_q, and at most cnt
    entries.  The thread will wait until there is at least one
    free buffer, but it will *not* wait for cnt buffers.

    Returns the number of Queue_t * pointers in array qa.

    UNTESTED CODE.  THIS IDEA CAME TO ME IN THE SHOWER ONE
    MORNING.  It might be a good way to handle the case where we've
    run out of buffers.  If we read say 10 off at a time, we can
    possibly write those quickly and free up more buffs, which
    might allow us to recover from out of buffers more quickly.

    The caller must do:

    for( i = 0; i < retFromThisRtn; i++ ) {
	AddFreeBuff( qa[ i ] );
    }

    Or perhaps we should write an AddArrayOfFreeBuffs routine.
**/

{
    int i;
    Queue_t * q;

    Pthread_mutex_lock( &(b->buff_q_mutex) );

    while( b->buff_q_cnt == 0 ) {
	Pthread_cond_wait( &(b->buff_q_cond), &(b->buff_q_mutex) );
    }

    if (b->buff_q_cnt < cnt) cnt = b->buff_q_cnt;

    for( i = 0; i < cnt; i++ ) {
	(*qa)[ i ] = Dequeue( &(b->buff_q) );
    }

    b->buff_q_cnt -= cnt;

    Pthread_mutex_unlock( &(b->buff_q_mutex) );
    return( cnt );
}

/**
    End of GetArrayOfBuffs.
**/

static int
NewSavedFile( time_t * Now )

/**
    Closes the current 'current' file, renames it to the saved file
    name, and makes a new one.

    Take the stub file name and add YYYYMMDD_HH:MM:SSZZZZZ where
    ZZZZZ is the zone offset.
**/

{
    char new_file[ PATH_MAX + 1 ];
    char TimeBuff[ 24 ];	/* Really needs to be 18! */

    char ZoneBuff[ 10 ];	/* Really needs to be 6! */
    time_t zone;		/* Zone offset */
    int hours;		/* Timezone hours offset */
    int mins;		/* Timezone minutes offset */

    struct tm Now_tm;

    memcpy( &Now_tm, localtime( Now ), sizeof( struct tm ) );

    strftime( TimeBuff, sizeof TimeBuff, "%Y%m%d_%H:%M:%S", &Now_tm );
    new_file[ sizeof new_file - 1  ] = '\0';
    strncpy( new_file, c.saved, sizeof new_file - 1 );
    strncat( new_file, TimeBuff, sizeof new_file - 1 );

/*
    if (Now_tm.tm_isdst > 0 && __daylight) {
	zone = __altzone;
    } else {
	zone = __timezone;
    }
*/
    zone = 5*3600;

/* Wierdness... */

    ZoneBuff[ 0 ] = (zone >= 0) ? '-' : ('+', zone *= -1);
    hours = zone / 3600;
    mins  = (zone - (hours * 3600)) / 60;
    sprintf( ZoneBuff+1, "%02d%02d", hours, mins );
    strncat( new_file, ZoneBuff, sizeof new_file - 1 );

    if (link( c.current, new_file )) {
	Log( "error during link( \"%s\", \"%s\" ): %s\n",
	     c.current, new_file, strerror( errno ) );
	return( 1 );
    }

    if (unlink( c.current )) {
	Log( "error during unlink( \"%s\" ): %s\n",
	    c.current, strerror( errno ) );
	return( 1 );
    }

    if (chmod( new_file, c.saved_mode )) {
	Log( "error during chmod( %s, %o ): %s\n",
	    new_file, c.saved_mode, strerror( errno ) );
	return( 1 );
    }

    return( 0 );
}

/**
    End of NewFile.
**/

static FILE *
NewCurrentFile( void )

/**
    Makes a new 'current' file.
**/

{
    FILE * f;
    int tf;		/* Temp file descriptor */

    if (unlink( c.current ) && errno != ENOENT) {
	Log( "failed to delete %s: %s\n", c.current, strerror( errno ));
	return( NULL );
    }

    if ((tf = creat( c.current, c.current_mode )) == -1) {
	Log( "failed to creat %s: %s\n", c.current, strerror( errno ));
	return( NULL );
    }

    f = fdopen( tf, "wb" );
    if (f == NULL) {
	Log( "Error opening %s: %s\n", c.current, strerror( errno ) );
	return( NULL );
    }

    return( f );
}

/**
    End of NewCurrentFile.
**/

static int
Write( char * buff, int len )

/**
    Write the flow to c.current.  If c.current is 5 minutes old,
    then rename and make a new one.  Or if len == -1, which
    is an overloaded shutdown do it sorta crappy thing.

    Returns:

	0 - Normal
	1 - Changed to a new "current" file.
       -1 - An error occured and messages were written.
**/

{
    Queue_t * q;
    static time_t StartTime;
    time_t Now;
    static FILE * f;

    int rc = 0;

    Now = time( NULL );

    if (len == -1 && f == NULL) {	/* Cleanup, but nothing to cleanup */
	return( 0 );
    }

    if (len == -1 || (f != NULL && 
		      StartTime > (time_t) 0 &&
		      difftime( Now, StartTime ) >= c.save_secs)) {

	FILE * tempf;

	tempf = f;			/* Close using this to */
	f     = NULL;			/* avoid atexit loops, etc */

	if (fclose( tempf ) != 0) {
	    Log( "fclose of %s failed: %s\n", c.current, strerror( errno ));
	    exit( 1 );
	}

	rc = NewSavedFile( &Now );	/* c.current -> c.saved */
	if (rc) return( rc );

 	if (len < 0) return( 0 );	/* SHUTDOWN */

	rc = 1;
    }

    if (f == NULL) {			/* Need a c.current file? */
	f = NewCurrentFile();
	if (f == NULL) return( -1 );
	StartTime = Now;
    }

    fwrite( buff, len, 1, f );
    if (ferror( f )) {
	Log( "Error writing to %s: %s\n", c.current, strerror( errno ) );
	return( -1 );
    }

    return( rc );
}

/**
    End of Write.
**/

static void
WriteThreadHandler( void * np )

/**
    Handles cleanup for the write thread.  We'll call Write with a
    -1 length.
**/

{
    Info( "write thread ending.\n" );
    Info( "moving %s to %s.\n", c.current, c.saved );

    Write( NULL, -1 );		/* Flushes buffers, moves current->saved */

    Info( "write thread ended.\n" );
}

/**
    End of WriteThreadHandler.
**/

static void *
WriteThread( void * Null )

/**
    The writing thread.  Processes the buffer array.  For each
    buffer, validate, convert and write.  All thread locking is
    handled in the buffer routines, which are the primary shared
    data structure.  So, don't expect to see any pthread calls
    here.
**/

{
    char CflowdBuff[ CFLOWD_V5_BUFF_SIZE ];	/* Buffer to write from */
    ssize_t len;				/* Its length */
    CISCOBuff_t * b;				/* Write buffer header */
    Queue_t * q;				/* Write queue header */

    int dropped;	/* Dropped flows/saved file */
    int stupid_implementation = 1;

    dropped = 0;

    pthread_cleanup_push( WriteThreadHandler, NULL );

    while( stupid_implementation ) {
	int rc;

	q = GetBuff( &CISCOBuffs );	/* Can wait */
	b = (CISCOBuff_t *) q->obj;

	if (!ValidateCISCOFlow( b->CISCOBuff, b->len, b->router,
				b->nodropped, &dropped )) {

	    len = CvtCISCOV5ToCflowd( b->CISCOBuff, CflowdBuff, b->router );

	    pthread_setcancelstate( PTHREAD_CANCEL_DISABLE, NULL );
	    rc = Write( CflowdBuff, len );
	    pthread_setcancelstate( PTHREAD_CANCEL_ENABLE, NULL );
	    if (rc == -1) {
		exit( 1 );
	    } else if (rc == 1) {	/* Means we move 'current' to 'saved' */
		dropped = 0;		/* So, re-init dropped counter */
	    }
	}

	AddFreeBuff( &CISCOBuffs, q );
    }

    pthread_cleanup_pop( 0 );
}

/**
    End of WriteThread.
**/

static void *
ReadThread( void * p )

/**
    Loop until we are killed...

    This thread should run quickly.  We want to pull items off the
    socket as fast as we can.  Once the datagrams have been read,
    we can take a little bit more time processing them.  We can
    always add more buffers if needed.
**/

{
    ReadThread_t * rt;

    int s;			/* Socket to listen on */
    char CISCOBuff[ CISCO_V5_BUFF_SIZE ]; /* Temp buffer */
    ssize_t len;		/* Buffer lenth */
    ipv4addr_t router;		/* IP of sending router */
    int dropping = 0;		/* Dropping flows message issued? */
    int cnt = 0;
    int port = 0;
    int nodropped = 0;

/*
    Get the port this thread should be reading on.
*/

    rt = (ReadThread_t *) p;
    port = rt->port;
    nodropped = rt->nodropped;
    free( rt );

    Info( "starting read thread for port %d%s.\n",
	port, nodropped ? " (skipping dropped flows checks)" : "" );

    if ((s = Bind( port )) < 0) exit( 1 );	/* Get socket */

/*
    Get datagrams.  Note that GetFreeBuff will wait until there are
    free buffers.  About the only thing you need to watch for is
    adding a 'continue' such that you end up calling GetFreeBuff
    without doing something with the last buffer you got.  Ie: a
    continue in the loop after GetFreeBuff without calling either
    AddFreeBuff or AddBuff is probably not good.  You'll lose a
    buffer.
*/

    while( 1 ) {
	Queue_t * q;
	CISCOBuff_t * b;

	q = GetFreeBuff( &CISCOBuffs, 1 );	/* Can wait if no free */
	b = (CISCOBuff_t *) q->obj;		/* Get buffer ptr */

	len = ReadCISCOFlow( s, b->CISCOBuff, &router );

	b->len = len;			/* Stash... */
	b->router = router;
	b->nodropped  = nodropped;

	AddBuff( &CISCOBuffs, q );	/* Add and wake writer... */
    }
}

/**
    End of ReadThread.
**/

static void
Ourdaemon( void )

/**
    Normal steps to turn a process into a daemon.
**/

{
#if defined(OPEN_MAX)
static int open_max = OPEN_MAX;
#else
static int open_max = 0;
#endif

#define OPEN_MAX_GUESS 256

    pid_t pid;
    int i;

    if ( (pid = fork()) < 0) {
	Log( "failed when trying to fork for daemon: %s\n", strerror( errno ));
	exit( 1 );
    } else if (pid != 0) {
	exit( 0 );		/* Parent process terminated. */
    }

/*
    Child continues.
*/

    setsid();		/* Doesn't really seem to fail.  See man page */
    chdir( "/" );
    umask( 0 );

    errno = 0;		/* Copied from Steven's Advanced Unix Programming */

    if ((open_max = sysconf( _SC_OPEN_MAX )) < 0) {
	if (errno == 0) {		/* Don't know */
	    open_max = OPEN_MAX_GUESS;	/* Guess! */
	} else {
	    Log( "sysconf error for _SC_OPEN_MAX: %s\n", strerror( errno ));
	}
    }

/*
    If we aren't using syslog, then don't close stderr.
*/

    for( i = 0; i <= open_max; i++ ) {
	if (c.logfac[ 0 ] == '\0' && i == STDERR_FILENO) {
	    continue;
	}

	close( i );
    }
}

/**
    End of Ourdaemon.
**/

static void
Sigterm( int sig )

/**
    SIGTERM handler.
**/

{
    if (DoneAndGone) {
	return;		/* We can get a recursive call because of atexit() */
    }

    Done = 1;		/* Ends most things we care about. */

    Info( "ReadFlows %d.%d.%d ending.\n", VERSION_MAJOR,
	VERSION_MINOR, VERSION_PATCH );

/*
    Should we take a mutex around the threadid?  Technically, yes!
*/

    if (writeThread != NULL) {
	Pthread_cancel( writeThread );
    }

    DoneAndGone = 1;
}

static void
Sigterm_atexit( void )
{
    Sigterm( SIGTERM );
}

/**
    End of Sigterm.
**/

static void
Sighup( int sig )

/**
    SIGHUP handler.
**/

{
    Info( "ReadFlows %d.%d.%d contacted.\n", VERSION_MAJOR,
	VERSION_MINOR, VERSION_PATCH );

    Info( "Hup, 2, 3, 4.\n" );

    signal( SIGHUP, Sighup );
}

/**
    End of Sighup.
**/

int
main( int argc, char * argv[] )

{
    pthread_t readThread = NULL;
    pthread_t scannerMonitorThread = NULL;

    struct sigaction sigterm_act;
    struct sigaction sighup_act;

    int i;

/*
    Start...
*/

    if (Cmdparse( argc, argv )) exit( 1 );	/* Parse command */

    if (!c.nodaemon) {
	Ourdaemon();		/* Could use 'system' daemon if it exists. */
    } else {
	umask( 0 );
    }

/*
    Handle signals.
*/

    memset( &sigterm_act, '\0', sizeof sigterm_act );
    sigterm_act.sa_handler = Sigterm;
    sigaction( SIGTERM, &sigterm_act, NULL );

    memset( &sighup_act, '\0', sizeof sighup_act );
    sighup_act.sa_handler = Sighup;
    sigaction( SIGHUP, &sighup_act, NULL );

    atexit( Sigterm_atexit );

    Info( "Starting ReadFlows V%d.%d.%d.\n", VERSION_MAJOR, VERSION_MINOR,
	VERSION_PATCH );

/*
    Normal startup...
*/

    if (MakeLastSeqTable()) exit( 1 );		/* Keeps track of last seq */
						/* by source IP */

/*
    Init the socket buffers.
*/

    BuffInit( &CISCOBuffs, c.num_buffs, sizeof( CISCOBuff_t ), "SocketBuffs" );

/*
    1 + n ports threads.  Start a reader for each port.

    n)  Read datagrams.
    2)  Process and write datagrams.
*/

    for( i = 0; i < c.num_ports; i++ ) {
	ReadThread_t * rt;

	rt = Malloc( sizeof( ReadThread_t ) );
	rt->port = c.port[ i ];
	rt->nodropped = c.nodropped[ i ];

	Pthread_create( &readThread, NULL, ReadThread, rt );
    }

    Pthread_create( &writeThread, NULL, WriteThread, NULL );

/*
    The signal handlers will cancel this thread.  This thread
    cleans up and then ends.  We'll get control back.  We could
    kill off the other threads, I suppose.  But, in any case, we
    will get control after this call when this process receives a
    SIGTERM.
*/

    Pthread_join( writeThread, NULL );

    DeleteLastSeqTable();

    Info( "ReadFlows %d.%d.%d ended.\n", VERSION_MAJOR,
	VERSION_MINOR, VERSION_PATCH );

    return( 0 );
}

/**
    End of readflows.
**/
