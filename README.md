# ipfixd
ipfixd is a daemon that can read a variety of NetFlow format packets and write them as 'clfowd' format files.

The daemon can fork and run itself in the background.  This mode
is not used when running under systemd as it causes way too many
problems.  We'll keep the forking code around in case someone
wants to run this in an appliance type system.  Bear in mind
that changing the uid and then forking often causes a problem
when trying to create the pid file in /var/run.  If the program
mysteriously fails to run, it is often because it can't add
a file to /var/run.
