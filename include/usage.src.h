/* vi: set sw=8 ts=8: */
/*
 * This file suffers from chronically incorrect tabification
 * of messages. Before editing this file:
 * 1. Switch you editor to 8-space tab mode.
 * 2. Do not use \t in messages, use real tab character.
 * 3. Start each source line with message as follows:
 *    |<7 spaces>"text with tabs"....
 * or
 *    |<5 spaces>"\ntext with tabs"....
 */
#ifndef BB_USAGE_H
#define BB_USAGE_H 1

#define NOUSAGE_STR "\b"

INSERT

#define busybox_notes_usage \
       "Hello world!\n"

#define eooqd_trivial_usage \
       "<queue-file>"
#define eooqd_full_usage \

#define eperd_trivial_usage \
       "-fbSAD -P pidfile -l N " IF_FEATURE_CROND_D("-d N ") "-L LOGFILE -c DIR"
#define eperd_full_usage "\n\n" \
       "        -f      Foreground" \
     "\n        -b      Background (default)" \
     "\n        -S      Log to syslog (default)" \
     "\n        -l      Set log level. 0 is the most verbose, default 8" \
     IF_FEATURE_CROND_D("\n        -d      Set log level, log to stderr") \
     "\n        -L      Log to file" \
     "\n        -c      Working dir" \
     "\n        -A      Atlas specific processing" \
     "\n        -D      Periodically kick watchdog" \
     "\n        -P      pidfile to use" \

#define evtdig_trivial_usage \
             "[-h|-i|-b|-s] ... <server IP address>"
#define evtdig_full_usage "\n\n" \
    "evtdig:  a tiny implemention dns queries which supports 4 queries\n" \
     "\n     not implemented:  recursion" \
     "\n     -h | --hostname-bind hostname.bind txt chaos " \
     "\n     -i | id-server id.server txt chaos " \
     "\n     -b | version-bind version-bind txt chaos " \
     "\n     -s | soa <zone> to be implmented " \
     "\n      RIPE NCC 2011 " \


#define evhttpget_trivial_usage \
       "[-ac0146] [--all [--combine]] [--get|--head|--post] [--post-file <file>] [--post-header <file>] [--post-footer <file>] [--store-headers <bytes>] [--user-agent <string>] [-A <atlas id>] [-O <file>]"
#define evhttpget_full_usage "\n\n" \
     "\nOptions:" \
     "\n        -a --all                Report on all addresses" \
     "\n        -c --combine            Combine the reports for all address in one JSON" \
     "\n        --get                   GET method" \
     "\n        --head                  HEAD method" \
     "\n        --post                  POST mehod" \
     "\n        --post-file <filename>  File to post" \
     "\n        --post-header <fn>      File to post (comes first)" \
     "\n        --post-footer <fn>      File to post (comes last)" \
     "\n        --store-headers <bytes> Number of bytes of the header to store"\
     "\n        --user-agent <string>   User agent header" \
     "\n        -0                      HTTP/1.0" \
     "\n        -1                      HTTP/1.1" \
     "\n        -A <atlas id>           Atlas ID" \
     "\n        -O <filename>           Output file" \
     "\n        -4                      Only IPv4 addresses" \
     "\n        -6                      Only IPv6 addresses" \

#define evping_trivial_usage \
       "todo"
#define evping_full_usage "\n\n" \
        "\nOptions:" \
        "\n     -c <count>      Number of packets" \
        "\n     -s <size>       Size" \
        "\n     -A <id>         Atlas measurement ID" \
        "\n     -O <out file>   Output file name" \
        "\n     -4              IPv4" \
        "\n     -6              IPv6" \
     "todo"

#define evtraceroute_trivial_usage \
       "todo"
#define evtraceroute_full_usage "\n\n" \
     "todo"

#define httppost_trivial_usage \
        "[--delete-file] [--post-file FILE] [--post-dir DIR] " \
        "[--post-header FILE] " \
        "[--post-footer FILE] [--set-time bound] " \
        "[-O FILE] URL"
#define httppost_full_usage "\n\n" \
"Post file using the HTTP POST command\n" \
"\nOptions:" \
"\n     --defile-file           Delete files after they have been posted" \
"\n     --post-file FILE        Post this file" \
"\n     --post-dir DIR          Post all files in this directory" \
"\n     --post-header FILE      First post this file and do not delete it" \
"\n     --post-footer FILE      Post this file last and do not delete it" \
"\n     --set-time bound        Parse the time in the HTTP reply and set the" \
"\n                             system time if it exceeds bound (in seconds)" \
"\n     -O FILE                 Write the body of the HTTP reply to FILE"

#define perd_trivial_usage \
       "-fbSAD -P pidfile -l N " IF_FEATURE_CROND_D("-d N ") "-L LOGFILE -c DIR"
#define perd_full_usage "\n\n" \


#endif
