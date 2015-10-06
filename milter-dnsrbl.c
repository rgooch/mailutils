/*  milter-dnsrbl.c

    Main file for  milter-dnsrbl  (Sendmail Milter to check DNS RBLs).

    Copyright (C) 2003-2005  Richard Gooch

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

    Richard Gooch may be reached at  http://www.safe-mbox.com/~rgooch/
*/

/*
    This milter allows you to reject or stall messages relayed via machines
    which are listed in a DNS Real-time Black List.


    Written by      Richard Gooch   20-SEP-2003: Copied skeleton from
  milter-size.c file.

    Updated by      Richard Gooch   10-OCT-2003: Coding begins.

    Updated by      Richard Gooch   13-OCT-2003: First working implementation.

    Updated by      Richard Gooch   14-OCT-2003: Added "STALLTIME" token.

    Updated by      Richard Gooch   16-OCT-2003: Worked around glibc brain
  damage.

    Updated by      Richard Gooch   17-OCT-2003: Switched to poll(2) because
  sleep(3) is not thread-safe (was losing wake-ups). Added sleep debugging.

    Updated by      Richard Gooch   26-OCT-2003: Added "ConnectMTA" option
  for RELAYIP matches.

    Updated by      Richard Gooch   15-FEB-2004: Added check for authenticated
  sender ("{auth_authen}").

    Updated by      Richard Gooch   1-MAR-2004: Fixed small resource leak:
  now always cleanup message data when SMFIS_CONTINUE is not returned.

    Updated by      Richard Gooch   19-APR-2004: Worked around around
  unfortunate IP address self-reporting in Computer Associates proprietary MTA
  software.

    Updated by      Richard Gooch   10-JUN-2004: Ignore private IPv4 addresses
  (to reduce unnecessary DNS traffic). Added default TEMPFAIL message to expose
  resource allocation failures. Fixed truncation of message line when $BADIP is
  specified before end of line. Support showing $BADIP up to 3 times.

    Updated by      Richard Gooch   19-AUG-2004: If connecting MTA is known
  (via an SSL certificate), do not lookup in DNSRBL.

    Last updated by Richard Gooch   9-JUN-2005: Worked around API breakage in
  glibc 2.3.2.


*/
#ifndef _REENTRANT
#  error  Compile with _REENTRANT
#endif

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#if defined(__linux__)
#  include <features.h>
#endif
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <sysexits.h>
#include <syslog.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <netdb.h>
#include <libmilter/mfapi.h>
#include <errno.h>
#include <pthread.h>


#define ERRSTRING                strerror (errno)
#define FALSE                    0
#define TRUE                     1
#define STRING_LENGTH          256
#define CONFIG_FILE              "/etc/mail/milter-dnsrbl.conf"
#define DEFAULT_STALL_SECONDS    5
#define MKIPV4(a,b,c,d)          (((a) << 24) | ((b) << 16) | ((c) << 8) | (d))
#define MAX_BADIP                3

#define ACTION_TAG                0  /*  This is also the default action     */
#define ACTION_PERMFAIL           1
#define ACTION_TEMPFAIL           2
#define ACTION_DISCARD            3
#define ACTION_OPTION_MASK     0xf0
#define ACTION_OPT_STALL       0x10

#define my_sleep(seconds) poll(NULL, 0, seconds * 1000)

#ifdef DEBUG
static void do_sleep (unsigned int seconds);
#else
#define do_sleep(seconds) my_sleep(seconds)
#endif

typedef int flag;

struct addr_range_s               /*  The values herein are in host order    */
{
    unsigned long base;           /*  The base address                       */
    unsigned long mask;           /*  The mask to apply before comparing     */
};

struct bl_struct
{
    char *domain;                 /*  The DNS domain name of the blacklist   */
    struct addr_range_s bl;       /*  The BL desired A record value          */
    struct addr_range_s dul;      /*  The DUL desired A record value         */
    char *message_text;           /*  Message to give the connecting MTA     */
    struct bl_struct *next;       /*  The next blacklist                     */
};

struct mta_struct
{
    struct addr_range_s mta;      /*  The connecting MTA                     */
    unsigned char action_relay;   /*  Action to take when relay IP matches   */
    struct mta_struct *next;      /*  The next MTA policy structure          */
};

struct config_struct
{
    unsigned int refcount;        /*  When this drops to 0, may deallocate   */
    unsigned char action_connect; /*  Action to take when connect IP matches */
    unsigned char def_action_relay;/* Default action when relay IP matches   */
    unsigned int stall_time;      /*  How many seconds to stall the MTA      */
    struct bl_struct *first_db;   /*  The first blacklist database           */
    struct bl_struct *last_db;    /*  The last blacklist database            */
    struct mta_struct *first_mta; /*  The first policy MTA structure         */
    struct mta_struct *last_mta;  /*  The last policy MTA structure          */
};

struct address_struct
{
    unsigned long address;        /*  IP address of MTA/relay                */
    struct bl_struct *match_bl;   /*  The best match database                */
    unsigned long arec_value;     /*  The A record from the database         */
    struct address_struct *next;
};

struct connect_struct
{
    struct config_struct *config;
    struct address_struct connect_mta;
    unsigned char action_relay;   /*  Action when relay IP matches           */
    struct address_struct *first_relay;
};


static void put_config (struct config_struct *config, flag grab_lock);


static pthread_mutex_t config_lock = PTHREAD_MUTEX_INITIALIZER;
static struct addr_range_s private_addresses[] =
{
    {MKIPV4 ( 10,   0,   0,   0), MKIPV4 (255,   0,   0,   0)},
    {MKIPV4 (172,  16,   0,   0), MKIPV4 (255, 240,   0,   0)},
    {MKIPV4 (192, 168,   0,   0), MKIPV4 (255, 255,   0,   0)},
    {MKIPV4 (127,   0,   0,   1), MKIPV4 (255, 255, 255, 255)},
    {0, 0}
};


static flag name_to_addr (char *name, unsigned long *addr)
/*  [SUMMARY] Convert a hostname to an address.
    <name> The hostname.
    <addr> The address is written here, in host format.
    [RETURNS] TRUE on success, else FALSE (if an A record was not found).
*/
{
    int herrnum;                  /*  Calling it h_error fouls up glibc  */
    struct hostent ret;
    struct hostent *result = NULL;
    char buf[1024];               /* 256 isn't big enough for glibc */

#if !defined(__linux__) || !defined(__GLIBC__)
    if ( !gethostbyname_r (name, &ret, buf, sizeof buf, &herrnum) )
	return (FALSE);
#else
    if ( gethostbyname_r (name, &ret, buf, sizeof buf, &result,
			  &herrnum) ) return (FALSE);
      /*  Can't trust return value alone on glibc 2.3.2, must also check the
	  result. Yet another undocumented API change.  */
    if (!result) return (FALSE);
#endif
    if (ret.h_length != 4) return (FALSE);
    *addr = ntohl (*(unsigned int *) ret.h_addr_list[0]);
    return (TRUE);
}   /*  End Function name_to_addr  */

static flag process_config_line (char *line, struct config_struct *config,
				 char list_db[STRING_LENGTH],
				 struct addr_range_s *storage_bl,
				 struct addr_range_s *storage_dul,
				 char list_txt[STRING_LENGTH])
/*  [SUMMARY] Process a configuration file line.
    <line> The line from the configuration file.
    <config> The config structure.
    <list_db> Some working space. This should initially be empty.
    <storage_bl> Some working space. This should be initialised at file open.
    <storage_dul> Some working space. This should be initialised at file open.
    <list_txt> Some working space. This should initially be empty.
    [RETURNS] TRUE on success, else FALSE.
*/
{
    char *ptr = line;

    while ( isspace (*ptr) ) ++ptr;  /*  Strip leading whitespace  */
    if (*ptr == '#') return (TRUE);
    line[strlen (line) - 1] = '\0';   /*  Remove newline            */
    /*  Process single-line configurations  */
    if ( (strncasecmp (ptr, "MATCH", 5) == 0) && isspace (ptr[5]) )
    {
	unsigned char *action;

	for (ptr += 5; isspace (*ptr); ++ptr);
	if (strncasecmp (ptr, "CONNECTIP", 9) == 0)
	{
	    action = &config->action_connect;
	    ptr += 9;
	}
	else if (strncasecmp (ptr, "RELAYIP", 7) == 0)
	{
	    action = &config->def_action_relay;
	    ptr += 7;
	}
	else
	{
	    syslog (LOG_ERR, "bad address group in line: \"%s\"", line);
	    return (FALSE);
	}
	while ( isspace (*ptr) ) ++ptr;
	if ( (action == &config->def_action_relay)
	     && (strncasecmp (ptr, "ConnectMTA=", 11) == 0) )
	{
	    unsigned long addr;
	    struct mta_struct *mta;
	    char *ptr2;
	    char name[256];

	    ptr += 11;
	    for (ptr2 = ptr; *ptr2 && !isspace (*ptr2); ++ptr2);
	    if (ptr2 <= ptr)
	    {
		syslog (LOG_ERR, "no MTA specified in line: \"%s\"", line);
		return (FALSE);
	    }
	    if (ptr2 - ptr + 1 >= sizeof name)
	    {
		syslog (LOG_ERR, "MTA too long in line: \"%s\"", line);
		return (FALSE);
	    }
	    strncpy (name, ptr, ptr2 - ptr);
	    name[ptr2 - ptr] = '\0';
	    if ( !name_to_addr (name, &addr) )
	    {
		syslog (LOG_ERR, "DNS lookup failed for: \"%s\"", name);
		return (FALSE);
	    }
	    if ( ( mta = calloc (1, sizeof *mta) ) == NULL )
	    {
		syslog (LOG_ERR, "error allocating MTA entry");
		return (FALSE);
	    }
	    mta->mta.base = addr;
	    mta->mta.mask = 0xffffffff;
	    if (config->last_mta) config->last_mta->next = mta;
	    else config->first_mta = mta;
	    config->last_mta = mta;
	    action = &mta->action_relay;
	    ptr = ptr2;
	    while ( isspace (*ptr) ) ++ptr;
	}
	/*  Now process all the actions  */
	while (*ptr)
	{
	    if (*ptr == ',')
	    {
		++ptr;
		continue;
	    }
	    if (strncasecmp (ptr, "TAG", 3) == 0)
	    {
		*action = (*action & ACTION_OPTION_MASK) + ACTION_TAG;
		ptr += 3;
	    }
	    else if (strncasecmp (ptr, "PERMFAIL", 8) == 0)
	    {
		*action = (*action & ACTION_OPTION_MASK) + ACTION_PERMFAIL;
		ptr += 8;
	    }
	    else if (strncasecmp (ptr, "TEMPFAIL", 8) == 0)
	    {
		*action = (*action & ACTION_OPTION_MASK) + ACTION_TEMPFAIL;
		ptr += 8;
	    }
	    else if (strncasecmp (ptr, "DISCARD", 7) == 0)
	    {
		*action = (*action & ACTION_OPTION_MASK) + ACTION_DISCARD;
		ptr += 7;
	    }
	    else if (strncasecmp (ptr, "STALL", 5) == 0)
	    {
		*action = *action | ACTION_OPT_STALL;
		ptr += 5;
	    }
	    else
	    {
		syslog (LOG_ERR, "bad action in line: \"%s\"", line);
		return (FALSE);
	    }
	}
	return (TRUE);  /*  No multi-line processing  */
    }
    else if ( (strncasecmp (ptr, "STALLTIME", 9) == 0) && isspace (ptr[9]) )
    {
	for (ptr += 9; isspace (*ptr); ++ptr);
	config->stall_time = atoi (ptr);
	return (TRUE);  /*  No multi-line processing  */
    }
    /*  Process multi-line configurations  */
    while (*ptr)
    {
	if ( isspace (*ptr) )
	{
	    ++ptr;
	    continue;
	}
	if (strncasecmp (ptr, "LIST", 4) == 0)
	{
	    char *endptr;

	    for (ptr += 4; isspace (*ptr); ++ptr);
	    if (*ptr == '\0')
	    {
		syslog (LOG_ERR, "no database in line: \"%s\"", line);
		return (FALSE);
	    }
	    for (endptr = ptr; *endptr && !isspace (*endptr); ++endptr);
	    if (endptr - ptr >= STRING_LENGTH)
	    {
		syslog (LOG_ERR, "database too long in line: \"%s\"", line);
		return (FALSE);
	    }
	    strncpy (list_db, ptr, endptr - ptr);
	    list_db[endptr - ptr] = '\0';
	    ptr = endptr;
	}
	else if (strncasecmp (ptr, "BLADDR", 6) == 0)
	{
	    struct in_addr addr;

	    for (ptr += 7; isspace (*ptr); ++ptr);
	    if ( !inet_aton (ptr, &addr) )
	    {
		syslog (LOG_ERR, "no bladdr in line: \"%s\"", line);
		return (FALSE);
	    }
	    storage_bl->base = ntohl (addr.s_addr);
	    while ( *ptr && !isspace (*ptr) ) ++ptr;
	}
	else if (strncasecmp (ptr, "BLMASK", 6) == 0)
	{
	    struct in_addr addr;

	    for (ptr += 7; isspace (*ptr); ++ptr);
	    if ( !inet_aton (ptr, &addr) )
	    {
		syslog (LOG_ERR, "no blmask in line: \"%s\"", line);
		return (FALSE);
	    }
	    storage_bl->mask = ntohl (addr.s_addr);
	    while ( *ptr && !isspace (*ptr) ) ++ptr;
	}
	else if (strncasecmp (ptr, "DULADDR", 7) == 0)
	{
	    struct in_addr addr;

	    for (ptr += 8; isspace (*ptr); ++ptr);
	    if ( !inet_aton (ptr, &addr) )
	    {
		syslog (LOG_ERR, "no duladdr in line: \"%s\"", line);
		return (FALSE);
	    }
	    storage_dul->base = ntohl (addr.s_addr);
	    while ( *ptr && !isspace (*ptr) ) ++ptr;
	}
	else if (strncasecmp (ptr, "DULMASK", 7) == 0)
	{
	    struct in_addr addr;

	    for (ptr += 8; isspace (*ptr); ++ptr);
	    if ( !inet_aton (ptr, &addr) )
	    {
		syslog (LOG_ERR, "no dulmask in line: \"%s\"", line);
		return (FALSE);
	    }
	    storage_dul->mask = ntohl (addr.s_addr);
	    while ( *ptr && !isspace (*ptr) ) ++ptr;
	}
	else if (strncasecmp (ptr, "MESSAGE", 7) == 0)
	{
	    unsigned int badip_count = 0;
	    char *outptr;
	    struct bl_struct *list;

	    if ( (list_db[0] == '\0') || (storage_bl->base == 0) )
	    {
		syslog (LOG_ERR,
			"database or address missing before line: \"%s\"",
			line);
		return (FALSE);
	    }
	    for (ptr += 7; isspace (*ptr); ++ptr);
	    if (*ptr == '\0')
	    {
		syslog (LOG_ERR, "no message in line: \"%s\"", line);
		return (FALSE);
	    }
	    if (strlen (ptr) >= STRING_LENGTH)
	    {
		syslog (LOG_ERR, "message too long in line: \"%s\"",
			line);
		return (FALSE);
	    }
	    for (outptr = list_txt; *ptr; ++ptr, ++outptr)
	    {
		if (*ptr != '$') *outptr = *ptr;
		else if (strncmp (ptr, "$BADIP", 6) == 0)
		{
		    ptr += 5;
		    if (++badip_count > MAX_BADIP)
			syslog (LOG_ERR,
				"too many $BADIP entries in config file");
		    else
		    {
			*outptr++ = '%';
			*outptr = 's';
		    }
		}
		else *outptr = *ptr;
	    }
	    *outptr = '\0';
	    if ( ( ( list = calloc (1, sizeof *list) ) == NULL ) ||
		 ( ( list->domain = strdup (list_db) ) == NULL ) ||
		 ( ( list->message_text = strdup (list_txt) ) == NULL ) )
	    {
		syslog (LOG_ERR, "error allocating database entry");
		return (FALSE);
	    }
	    list->bl = *storage_bl;
	    list->bl.base &= list->bl.mask;
	    list->dul = *storage_dul;
	    list->dul.base &= list->dul.mask;
	    if (config->last_db) config->last_db->next = list;
	    else config->first_db = list;
	    config->last_db = list;
	    memset (list_db, 0, STRING_LENGTH);
	    storage_bl->base = 0;
	    storage_bl->mask = 0xffffffff;
	    storage_dul->base = 0;
	    storage_dul->mask = 0xffffffff;
	    memset (list_txt, 0, STRING_LENGTH);
	}
	else
	{
	    syslog (LOG_ERR, "unknown token in line: \"%s\"", line);
	    return (FALSE);
	}
    }
    return (TRUE);
}   /*  End Function process_config_line  */

static struct config_struct *read_config (const char *filename)
/*  [SUMMARY] Read the configuration file.
    <filename> The filename to read from.
    [NOTE] The <<config_lock>> must be held by the caller.
    [NOTE] This should only be called by [<get_config>].
    [RETURNS] A pointer to the configuration on success, else NULL.
*/
{
    struct addr_range_s storage_bl, storage_dul;
    struct config_struct *config;
    FILE *fp;
    char line[1024], list_db[STRING_LENGTH], list_txt[STRING_LENGTH];

    if ( ( fp = fopen (filename, "r") ) == NULL ) return (NULL);
    if ( ( config = calloc (1, sizeof *config) ) == NULL )
    {
	fclose (fp);
	return (NULL);
    }
    config->stall_time = DEFAULT_STALL_SECONDS;
    memset (list_db, 0, STRING_LENGTH);
    storage_bl.base = 0;
    storage_bl.mask = 0xffffffff;
    storage_dul.base = 0;
    storage_dul.mask = 0xffffffff;
    memset (list_txt, 0, STRING_LENGTH);
    while ( fgets (line, sizeof line, fp) )
    {
	if ( !process_config_line (line, config, list_db, &storage_bl,
				   &storage_dul, list_txt) )
	{
	    put_config (config, FALSE);
	    fclose (fp);
	    return (NULL);
	}
    }
    fclose (fp);
    return (config);
}   /*  End Function read_config  */

static struct config_struct *get_config ()
/*  [SUMMARY] Get the current configuration.
    [RETURNS] A pointer to the configuration on success, else NULL.
*/
{
    struct stat statbuf;
    struct config_struct *config;
    static time_t last_mtime = 0;
    static struct config_struct *available_config = NULL;

    pthread_mutex_lock (&config_lock);
    if ( (stat (CONFIG_FILE,&statbuf) == 0) && (statbuf.st_mtime >last_mtime) )
    {   /*  File exists and has changed since the last read  */
	config = read_config (CONFIG_FILE);
	if (config)
	{
	    if (available_config)
	    {
		put_config (available_config, FALSE);
		syslog (LOG_INFO, "re-read config file: %s", CONFIG_FILE);
	    }
	    else syslog (LOG_INFO, "read config file: %s", CONFIG_FILE);
	    available_config = config;
	    last_mtime = statbuf.st_mtime;
	}
    }
    config = available_config;
    if (config) ++config->refcount;
    pthread_mutex_unlock (&config_lock);
    return (config);
}   /*  End Function get_config  */

static void put_config (struct config_struct *config, flag grab_lock)
{
    int dealloc = FALSE;
    struct bl_struct *list, *db_next;
    struct mta_struct *mta, *mta_next;

    if (grab_lock) pthread_mutex_lock (&config_lock);
    if (config->refcount > 0) --config->refcount;
    else dealloc = TRUE;
    if (grab_lock) pthread_mutex_unlock (&config_lock);
    if (!dealloc) return;
    for (list = config->first_db; list; list = db_next)
    {
	db_next = list->next;
	if (list->domain) free (list->domain);
	if (list->message_text) free (list->message_text);
	free (list);
    }
    for (mta = config->first_mta; mta; mta = mta_next)
    {
	mta_next = mta->next;
	free (mta);
    }
    free (config);
}   /*  End Function put_config  */

static sfsistat mlfi_abort (SMFICTX *ctx);

static sfsistat search_databases (SMFICTX *ctx, struct bl_struct *database,
				  struct address_struct *relay, flag is_relay,
				  unsigned char action,
				  unsigned int stall_time)
{
    sfsistat retval;
    char ascii_address[17], message[1024];

    for (; database; database = database->next)
    {
	unsigned long arec;
	char lookup_name[256];

	snprintf (lookup_name, sizeof lookup_name, "%lu.%lu.%lu.%lu.%s.",
		  (relay->address & 0x000000ff) >> 0,
		  (relay->address & 0x0000ff00) >> 8,
		  (relay->address & 0x00ff0000) >> 16,
		  (relay->address & 0xff000000) >> 24,
		  database->domain);
	if ( !name_to_addr (lookup_name, &arec) ) continue;
	if ( is_relay && ( (arec & database->dul.mask) == database->dul.base) )
	    continue;  /*  Relay MTA only appears in a DUL, ignore match  */
	relay->match_bl = database;  /*  Record match, good or not  */
	relay->arec_value = arec;
	if ( (arec & database->bl.mask) == database->bl.base ) break; /*Good */
    }
    if (!relay->match_bl
	|| ( (relay->arec_value & relay->match_bl->bl.mask)
	     != relay->match_bl->bl.base) )
	return (SMFIS_CONTINUE);
    /*  Have a good match: take action  */
    if (action & ACTION_OPT_STALL) do_sleep (stall_time);
    snprintf (ascii_address, sizeof ascii_address, "%lu.%lu.%lu.%lu",
	      (relay->address & 0xff000000) >> 24,
	      (relay->address & 0x00ff0000) >> 16,
	      (relay->address & 0x0000ff00) >> 8,
	      (relay->address & 0x000000ff) >> 0);
    /*  Construct message, with up to MAX_BADIP instances of address shown  */
    snprintf (message, sizeof message, relay->match_bl->message_text,
	      ascii_address, ascii_address, ascii_address);
    switch (action & ~ACTION_OPTION_MASK)
    {
      case ACTION_PERMFAIL:
	smfi_setreply (ctx, "551", NULL, message);
	retval = SMFIS_REJECT;
	break;
      case ACTION_TEMPFAIL:
	smfi_setreply (ctx, "441", NULL, message);
	retval = SMFIS_TEMPFAIL;
	break;
      case ACTION_DISCARD:
	retval = SMFIS_DISCARD;
	break;
      case ACTION_TAG:
      default:
	return (SMFIS_CONTINUE);
	break;
    }
    mlfi_abort (ctx);
    return (retval);
}   /*  End Function search_databases  */

static sfsistat mlfi_connect (SMFICTX *ctx, char *hostname,
			      _SOCK_ADDR *hostaddr)
{
    struct connect_struct *privdata;

    /*  Set default message for resource problems  */
    smfi_setreply (ctx, "441", NULL, "milter-dnsrbl: allocation failure");
    if ( ( privdata = calloc (1, sizeof *privdata) ) == NULL )
	return (SMFIS_TEMPFAIL);
    smfi_setpriv (ctx, privdata);
    privdata->config = get_config ();
    privdata->action_relay = privdata->config->def_action_relay;
    if (hostaddr)
    {
	struct sockaddr_in *in_addr = (struct sockaddr_in *) hostaddr;
	struct config_struct *config = privdata->config;
	struct mta_struct *mta;

	privdata->connect_mta.address = ntohl (in_addr->sin_addr.s_addr);
	for (mta = config->first_mta; mta; mta = mta->next)
	{
	    if ( (privdata->connect_mta.address & mta->mta.mask)
		 == mta->mta.base )
	    {
		privdata->action_relay = mta->action_relay;
		break;
	    }
	}
    }
    else syslog (LOG_ERR, "NULL hostaddr in connect()");
    return (SMFIS_CONTINUE);
}   /*  End Function mlfi_connect  */

static flag should_check_address (unsigned long address)
{
    struct addr_range_s *privaddr;

    if (!address) return (FALSE);  /*  No address at all: don't check  */
    for (privaddr = private_addresses; privaddr->base; ++privaddr)
	if ( (address & privaddr->mask) == privaddr->base ) return (FALSE);
    return (TRUE);  /*  A real, non-private address: check it  */
}   /*  End Function should_check_address  */

static sfsistat mlfi_envfrom (SMFICTX *ctx, char **argv)
{
    struct connect_struct *privdata = smfi_getpriv (ctx);
    struct config_struct *config = privdata->config;

    /*  If the user has authenticated, accept the message immediately  */
    if ( smfi_getsymval (ctx, "{auth_authen}") ) return (SMFIS_ACCEPT);
    /*  Set default message for resource problems for each message  */
    smfi_setreply (ctx, "441", NULL, "milter-dnsrbl: allocation failure");
    privdata->connect_mta.match_bl = NULL;
    if ( !should_check_address (privdata->connect_mta.address) )
	return (SMFIS_CONTINUE);
    if ( smfi_getsymval (ctx, "{cert_subject}") )
    {   /*  If the connecting relay is known, ignore DNSRBL entries  */
	char *verify;

	verify = smfi_getsymval(ctx, "{verify}");
	if ( verify && (strcmp (verify, "OK") == 0) ) return (SMFIS_CONTINUE);
    }
    return search_databases (ctx, config->first_db, &privdata->connect_mta, 
			     FALSE, config->action_connect,
			     config->stall_time);
}   /*  End Function mlfi_envfrom  */

static sfsistat mlfi_header (SMFICTX *ctx, char *headerf, char *headerv)
{
    unsigned long address = 0;
    struct connect_struct *privdata = smfi_getpriv (ctx);

    if (strcmp (headerf, "Received") != 0) return (SMFIS_CONTINUE);
    ++headerv;
    while (*headerv)
    {
	char close_ch;
	unsigned long b0, b1, b2, b3;
	char *ptr;

	/*  If "by " is found, and already have address, stop scanning. Works
	    around unfortunate IP address self-reporting in Computer Associates
	    proprietary MTA software  */
	if ( (headerv[-1] == 'b') && (headerv[0] == 'y')
	     && (headerv[1] == ' ') && address ) break;
	if ( !isdigit (*headerv) )
	{
	    ++headerv;
	    continue;
	}
	switch (headerv[-1])
	{
	  case '[':
	    close_ch = ']';
	    break;
	  case '(':
	    close_ch =')';
	    break;
	  default:
	    ++headerv;
	    continue;
	}
	b0 = strtoul (headerv, &headerv, 10);
	if (*headerv++ != '.') continue;
	b1 = strtoul (headerv, &ptr, 10);
	if ( (ptr <= headerv) || (*ptr != '.') ) continue;
	headerv = ptr + 1;
	b2 = strtoul (headerv, &ptr, 10);
	if ( (ptr <= headerv) || (*ptr != '.') ) continue;
	headerv = ptr + 1;
	b3 = strtoul (headerv, &ptr, 10);
	if (ptr <= headerv) continue;
	headerv = ptr;
	if (*headerv != close_ch) continue;
	if ( (b0 > 255) || (b1 > 255) || (b2 > 255) || (b3 > 255) ) continue;
	address = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
	address = MKIPV4 (b0, b1, b2, b3);
    }
    if ( should_check_address (address) )
    {
	struct config_struct *config = privdata->config;
	struct address_struct *relay;

	if ( ( relay = calloc (1, sizeof *relay) ) == NULL )
	{
	    mlfi_abort (ctx);
	    return (SMFIS_TEMPFAIL);
	}
	relay->address = address;
	relay->next = privdata->first_relay;
	privdata->first_relay = relay;
	return search_databases (ctx, config->first_db, relay, TRUE,
				 privdata->action_relay, config->stall_time);
    }
    return (SMFIS_CONTINUE);
}   /*  End Function mlfi_header  */

static void maybe_tag_address (SMFICTX *ctx, struct address_struct *relay,
			       char *addrgroup)
{
    char *goodbad, *comment;
    char txt[256];

    if (!relay->match_bl) return;
    if ( (relay->arec_value & relay->match_bl->bl.mask)
	 == relay->match_bl->bl.base)
    {
	goodbad = "GOOD";
	comment = "blacklisted";
    }
    else
    {
	goodbad = "BAD";
	comment = "hijacked/misconfigured";
    }
    snprintf (txt, sizeof txt,
	      "%s %s match %lu.%lu.%lu.%lu (%s) for %lu.%lu.%lu.%lu in %s",
	      goodbad, addrgroup,
	      (relay->arec_value & 0xff000000) >> 24,
	      (relay->arec_value & 0x00ff0000) >> 16,
	      (relay->arec_value & 0x0000ff00) >> 8,
	      (relay->arec_value & 0x000000ff) >> 0,
	      comment,
	      (relay->address & 0xff000000) >> 24,
	      (relay->address & 0x00ff0000) >> 16,
	      (relay->address & 0x0000ff00) >> 8,
	      (relay->address & 0x000000ff) >> 0,
	      relay->match_bl->domain);
    smfi_addheader (ctx, "X-Milter-DNSRBL", txt);
}   /*  End Function maybe_tag_address  */

static sfsistat mlfi_eom (SMFICTX *ctx)
{
    struct connect_struct *privdata = smfi_getpriv (ctx);
    struct address_struct *relay;

    maybe_tag_address (ctx, &privdata->connect_mta, "connectIP");
    for (relay = privdata->first_relay; relay; relay = relay->next)
	maybe_tag_address (ctx, relay, "relayIP");
    return mlfi_abort (ctx);
}   /*  End Function mlfi_eom  */

static sfsistat mlfi_abort (SMFICTX *ctx)
{
    struct connect_struct *privdata = smfi_getpriv (ctx);
    struct address_struct *relay, *next;

    for (relay = privdata->first_relay; relay; relay = next)
    {
	next = relay->next;
	free (relay);
    }
    privdata->first_relay = NULL;
    return (SMFIS_CONTINUE);
}   /*  End Function mlfi_abort  */

sfsistat mlfi_close (SMFICTX *ctx)
{
    struct connect_struct *privdata = smfi_getpriv (ctx);

    smfi_setpriv (ctx, NULL);
    if (privdata)
    {
	put_config (privdata->config, TRUE);
	free (privdata);
    }
    return (SMFIS_CONTINUE);
}   /*  End Function mlfi_close  */

static struct smfiDesc smfilter =
{
    "DNSRBLMilter",	/* filter name */
    SMFI_VERSION,	/* version code -- do not change */
    SMFIF_ADDHDRS,	/* flags */
    mlfi_connect,	/* connection info filter */
    NULL,		/* SMTP HELO command filter */
    mlfi_envfrom,	/* envelope sender filter */
    NULL,		/* envelope recipient filter */
    mlfi_header,	/* header filter */
    NULL,		/* end of header */
    NULL,		/* body block filter */
    mlfi_eom,		/* end of message */
    mlfi_abort,		/* message aborted */
    mlfi_close		/* connection cleanup */
};

int main (int argc, char *argv[])
{
    int c;
    struct config_struct *config;
    char *args = "p:";

    openlog ("milter-dnsrbl", 0, LOG_MAIL);
    if ( ( config = get_config () ) == NULL )
    {
	fprintf (stderr, "No config data\n");
	exit (EX_OSFILE);
    }
    put_config (config, FALSE);  /*  Mark it unused  */
    switch ( fork () )
    {
      case 0:   /*  Child   */
	break;
      case -1:  /*  Error   */
	fprintf (stderr, "Error forking\n");
	exit (EX_UNAVAILABLE);
	/*break;*/
      default:  /*  Parent  */
	_exit (0);
	/*break;*/
    }
    /* Process command line options */
    while ( ( c = getopt (argc, argv, args) ) != -1 )
    {
	switch (c)
	{
	  case 'p':
	    if ( !optarg || (*optarg == '\0') )
	    {
		fprintf (stderr, "Illegal conn: %s\n", optarg);
		exit (EX_USAGE);
	    }
	    smfi_setconn (optarg);
	    break;
	}
    }
    if (smfi_register (smfilter) == MI_FAILURE)
    {
	fprintf (stderr, "smfi_register failed\n");
	exit (EX_UNAVAILABLE);
    }
    umask (S_IXUSR | S_IRWXG | S_IRWXO);
    close (0);
    close (1);
    close (2);
    return smfi_main ();
}   /*  End Function main  */


/*  Debugging code follows  */
#ifdef DEBUG

static void do_sleep (unsigned int seconds)
{
    int num_sleepers_l;
    static pthread_mutex_t count_lock = PTHREAD_MUTEX_INITIALIZER;
    static int num_sleepers = 0;

    pthread_mutex_lock (&count_lock);
    num_sleepers_l = ++num_sleepers;
    pthread_mutex_unlock (&count_lock);
    syslog (LOG_INFO, "pid=%d starting sleep for %u seconds, %d sleepers",
	    getpid (), seconds, num_sleepers_l);
    my_sleep (seconds);
    pthread_mutex_lock (&count_lock);
    num_sleepers_l = --num_sleepers;
    pthread_mutex_unlock (&count_lock);
    syslog (LOG_INFO, "pid=%d finished sleep for %u seconds, %d sleepers",
	    getpid (), seconds, num_sleepers_l);
}   /*  End Function do_sleep  */

#endif   /*  DEBUG  */
