/*  milter-regexp.c

    Main file for  milter-regexp  (Sendmail Milter to process regular exp.).

    Copyright (C) 2004  Richard Gooch

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
    This milter allows you to reject or stall messages by specifying regular
    expressions.


    Written by      Richard Gooch   21-FEB-2004: Copied skeleton from
  milter-dnsrbl.c file.

    Updated by      Richard Gooch   29-FEB-2004: First cut after intermittent
  coding.

    Updated by      Richard Gooch   1-MAR-2004: Added message buffer for lines
  split across calls to <mlfi_body>.

    Updated by      Richard Gooch   5-MAR-2004: Fixed config file name for
  users.

    Updated by      Richard Gooch   7-MAR-2004: Strip linefeed and carriage
  return in <mlfi_header>.

    Updated by      Richard Gooch   4-MAY-2004: Added -f option and ability to
  match envelope sender address.

    Updated by      Richard Gooch   5-MAY-2004: Fixed bug in <mlfi_eom>:
  recipients with PERMFAIL or TEMPFAIL actions were not being discarded when
  other recipients want delivery/redirection.

    Updated by      Richard Gooch   15-MAY-2004: Increased BODY_BUFLEN from
  256 to 1024 (received Chinese spam with a 644 byte line).

    Updated by      Richard Gooch   27-MAY-2004: Fixed config file processing:
  "ACCEPT" was resulting in REDIRECT action. Converted configuration file names
  to lower-case. Thanks to Adrian Thomas.

    Updated by      Richard Gooch   10-JUN-2004: Added default TEMPFAIL message
  to expose resource allocation failures.

    Updated by      Richard Gooch   16-JUN-2004: Unified header and body
  buffers and use heap space instead of stack space in case some thread
  implementations have tiny (i.e. only few KiB) stacks allocations per thread.

    Updated by      Richard Gooch   27-JUN-2004: Report errors from regcomp(3).

    Updated by      Richard Gooch   20-SEP-2004: Added envelope recipient
  matching.

    Updated by      Richard Gooch   24-SEP-2004: Increased BUFLEN from
  1024 to 2048 (received Korean spam with a 1242 byte To: header line). Fixed
  bug in <mlfi_eom>: bad user configuration file caused a pointer dereference
  of a character value.

    Last updated by Richard Gooch   13-NOV-2004: Fixed bug in <mlfi_body>:
  could overwrite message buffer by one byte.


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
#include <regex.h>
#include <netdb.h>
#include <libmilter/mfapi.h>
#include <errno.h>
#include <pthread.h>


#define ERRSTRING                strerror (errno)
#define FALSE                    0
#define TRUE                     1
#define STRING_LENGTH          256
#define BUFLEN                2048
#define CONFIG_FILE              "/etc/mail/milter-regexp.conf"
#define DEFAULT_STALL_SECONDS    5
#define FILTER_FLAGS             SMFIF_ADDHDRS | SMFIF_ADDRCPT | SMFIF_DELRCPT
#define STALL_TIME              10

#define ACTION_UNITIALISED        0
#define ACTION_PERMFAIL           1
#define ACTION_TEMPFAIL           2
#define ACTION_TAG                3
#define ACTION_DISCARD            4
#define ACTION_REDIRECT           5
#define ACTION_ACCEPT             6
#define ACTION_OPTION_MASK     0xf0
#define ACTION_OPT_STALL       0x10

#define CHECK_SENDER              0
#define CHECK_RECIPIENT           1
#define CHECK_HEADER              2
#define CHECK_BODY                3

#define my_sleep(seconds) poll(NULL, 0, seconds * 1000)

#ifdef DEBUG
static void do_sleep (unsigned int seconds);
#else
#define do_sleep(seconds) my_sleep(seconds)
#endif

typedef char flag;

struct regexp
{
    flag inverted;                /*  Whether to invert the regexp result    */
    flag and_logic;               /*  TRUE: AND logic, FALSE: OR logic       */
    char where;                   /*  Where to check (sender, header, body)  */
    regex_t preg;                 /*  The compiled regular expression        */
    struct regexp *next;          /*  The next regular expression structure  */
};

struct recipe
{
    unsigned int num_expressions; /*  Number of regular expressions          */
    struct regexp *first_regexp;  /*  The first regular expression           */
    struct regexp *last_regexp;   /*  The last regular expression            */
    unsigned char action;         /*  Action to take on match                */
    char *string;                 /*  Message text or redirect recipient     */
    flag no_body;                 /*  TRUE: no expressions are for body      */
    struct recipe *next;          /*  The next recipe structure              */
};

struct config
{
    unsigned int refcount;        /*  When this drops to 0, may deallocate   */
    struct recipe *first_recipe;  /*  The first recipe                       */
    struct recipe *last_recipe;   /*  The last recipe                        */
};

struct recipient
{
    flag bad_config;              /*  Whether the config file was bad        */
    struct config *config;        /*  The configuration structure            */
    time_t last_rtime;            /*  Time of last attempted read            */
    struct recipient *next;       /*  The next recipient structure           */
    char name[1];                 /*  The name of the recipient. "" is all   */
    /*  Nothing must come here, since <<name>> is stored here                */
};

struct regexp_status
{
    flag matched;                 /*  Whether this expression has matched    */
    const struct regexp *regexp;  /*  The regular expression                 */
};

struct recipe_status
{
    const struct recipe *recipe;  /*  The recipe                             */
    struct recipe_status *next;   /*  The next recipe status structure       */
    struct regexp_status expressions[1]; /* The regular expressions          */
    /*  Nothing must come here, since <<expressions>> is stored here         */
};

struct envrcpt
{
    const char *name;             /*  The name of the recipient. "" is all   */
    flag bad_config;              /*  Whether the config file was bad        */
    struct config *config;        /*  The configuration structure            */
    struct recipe_status *first;  /*  The first recipe                       */
    struct recipe_status *last;   /*  The last recipe                        */
    const struct recipe *matched; /*  The recipe that matched                */
    struct envrcpt *next;         /*  The next envrcpt for this message      */
};

struct message
{
    const char *envfrom;          /*  The envelope sender                    */
    flag long_header;             /*  Whether header line was too big        */
    unsigned int body_overrun;    /*  Number bytes in oversized body line    */
    struct envrcpt *first;        /*  The first envelope recipient           */
    struct envrcpt *last;         /*  The last envelope recipient            */
    unsigned int wpos;            /*  Position to start writing to buffer    */
    u_char buffer[BUFLEN];        /*  The header/body overrun buffer         */
};


static pthread_mutex_t config_lock = PTHREAD_MUTEX_INITIALIZER;
static char *usersdir = NULL;
static flag debug = FALSE;
static flag full_recipient = FALSE;


static void put_config (struct config *config, flag grab_lock)
{
    int dealloc = FALSE;
    struct recipe *recipe, *recipe_next;

    if (grab_lock) pthread_mutex_lock (&config_lock);
    if (config->refcount > 0) --config->refcount;
    else dealloc = TRUE;
    if (grab_lock) pthread_mutex_unlock (&config_lock);
    if (!dealloc) return;
    for (recipe = config->first_recipe; recipe; recipe = recipe_next)
    {
	struct regexp *regexp, *regexp_next;

	recipe_next = recipe->next;
	for (regexp = recipe->first_regexp; regexp; regexp = regexp_next)
	{
	    regexp_next = regexp->next;
	    regfree (&regexp->preg);
	    free (regexp);
	}
	if (recipe->string) free (recipe->string);
	free (recipe);
    }
    free (config);
}   /*  End Function put_config  */

static char *skip_to_next (char *ptr)
/*  [SUMMARY] Skip whitespace to next non-whitespace character.
    <ptr> A pointer to the current non-whitespace character.
    [RETURNS] A pointer to the next non-whitespace character after the
    following whitespace. NULL is returned if following whitespace was not
    found or the end of the string was reached.
*/
{
    if ( !isspace (*++ptr) ) return (NULL);
    for (++ptr; isspace (*ptr); ++ptr);
    return (*ptr ? ptr : NULL);
}   /*  End Function skip_to_next  */

static flag process_config_line (char *line, struct config *config)
/*  [SUMMARY] Process a configuration file line.
    <line> The line from the configuration file.
    <config> The config structure.
    [RETURNS] TRUE on success, else FALSE.
*/
{
    char *ptr;

    while ( isspace (*line) ) ++line;  /*  Skip leading whitespace  */
    if (*line == '#') return (TRUE);
    /*  Strip trailing whitespace  */
    for (ptr = line + strlen (line) - 1; ptr > line; --ptr)
    {
	if ( isspace (*ptr) ) *ptr = '\0';
	else break;
    }
    if (ptr <= line) return (TRUE);
    if ( (*line == 's') || (*line == 'r') || (*line == 'h') || (*line == 'b') )
    {
	int errcode;
	struct regexp tmp, *regexp;
	struct recipe *recipe;

	memset (&tmp, 0, sizeof tmp);
	tmp.and_logic = TRUE;
	switch (*line)
	{
	  case 's':
	    tmp.where = CHECK_SENDER;
	    break;
	  case 'r':
	    tmp.where = CHECK_RECIPIENT;
	    break;
	  case 'h':
	    tmp.where = CHECK_HEADER;
	    break;
	  case 'b':
	    tmp.where = CHECK_BODY;
	    break;
	}
	if ( ( line = skip_to_next (line) ) == NULL ) return (FALSE);
	if (*line == '&')
	{
	    if ( ( line = skip_to_next (line) ) == NULL ) return (FALSE);
	}
	else if (*line == '|')
	{
	    tmp.and_logic = FALSE;
	    if ( ( line = skip_to_next (line) ) == NULL ) return (FALSE);
	}
	if (*line == '!')
	{
	    tmp.inverted = TRUE;
	    if ( ( line = skip_to_next (line) ) == NULL ) return (FALSE);
	}
	if ( ( errcode = regcomp (&tmp.preg, line, REG_EXTENDED | REG_ICASE) )
	     != 0)
	{
	    char errbuf[STRING_LENGTH];

	    regerror (errcode, &tmp.preg, errbuf, sizeof errbuf);
	    syslog (LOG_ERR, "regcomp(3) error: %s", errbuf);
	    return (FALSE);
	}
	if ( ( regexp = malloc (sizeof *regexp) ) == NULL )
	{
	    regfree (&tmp.preg);
	    return (FALSE);
	}
	memcpy (regexp, &tmp, sizeof *regexp);
	if ( config->last_recipe &&
	     (config->last_recipe->action == ACTION_UNITIALISED) )
	{   /*  Add to existing recipe  */
	    ++config->last_recipe->num_expressions;
	    config->last_recipe->last_regexp->next = regexp;
	    config->last_recipe->last_regexp = regexp;
	    if (regexp->where == CHECK_BODY)
		config->last_recipe->no_body = FALSE;
	    return (TRUE);
	}
	/*  Create new recipe  */
	if ( ( recipe = calloc (1, sizeof *recipe) ) == NULL )
	{
	    regfree (&regexp->preg);
	    free (regexp);
	    return (FALSE);
	}
	recipe->num_expressions = 1;
	recipe->first_regexp = regexp;
	recipe->last_regexp = regexp;
	recipe->no_body = (regexp->where == CHECK_BODY) ? FALSE : TRUE;
	if (config->last_recipe) config->last_recipe->next = recipe;
	else config->first_recipe = recipe;
	config->last_recipe = recipe;
	return (TRUE);
    }
    if (!config->last_recipe) return (FALSE);
    if (strncasecmp (line, "MESSAGE", 7) == 0)
    {
	if (config->last_recipe->string) return (FALSE);
	ptr = skip_to_next (line + 6);
	config->last_recipe->string = strdup (ptr);
	return (config->last_recipe->string ? TRUE : FALSE);
    }
    if (strncasecmp (line, "DESTINATION", 11) == 0)
    {
	if (config->last_recipe->string) return (FALSE);
	ptr = skip_to_next (line + 10);
	config->last_recipe->string = strdup (ptr);
	return (config->last_recipe->string ? TRUE : FALSE);
    }
    if (config->last_recipe->action) return (FALSE);
    /*  Now process all the actions  */
    for (ptr = line; *ptr; )
    {
	unsigned char *action = &config->last_recipe->action;

	if (*ptr == ',')
	{
	    for (++ptr; isspace (*ptr); ++ptr);
	    continue;
	}
	if (strncasecmp (ptr, "PERMFAIL", 8) == 0)
	{
	    *action = (*action & ACTION_OPTION_MASK) + ACTION_PERMFAIL;
	    ptr += 8;
	}
	else if (strncasecmp (ptr, "TEMPFAIL", 8) == 0)
	{
	    *action = (*action & ACTION_OPTION_MASK) + ACTION_TEMPFAIL;
	    ptr += 8;
	}
	else if (strncasecmp (ptr, "TAG", 3) == 0)
	{
	    *action = (*action & ACTION_OPTION_MASK) + ACTION_TAG;
	    ptr += 3;
	}
	else if (strncasecmp (ptr, "DISCARD", 7) == 0)
	{
	    *action = (*action & ACTION_OPTION_MASK) + ACTION_DISCARD;
	    ptr += 7;
	}
	else if (strncasecmp (ptr, "REDIRECT", 8) == 0)
	{
	    *action = (*action & ACTION_OPTION_MASK) + ACTION_REDIRECT;
	    ptr += 8;
	}
	else if (strncasecmp (ptr, "ACCEPT", 6) == 0)
	{
	    *action = (*action & ACTION_OPTION_MASK) + ACTION_ACCEPT;
	    ptr += 6;
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
    return (TRUE);
}   /*  End Function process_config_line  */

static struct config *read_config (const char *filename)
/*  [SUMMARY] Read the configuration file.
    <filename> The filename to read from.
    [NOTE] The <<config_lock>> must be held by the caller.
    [NOTE] This should only be called by [<get_envrcpt>].
    [RETURNS] A pointer to the configuration on success, else NULL.
*/
{
    struct config *config;
    FILE *fp;
    char line[1024];

    if ( ( fp = fopen (filename, "r") ) == NULL ) return (NULL);
    if ( ( config = calloc (1, sizeof *config) ) == NULL )
    {
	fclose (fp);
	return (NULL);
    }
    while ( fgets (line, sizeof line, fp) )
    {
	if ( !process_config_line (line, config) )
	{
	    put_config (config, FALSE);
	    fclose (fp);
	    syslog (LOG_ERR, "bad config line: \"%s\"", line);
	    return (NULL);
	}
    }
    fclose (fp);
    return (config);
}   /*  End Function read_config  */

static void free_envrcpt (struct envrcpt *envrcpt)
{
    struct recipe_status *rstatus, *rstatus_next;

    for (rstatus = envrcpt->first; rstatus; rstatus = rstatus_next)
    {
	rstatus_next = rstatus->next;
	free (rstatus);
    }
    if (envrcpt->config) put_config (envrcpt->config, TRUE);
    free (envrcpt);
}   /*  End Function free_envrcpt  */

static struct envrcpt *get_envrcpt (const char *recipient_name)
/*  [SUMMARY] Get the current configuration for an envelope recipient.
    <recipient> The recipient name, or NULL for all recipients.
    [RETURNS] A pointer to the configuration on success, else NULL.
*/
{
    struct stat statbuf;
    struct recipient *recipient;
    struct envrcpt *envrcpt;
    struct recipe *recipe;
    char filename[STRING_LENGTH];
    static struct recipient *first_recipient = NULL;
    static struct recipient *last_recipient = NULL;

    if (recipient_name)
    {
	int pos;
	const char *ptr = recipient_name;
	char user[STRING_LENGTH + 1];

	if (*ptr == '<') ++ptr;
	for (pos = 0; *ptr && (pos < STRING_LENGTH); ++ptr)
	{
	    if (*ptr == '>') break;
	    if (*ptr == '/') continue;
	    if ( !full_recipient && (*ptr == '@') ) break;
	    user[pos++] = tolower (*ptr);
	}
	user[pos] = '\0';
	snprintf (filename, STRING_LENGTH, "%s/%s/.milter-regexp.conf",
		  usersdir, user);
    }
    else strcpy (filename, CONFIG_FILE);
    if ( ( envrcpt = calloc (1, sizeof *envrcpt) ) == NULL ) return (NULL);
    pthread_mutex_lock (&config_lock);
    for (recipient = first_recipient; recipient; recipient = recipient->next)
    {
	if ( recipient_name && (strcmp (recipient_name,recipient->name) == 0) )
	    break;
	if (!recipient_name && !recipient->name[0]) break;
    }
    if (!recipient)
    {
	int len = sizeof *recipient;

	if (recipient_name) len += strlen (recipient_name);
	if ( ( recipient = calloc (1, len) ) == NULL )
	{
	    pthread_mutex_unlock (&config_lock);
	    free (envrcpt);
	    return (NULL);
	}
	if (last_recipient) last_recipient->next = recipient;
	else first_recipient = recipient;
	last_recipient = recipient;
	if (recipient_name) strcpy (recipient->name, recipient_name);
    }
    envrcpt->name = recipient->name;
    if (stat (filename, &statbuf) == 0)
    {
	if (statbuf.st_mtime > recipient->last_rtime)
	{   /*  File exists and has changed since the last attempted read  */
	    struct config *config = read_config (filename);

	    recipient->last_rtime = statbuf.st_mtime;
	    if (config)
	    {
		if (recipient->config)
		{
		    put_config (recipient->config, FALSE);
		    syslog (LOG_INFO, "re-read config file: %s", filename);
		}
		else syslog (LOG_INFO, "read config file: %s", filename);
		recipient->config = config;
		recipient->bad_config = FALSE;
	    }
	    else
	    {
		syslog (LOG_INFO, "error in %s config file: %s",
			recipient->config ? "replacement" : "new", filename);
		if (recipient->config)
		{
		    put_config (recipient->config, FALSE);
		    recipient->config = NULL;
		}
		recipient->bad_config = TRUE;
	    }
	}
    }
    else if (recipient->config)
    {
	put_config (recipient->config, FALSE);
	recipient->config = NULL;
	syslog (LOG_INFO, "forgetting deleted config file: %s", filename);
	recipient->bad_config = FALSE;
    }
    if (recipient->config) ++recipient->config->refcount;
    envrcpt->bad_config = recipient->bad_config;
    pthread_mutex_unlock (&config_lock);
    envrcpt->config = recipient->config;
    if (!recipient->config) return (envrcpt);
    /*  Populate the recipient structure for this message  */
    for (recipe = recipient->config->first_recipe; recipe;
	 recipe = recipe->next)
    {
	signed int len = (signed int) recipe->num_expressions - 1;
	struct recipe_status *rstatus;
	struct regexp *regexp;

	if (recipe->action == ACTION_UNITIALISED) continue;
	if (len < 0) len = 0;
	len *= sizeof (struct regexp_status);
	if ( ( rstatus = calloc (1, sizeof *rstatus + len) ) == NULL )
	{
	    free_envrcpt (envrcpt);
	    return (NULL);
	}
	rstatus->recipe = recipe;
	for (regexp = recipe->first_regexp, len = 0; regexp;
	     regexp = regexp->next, ++len)
	    rstatus->expressions[len].regexp = regexp;
	if (envrcpt->last) envrcpt->last->next = rstatus;
	else envrcpt->first = rstatus;
	envrcpt->last = rstatus;
    }
    return (envrcpt);
}   /*  End Function get_envrcpt  */

static sfsistat mlfi_envfrom (SMFICTX *ctx, char **argv)
{
    struct message *message;

    if (debug) fprintf (stderr, "mlfi_envfrom: \"%s\"\n", argv[0]);
    /*  Set default message for resource problems for each message  */
    smfi_setreply (ctx, "441", NULL, "milter-regexp: allocation failure");
    if ( ( message = calloc (1, sizeof *message) ) == NULL )
	return (SMFIS_TEMPFAIL);
    if ( ( message->envfrom = strdup (argv[0]) ) == NULL )
    {
	free (message);
	return (SMFIS_TEMPFAIL);
    }
    if ( ( message->first = get_envrcpt (NULL) ) == NULL )
    {
	free ( (void *) message->envfrom );
	free (message);
	return (SMFIS_TEMPFAIL);
    }
    message->last = message->first;
    smfi_setpriv (ctx, message);
    return (SMFIS_CONTINUE);
}   /*  End Function mlfi_envfrom  */

static sfsistat mlfi_envrcpt (SMFICTX *ctx, char **argv)
{
    struct message *message = smfi_getpriv (ctx);
    struct envrcpt *envrcpt;

    if (debug) fprintf (stderr, "mlfi_envrcpt: \"%s\"\n", argv[0]);
    if ( ( envrcpt = get_envrcpt (argv[0]) ) == NULL ) return (SMFIS_TEMPFAIL);
    message->last->next = envrcpt;
    message->last = envrcpt;
    return (SMFIS_CONTINUE);
}   /*  End Function mlfi_envrcpt  */

static void process_line (SMFICTX *ctx, const char *line, char where)
/*  [SUMMARY] Perform regexp matching on a line of data.
    <ctx> The message context.
    <line> The line of data.
    <where> The part of the message where the line came from.
    [NOTE] This must be called in [<mlfi_header>] or later, to ensure all
    envelope recipients have their configuration data available.
    [RETURNS] Nothing.
*/
{
    struct message *message = smfi_getpriv (ctx);
    struct envrcpt *envrcpt;

    for (envrcpt = message->first; envrcpt; envrcpt = envrcpt->next)
    {
	struct recipe_status *rstatus;

	if (envrcpt->matched) continue;
	for (rstatus = envrcpt->first; rstatus; rstatus = rstatus->next)
	{
	    unsigned int count;

	    for (count = 0; count < rstatus->recipe->num_expressions; ++count)
	    {
		struct regexp_status *re = rstatus->expressions + count;

		if (re->matched) continue;
		if (re->regexp->where != where) continue;
		if (regexec (&re->regexp->preg, line, 0, NULL, 0) == 0)
		    re->matched = TRUE;
	    }
	}
    }
}   /*  End Function process_line  */

static sfsistat mlfi_header (SMFICTX *ctx, char *headerf, char *headerv)
{
    size_t len;
    struct message *message = smfi_getpriv (ctx);
    char *inptr, *outptr, *stop;

    if (message->envfrom)
    {   /*  First time for this message  */
	struct envrcpt *envrcpt;

	process_line (ctx, message->envfrom, CHECK_SENDER);
	free ( (void *) message->envfrom );
	message->envfrom = NULL;
	for (envrcpt = message->first->next; envrcpt; envrcpt = envrcpt->next)
	    process_line (ctx, envrcpt->name, CHECK_RECIPIENT);
    }
    if (message->long_header) return (SMFIS_CONTINUE);
    len = strlen (headerf);
    if (len + 5 > BUFLEN)
    {
	message->long_header = TRUE;
	return (SMFIS_CONTINUE);
    }
    sprintf (message->buffer, "%s: ", headerf);
    outptr = (char *) message->buffer + len + 2;
    stop = (char *) message->buffer + BUFLEN;
    for (inptr = headerv; outptr < stop; ++inptr)
    {
	if ( (*inptr == '\n') || (*inptr == '\r') ) continue;
	*outptr = *inptr;
	if (!*outptr) break;
	++outptr;
    }
    if (outptr >= stop)
    {
	message->long_header = TRUE;
	return (SMFIS_CONTINUE);
    }
    process_line (ctx, message->buffer, CHECK_HEADER);
    return (SMFIS_CONTINUE);
}   /*  End Function mlfi_header  */

static sfsistat mlfi_abort (SMFICTX *ctx);

static sfsistat test_all (SMFICTX *ctx, flag header_only)
{
    sfsistat retval = SMFIS_ACCEPT;
    struct message *message = smfi_getpriv (ctx);
    struct envrcpt *envrcpt;
    const struct recipe *matched_sys_recipe;

    for (envrcpt = message->first; envrcpt; envrcpt = envrcpt->next)
    {
	struct recipe_status *rstatus;

	if (envrcpt->matched) continue;
	for (rstatus = envrcpt->first; rstatus; rstatus = rstatus->next)
	{
	    flag match;
	    unsigned int count;
	    const struct recipe *recipe = rstatus->recipe;

	    if (header_only && !recipe->no_body) break;
	    match = rstatus->expressions[0].regexp->and_logic ? TRUE : FALSE;
	    for (count = 0; count < recipe->num_expressions; ++count)
	    {
		flag regexp_val;
		struct regexp_status *re = rstatus->expressions + count;

		regexp_val = re->matched;
		if (re->regexp->inverted)
		    regexp_val = regexp_val ? FALSE : TRUE;
		if (re->regexp->and_logic)
		    match = (match & regexp_val) ? TRUE : FALSE;
		else match = (match | regexp_val) ? TRUE : FALSE;
	    }
	    if (match)
	    {
		envrcpt->matched = recipe;
		break;
	    }
	}
    }
    matched_sys_recipe = message->first->matched;
    if (!matched_sys_recipe) return (SMFIS_CONTINUE);
    /*  Early processing of matched recipe in system configuration  */
    switch (matched_sys_recipe->action & ~ACTION_OPTION_MASK)
    {
      case ACTION_PERMFAIL:
	smfi_setreply (ctx, "551", NULL, matched_sys_recipe->string);
	retval = SMFIS_REJECT;
	break;
      case ACTION_TEMPFAIL:
	smfi_setreply (ctx, "441", NULL, matched_sys_recipe->string);
	retval = SMFIS_TEMPFAIL;
	break;
      case ACTION_TAG:
	if (header_only) return (SMFIS_CONTINUE);  /*  Wait until mlfi_eom() */
	smfi_addheader (ctx, "X-Milter-regexp", matched_sys_recipe->string);
	break;
      case ACTION_DISCARD:
	retval = SMFIS_DISCARD;
	break;
      case ACTION_REDIRECT:
	if (header_only) return (SMFIS_CONTINUE);  /*  Wait until mlfi_eom() */
	for (envrcpt = message->first->next; envrcpt; envrcpt = envrcpt->next)
	    smfi_delrcpt (ctx, (char *) envrcpt->name);
	smfi_addrcpt (ctx, matched_sys_recipe->string);
	break;
      case ACTION_ACCEPT:
	break;
      default:
	return (SMFIS_CONTINUE);
	break;
    }
    if (matched_sys_recipe->action & ACTION_OPT_STALL) do_sleep (STALL_TIME);
    return (retval);
}   /*  End Function test_all  */

static sfsistat mlfi_eoh (SMFICTX *ctx)
{
    sfsistat retval;
    struct message *message = smfi_getpriv (ctx);

    if (debug) fprintf (stderr, "mlfi_eoh\n");
    if (message->long_header) return (SMFIS_CONTINUE);
    retval = test_all (ctx, TRUE);
    if (retval != SMFIS_CONTINUE) mlfi_abort (ctx);
    return (retval);
}   /*  End Function mlfi_eoh  */

static sfsistat mlfi_body (SMFICTX *ctx, u_char *bodyp, size_t bodylen)
{
    struct message *message = smfi_getpriv (ctx);
    u_char *stop = bodyp + bodylen;

    if (message->body_overrun) return (SMFIS_CONTINUE);
    while (bodyp < stop)
    {
	u_char *eol;

	for (eol = bodyp; eol < stop; ++eol)
	{
	    switch (*eol)
	    {
	      case '\0':
	      case '\n':
	      case '\r':
		break;
	      default:
		continue;
	    }
	    break;
	}
	if (eol >= stop)
	{   /*  No EndOfLine: try to store in buffer for next time around  */
	    unsigned int len = stop - bodyp;

	    if (message->wpos + len >= BUFLEN)
	    {
		message->body_overrun = message->wpos + len;
		return (SMFIS_CONTINUE);
	    }
	    memcpy (message->buffer + message->wpos, bodyp, len);
	    message->wpos += len;
	    return (SMFIS_CONTINUE);
	}
	*eol = '\0';
	if (message->wpos)
	{   /*  Append to unfinished line obtained previously  */
	    unsigned int len = eol - bodyp + 1;  /*  Include terminator  */

	    if (message->wpos + len >= BUFLEN)
	    {
		message->body_overrun = message->wpos + len;
		return (SMFIS_CONTINUE);
	    }
	    memcpy (message->buffer + message->wpos, bodyp, len);
	    process_line (ctx, message->buffer, CHECK_BODY);
	    message->wpos = 0;
	}
	else if (eol > bodyp) process_line (ctx, bodyp, CHECK_BODY);
	bodyp = eol + 1;
    }
    return (SMFIS_CONTINUE);
}   /*  End Function mlfi_body  */

static sfsistat mlfi_eom (SMFICTX *ctx)
{
    flag someone_wants_stall = FALSE;
    sfsistat retval;
    struct message *message = smfi_getpriv (ctx);
    struct envrcpt *envrcpt;
    unsigned int best_action = ACTION_UNITIALISED;
    char *reply = NULL;
    char txt[STRING_LENGTH];
    static char *err_header = "X-Milter-regexp-error";
    static char *tag_header = "X-Milter-regexp";

    if (debug) fprintf (stderr, "mlfi_eom\n");
    if (message->long_header) smfi_addheader (ctx, err_header, "long header");
    if (message->body_overrun)
    {
	sprintf (txt, "body broken, long line of at least: %d bytes",
		 message->body_overrun);
	smfi_addheader (ctx, err_header, txt);
    }
    else if (message->wpos)
	smfi_addheader (ctx, err_header, "unterminated trailing body line");
    for (envrcpt = message->first; envrcpt; envrcpt = envrcpt->next)
    {
	if (!envrcpt->bad_config) continue;
	if (envrcpt->name[0])
	{
	    char txt[STRING_LENGTH];

	    snprintf (txt, STRING_LENGTH, "bad configuration for user: %s",
		      envrcpt->name);
	    smfi_addheader (ctx, err_header, txt);
	}
	else smfi_addheader (ctx, err_header, "bad system configuration file");
    }
    if (message->long_header || message->body_overrun) return mlfi_abort (ctx);
    retval = test_all (ctx, FALSE);
    if (retval != SMFIS_CONTINUE)
    {
	mlfi_abort (ctx);
	return (retval);
    }
    /*  No system recipe matched, find user recipes that matched and resolve */
    /*  First find action that will be used for the message  */
    for (envrcpt = message->first->next; envrcpt; envrcpt = envrcpt->next)
    {
	unsigned char action;
	const struct recipe *recipe = envrcpt->matched;

	action = recipe ? recipe->action : ACTION_ACCEPT;
	if (action & ACTION_OPT_STALL) someone_wants_stall = TRUE;
	action &= ~ACTION_OPTION_MASK;
	switch (action)  /*  Treat delivery actions the same for now  */
	{
	  case ACTION_TAG:
	  case ACTION_REDIRECT:
	    action = ACTION_ACCEPT;
	    break;
	}
	if (best_action == ACTION_UNITIALISED)
	{
	    best_action = action;
	    if (recipe) reply = recipe->string;
	}
	else
	{
	    if (best_action == action) continue;
	    switch (action)
	    {
	      case ACTION_PERMFAIL:
		if (best_action == ACTION_DISCARD)
		{
		    best_action = action;
		    reply = recipe->string;
		}
		break;
	      case ACTION_TEMPFAIL:
		switch (best_action)
		{
		  case ACTION_PERMFAIL:
		  case ACTION_DISCARD:
		    best_action = action;
		    reply = recipe->string;
		    break;
		}
		break;
	      case ACTION_DISCARD:
		break;
	      case ACTION_ACCEPT:
		best_action = ACTION_ACCEPT;
		break;
	    }
	}
    }
    /*  Now can stall and reject/discard message if appropriate  */
    if ( someone_wants_stall && (best_action != ACTION_ACCEPT) )
	do_sleep (STALL_TIME);
    switch (best_action)
    {
	case ACTION_PERMFAIL:
	smfi_setreply (ctx, "551", NULL, reply);
	mlfi_abort (ctx);
	return (SMFIS_REJECT);
	break;
      case ACTION_TEMPFAIL:
	smfi_setreply (ctx, "441", NULL, reply);
	mlfi_abort (ctx);
	return (SMFIS_TEMPFAIL);
	break;
      case ACTION_DISCARD:
	mlfi_abort (ctx);
	return (SMFIS_DISCARD);
	break;
    }
    /*  Message will be delivered/redirected to at least one recipient, so now
	add tags and change recipients as appropriate  */
    for (envrcpt = message->first->next; envrcpt; envrcpt = envrcpt->next)
    {
	unsigned char action;
	const struct recipe *recipe = envrcpt->matched;

	action = recipe ? recipe->action : ACTION_ACCEPT;
	action &= ~ACTION_OPTION_MASK;
	switch (action)
	{
	  case ACTION_TAG:
	    smfi_addheader (ctx, tag_header, recipe->string);
	    break;
	  case ACTION_PERMFAIL:
	  case ACTION_TEMPFAIL:
	  case ACTION_DISCARD:
	    smfi_delrcpt (ctx, (char *) envrcpt->name);
	    break;
	  case ACTION_REDIRECT:
	    smfi_delrcpt (ctx, (char *) envrcpt->name);
	    smfi_addrcpt (ctx, recipe->string);
	    break;
	}
    }
    return mlfi_abort (ctx);
}   /*  End Function mlfi_eom  */

static sfsistat mlfi_abort (SMFICTX *ctx)
{
    struct message *message = smfi_getpriv (ctx);
    struct envrcpt *envrcpt, *envrcpt_next;

    if (debug) fprintf (stderr, "mlfi_abort\n");
    smfi_setpriv (ctx, NULL);
    for (envrcpt = message->first; envrcpt; envrcpt = envrcpt_next)
    {
	envrcpt_next = envrcpt->next;
	free_envrcpt (envrcpt);
    }
    if (message->envfrom) free ( (void *) message->envfrom );
    free (message);
    return (SMFIS_CONTINUE);
}   /*  End Function mlfi_abort  */

static struct smfiDesc smfilter =
{
    "RegexpMilter",	/* filter name */
    SMFI_VERSION,	/* version code -- do not change */
    FILTER_FLAGS,	/* flags */
    NULL,		/* connection info filter */
    NULL,		/* SMTP HELO command filter */
    mlfi_envfrom,	/* envelope sender filter */
    mlfi_envrcpt,	/* envelope recipient filter */
    mlfi_header,	/* header filter */
    mlfi_eoh,		/* end of header */
    mlfi_body,		/* body block filter */
    mlfi_eom,		/* end of message */
    mlfi_abort,		/* message aborted */
    NULL		/* connection cleanup */
};

int main (int argc, char *argv[])
{
    int c;
    struct config *config;
    struct stat statbuf;
    char *args = "p:u:df";

    openlog ("milter-regexp", 0, LOG_MAIL);
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
	  case 'u':
	    if ( !optarg || (*optarg == '\0') )
	    {
		fprintf (stderr, "Illegal user directory: %s\n", optarg);
		exit (EX_USAGE);
	    }
	    if (stat (optarg, &statbuf) != 0)
	    {
		fprintf (stderr, "Error stating: \"%s\"\t%s\n",
			 optarg, ERRSTRING);
		exit (EX_NOINPUT);
	    }
	    if ( !S_ISDIR (statbuf.st_mode) )
	    {
		fprintf (stderr, "Path: \"%s\"\t is not a directory\n",optarg);
		exit (EX_NOINPUT);
	    }
	    usersdir = optarg;
	    break;
	  case 'd':
	    debug = TRUE;
	    break;
	  case 'f':
	    full_recipient = TRUE;
	    break;
	}
    }
    if (smfi_register (smfilter) == MI_FAILURE)
    {
	fprintf (stderr, "smfi_register failed\n");
	exit (EX_UNAVAILABLE);
    }
    umask (S_IXUSR | S_IRWXG | S_IRWXO);
    if (debug) return smfi_main ();
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
