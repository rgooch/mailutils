/*  sizemilter.c

    Main file for  sizemilter  (Sendmail Milter to control message sizes).

    Copyright (C) 2003  Richard Gooch

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
    This milter allows you to reject messages of a specified size range.


    Written by      Richard Gooch   29-AUG-2003

    Updated by      Richard Gooch   31-AUG-2003: Improved resource management.

    Last updated by Richard Gooch   11-SEP-2003: Added size reporting via UDP.


*/
#ifndef _REENTRANT
#  error  Compile with _REENTRANT
#endif

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netdb.h>
#include <libmilter/mfapi.h>
#include <errno.h>

#define ERRSTRING strerror (errno)


struct private_struct
{
    unsigned int  nbytes;    /*  Number of bytes in the message body  */
};

static unsigned int minbytes = 0;
static unsigned int maxbytes = 0;
static int remhost_fd = -1;


static sfsistat mlfi_connect (SMFICTX *ctx, char *hostname,
			      _SOCK_ADDR *hostaddr)
{
    struct private_struct *priv;

    /*  Allocate per-connection private memory  */
    if ( ( priv = malloc (sizeof *priv) ) == NULL )
    {
	/*  Can't accept this message right now  */
	return (SMFIS_TEMPFAIL);
    }
    smfi_setpriv (ctx, priv);
    return (SMFIS_CONTINUE);
}   /*  End Function mlfi_connect  */

static sfsistat mlfi_envfrom (SMFICTX *ctx, char **envfrom)
{
    struct private_struct *priv = smfi_getpriv (ctx);

    /*  Initialise private memory for this new message  */
    memset (priv, 0, sizeof *priv);
    return (SMFIS_CONTINUE);
}   /*  End Function mlfi_envfrom  */

static sfsistat mlfi_body (SMFICTX *ctx, u_char *bodyp, size_t bodylen)
{
    struct private_struct *priv = smfi_getpriv (ctx);

    priv->nbytes += bodylen;
    return (SMFIS_CONTINUE);
}   /*  End Function mlfi_body  */

static sfsistat mlfi_eom (SMFICTX *ctx)
{
    struct private_struct *priv = smfi_getpriv (ctx);
    char txt[256];

    if (remhost_fd > -1)
    {   /*  Transmit the size for analysis  */
	uint32_t buf = htonl (priv->nbytes);

	if ( (write (remhost_fd, &buf, 4) < 4) && (errno == ECONNREFUSED) )
	    write (remhost_fd, &buf, 4);  /*  Previous call consumed error  */
    }
    if ( (minbytes == 0) && (maxbytes == 0) ) return (SMFIS_CONTINUE);
    if (minbytes <= maxbytes)
    {   /*  Legal message: min <= size <= max  */
	if ( (priv->nbytes >= minbytes) && (priv->nbytes <= maxbytes) )
	    return (SMFIS_CONTINUE);
    }
    else
    {   /*  Illegal message: max <= size <= min  */
	if ( (priv->nbytes < maxbytes) || (priv->nbytes > minbytes) )
	    return (SMFIS_CONTINUE);
    }
    sprintf (txt, "body length: %d rejected by administrator", priv->nbytes);
    smfi_setreply (ctx, "551", NULL, txt);
    return (SMFIS_REJECT);
}   /*  End Function mlfi_eom  */

sfsistat mlfi_close (SMFICTX *ctx)
{
    struct private_struct *priv = smfi_getpriv (ctx);

    smfi_setpriv (ctx, NULL);
    if (priv) free (priv);
    return (SMFIS_CONTINUE);
}   /*  End Function mlfi_close  */

static struct smfiDesc smfilter =
{
    "SizeMilter",	/* filter name */
    SMFI_VERSION,	/* version code -- do not change */
    SMFIF_ADDHDRS,	/* flags */
    mlfi_connect,	/* connection info filter */
    NULL,		/* SMTP HELO command filter */
    mlfi_envfrom,	/* envelope sender filter */
    NULL,		/* envelope recipient filter */
    NULL,		/* header filter */
    NULL,		/* end of header */
    mlfi_body,		/* body block filter */
    mlfi_eom,		/* end of message */
    NULL,		/* message aborted */
    mlfi_close		/* connection cleanup */
};

int main (int argc, char *argv[])
{
    int c;
    int remport = 1024;
    char *args = "l:h:p:r:R:";
    char *remhost = NULL;

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
	  case 'l':
	    if ( !optarg || (*optarg == '\0') )
	    {
		fprintf (stderr, "Illegal minimum: %s\n", optarg);
		exit (EX_USAGE);
	    }
	    minbytes = atoi (optarg);
	    break;
	  case 'h':
	    if ( !optarg || (*optarg == '\0') )
	    {
		fprintf (stderr, "Illegal maximum: %s\n", optarg);
		exit (EX_USAGE);
	    }
	    maxbytes = atoi (optarg);
	    break;
	  case 'p':
	    if ( !optarg || (*optarg == '\0') )
	    {
		fprintf (stderr, "Illegal conn: %s\n", optarg);
		exit (EX_USAGE);
	    }
	    smfi_setconn (optarg);
	    break;
	  case 'r':
	    if ( !optarg || (*optarg == '\0') )
	    {
		fprintf (stderr, "Illegal remhost: %s\n", optarg);
		exit (EX_USAGE);
	    }
	    remhost = optarg;
	    break;
	  case 'R':
	    if ( !optarg || (*optarg == '\0') )
	    {
		fprintf (stderr, "Illegal remport: %s\n", optarg);
		exit (EX_USAGE);
	    }
	    remport = atoi (optarg);
	    break;
	}
    }
    if (remhost)
    {
	struct sockaddr_in in_addr;
	struct hostent *hostent;

	if ( isascii (remhost[0]) && isdigit (remhost[0]) )
	{
	    /*  Numeric Internet address  */
	    if ( !inet_aton (remhost, &in_addr.sin_addr) )
	    {
		fprintf (stderr, "Invalid host address: \"%s\"\n", remhost);
		exit (EX_USAGE);
	    }
	}
	else if ( ( hostent = gethostbyname (remhost) ) == NULL )
	{
	    fprintf (stderr, "Error looking up host: \"%s\"\t%s\n",
		     remhost, ERRSTRING);
	    exit (EX_OSERR);
	}
	else
	{
	    if (hostent->h_length != 4)
	    {
		fprintf (stderr, "Hostlength: %d is not 4\n",
			 hostent->h_length);
		exit (EX_OSERR);
	    }
	    in_addr.sin_addr.s_addr = *(uint32_t *) hostent->h_addr_list[0];
	}
	in_addr.sin_family = AF_INET;
	in_addr.sin_port = htons (remport);
	if ( ( remhost_fd = socket (AF_INET, SOCK_DGRAM, 0) ) < 0 )
	{
	    fprintf (stderr, "Error creating socket\t%s\n", ERRSTRING);
	    exit (EX_OSERR);
	}
	if (connect (remhost_fd, (struct sockaddr *) &in_addr, sizeof in_addr)
	    != 0)
	{
	    fprintf (stderr, "Error connecting\t%s\n", ERRSTRING);
	    exit (EX_OSERR);
	}
    }
    if (smfi_register (smfilter) == MI_FAILURE)
    {
	fprintf (stderr, "smfi_register failed\n");
	exit (EX_UNAVAILABLE);
    }
    close (0);
    close (1);
    close (2);
    return smfi_main ();
}   /*  End Function main  */
