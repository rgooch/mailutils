/*  kemail-size-query.c

    Main file for  kemail-size-query  (Karma utility to query message sizes).

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
    This programme will query email message sizes from kemail-size-logd.


    Written by      Richard Gooch   11-SEP-2003

    Last updated by Richard Gooch   11-SEP-2003


*/
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>
#include <karma.h>
#include <karma_conn.h>
#include <karma_pio.h>
#include <karma_chm.h>
#include <karma_ch.h>
#include <karma_dm.h>
#include <karma_r.h>

#define BUFFER_SIZE  1024


/*  Private functions  */
STATIC_FUNCTION (flag client_read_func,
		 (Connection connection, void **info, Channel channel) );


/*  Public functions follow  */

int main (int argc, char **argv)
{
    int port_number;

    if (argc != 2)
    {
	fprintf (stderr, "Usage:\tkemail-size-query hostname\n");
	exit (RV_MISSING_PARAM);
    }
    /*  Initialise communications package  */
    dm_native_setup ();
    conn_initialise ( ( void (*) () ) NULL );
    conn_register_client_protocol ("email-message-size", 0, 1,
				   ( flag (*) () ) NULL, ( flag (*) () ) NULL,
				   client_read_func, ( void (*) () ) NULL);
    /*  Get default port number  */
    if ( ( port_number = r_get_def_port ("kemail-size-logd", NULL) ) < 0 )
    {
	fprintf (stderr, "Could not get default port number\n");
	exit (RV_UNDEF_ERROR);
    }
    if ( !conn_attempt_connection (argv[1], port_number,"email-message-size") )
    {
	fprintf (stderr, "Error connecting\t%s\n", ERRSTRING);
	exit (RV_UNDEF_ERROR);
    }
    fflush (stdout);
    setvbuf (stdout, NULL, _IOLBF, 0);
    while (TRUE) dm_native_poll (-1);
    exit (RV_OK);
}   /*  End Function main  */


/*  Private functions follow  */


static flag client_read_func (Connection connection, void **info,
			      Channel channel)
/*  [SUMMARY] Connection read event callback.
    [PURPOSE] This routine is called when data is ready to be read from a
    connection.
    <connection> The connection object.
    <info> A pointer to the arbitrary information pointer. This may be modified
    <channel> The channel object on which the read event occurred. This may be
    the normal or datagram channel.
    [RETURNS] TRUE on successful reading, else FALSE (indicating the connection
    should be closed).
    [NOTE] The <<close_func>> will be called if this routine returns FALSE.
*/
{
    unsigned long size;

    if ( !pio_read32 (channel, &size) ) return (FALSE);
    printf ("%lu\n", size);
    return (TRUE);
}   /*  End Function client_read_func  */
