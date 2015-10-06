/*  kemail-size-logd.c

    Main file for  kemail-size-logd  (Karma daemon to log email message sizes).

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
    This programme will collect and distribute email message sizes. The
    incoming data must come from milter-size(8).


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
STATIC_FUNCTION (flag milter_input_func, (Channel channel, void **info) );
STATIC_FUNCTION (flag server_open_func, (Connection connection, void **info) );


/*  Private structures  */
struct buffer_struct
{
    unsigned int rpos;  /*  Where to start reading  */
    unsigned int wpos;  /*  Where to start writing  */
    unsigned int buffer[BUFFER_SIZE];
};


/*  Private data  */
struct buffer_struct buffer = {0, 0};


/*  Public functions follow  */

int main (int argc, char **argv)
{
    Channel channel;
    int def_port_number;
    unsigned int server_port_number = 0;

    /*  Initialise communications package  */
    dm_native_setup ();
    conn_initialise ( ( void (*) () ) NULL );
    conn_register_server_protocol ("email-message-size", 0, 0,
				   server_open_func, ( flag (*) () ) NULL,
				   ( void (*) () ) NULL);
    /*  Get default port number  */
    if ( ( def_port_number = r_get_def_port ("kemail-size-logd", NULL) ) < 0 )
    {
	fprintf (stderr, "Could not get default port number\n");
	exit (RV_UNDEF_ERROR);
    }
    server_port_number = def_port_number;
    if ( !conn_become_server (&server_port_number, 0) )
    {
	fprintf (stderr, "Error becomming a server\n");
	exit (RV_UNDEF_ERROR);
    }
    server_port_number = 1024;
    if ( ( channel = ch_udp_alloc (&server_port_number, TRUE) ) == NULL )
	exit (RV_UNDEF_ERROR);
    if (chm_manage (channel, NULL, milter_input_func, NULL, NULL, NULL)
	== NULL) exit (RV_UNDEF_ERROR);
    while (TRUE) dm_native_poll (-1);
    exit (RV_OK);
}   /*  End Function main  */


/*  Private functions follow  */

static flag milter_input_func (Channel channel, void **info)
/*  [SUMMARY] This routine is called when new input occurs on a channel.
    <channel> The channel object.
    <info> A pointer to the arbitrary information pointer. This may be modified
    [RETURNS] TRUE if the channel is to remain managed and open, else FALSE
    (indicating that the channel is to be unmanaged and closed).
    [NOTE] This routine MUST NOT unmanage or close the channel.
    [NOTE] The <<close_func>> will be called if this routine returns FALSE.
*/
{
    Connection conn;
    unsigned int num_conn, count;
    unsigned long size;

    if ( !pio_read32 (channel, &size) ) exit (RV_UNDEF_ERROR);
    buffer.buffer[buffer.wpos++] = size;
    if (buffer.wpos >= BUFFER_SIZE) buffer.wpos = 0;
    if (buffer.wpos == buffer.rpos)
    {   /*  Running up the arse of the reader: drop oldest value  */
	if (++buffer.rpos >= BUFFER_SIZE) buffer.rpos = 0;
    }
    num_conn = conn_get_num_serv_connections ("email-message-size");
    for (count = 0; count < num_conn; )
    {
	conn = conn_get_serv_connection ("email-message-size", count);
	channel = conn_get_datagram_channel (conn);
	if (!channel) channel = conn_get_channel (conn);
	if ( pio_write32 (channel, size) && ch_flush (channel) ) ++count;
	else
	{
	    conn_close (conn);
	    --num_conn;
	}
    }
    return (TRUE);
}   /*  End Function milter_input_func  */

static flag server_open_func (Connection connection, void **info)
/*  [SUMMARY] Connection open event callback.
    [PURPOSE] This routine is called when a connection opens.
    <connection> The connection object.
    <info> A pointer to the arbitrary information pointer. This may be modified
    [RETURNS] TRUE on successful registration, else FALSE (indicating the
    connection should be closed).
    [NOTE] The <<close_func>> will not be called if this routine returns
    FALSE.
*/
{
    Channel channel = conn_get_channel (connection);
    unsigned int pos;

    /*  Send the contents of the buffer over a reliable connection  */
    for (pos = buffer.rpos; pos != buffer.wpos; ++pos)
    {
	if (pos >= BUFFER_SIZE) pos = 0;
	if ( !pio_write32 (channel, buffer.buffer[pos]) ) return (FALSE);
    }
    return ch_flush (channel);
}   /*  End Function server_open_func  */
