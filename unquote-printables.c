/*  unquote-printables.c

    Main file for  unquote-printables  (convert quoted-printables to 8 bits).

    Copyright (C) 2002  Richard Gooch

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
    This programme reads the standard input and convert quoted printable
    characters to 8 bit characters. The output is written to the standard
    output.


    Written by      Richard Gooch   10-MAR-2002

    Last updated by Richard Gooch   10-MAR-2002


*/
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>


#define ERRSTRING  strerror (errno)

int main ()
{
    int ch1, ch2;

    while ( ( ch1 = getchar () ) != EOF )
    {
	if (ch1 != '=')
	{
	    putchar (ch1);
	    continue;
	}
	if ( ( ch1 = getchar () ) == EOF ) break;
	if (ch1 == '\n') continue;
	if ( !isxdigit (ch1) )
	{
	    putchar ('=');
	    putchar (ch1);
	    continue;
	}
	if ( ( ch2 = getchar () ) == EOF )
	{
	    putchar ('=');
	    putchar (ch1);
	    break;
	}
	if ( !isxdigit (ch2) )
	{
	    putchar ('=');
	    putchar (ch1);
	    putchar (ch2);
	    continue;
	}
	ch1 = tolower (ch1);
	ch1 = isdigit (ch1) ? (ch1 - '0') : (ch1 - 'a' + 10);
	ch2 = tolower (ch2);
	ch2 = isdigit (ch2) ? (ch2 - '0') : (ch2 - 'a' + 10);
	putchar ( (ch1 << 4) + ch2 );
    }
    if ( ferror (stdin) || ferror (stdout) ) exit (1);
    return (0);
}   /*  End Function main  */
