/*  halve-duplicatedb.c

    Main file for  halve-duplicatedb  (halve duplicates database).

    Copyright (C) 1998-2005  Richard Gooch

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
    This programme will halve the size of a duplicates database.


    Written by      Richard Gooch   1-OCT-1998

    Last updated by Richard Gooch   30-MAY-2005: Added #include <errno.h>


*/
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define TIMEOUT 10  /*  Seconds  */
#define ERRSTRING strerror (errno)


int main (int argc, char **argv)
{
    int lockfd = -1;
    int ival;
    off_t hpos;
    struct stat statbuf;
    FILE *dbfp;
    char *dbfname, *lockfname, *buffer;
    static char usage[] = "halve-duplicatedb dbfile lockfile";

    if (argc != 3)
    {
	fprintf (stderr, "Usage:\t%s\n", usage);
	exit (1);
    }
    dbfname = argv[1];
    lockfname = argv[2];
    /*  Wait for lockfile  */
    for (ival = 0; ival < TIMEOUT; ++ival)
    {
	if ( ( lockfd = open (lockfname, O_CREAT | O_EXCL | O_RDWR, 0) ) < 0 )
	{
	    if (errno == EEXIST)
	    {
		sleep (1);
		continue;
	    }
	    fprintf (stderr, "Error creating lockfile: \"%s\"\t%s\n",
		     lockfname, ERRSTRING);
	    exit (1);
	}
	break;
    }
    if (lockfd < 0)
    {
	fprintf (stderr, "Timeout gaining lockfile: \"%s\"\n", lockfname);
	exit (1);
    }
    close (lockfd);
    /*  Find database file size and allocate half-size buffer  */
    if (stat (dbfname, &statbuf) != 0)
    {
	fprintf (stderr, "Error statting file: \"%s\"\t%s\n",
		 dbfname, ERRSTRING);
	unlink (lockfname);
	exit (1);
    }
    hpos = statbuf.st_size / 2;
    if ( ( buffer = malloc (hpos) ) == NULL )
    {
	fprintf (stderr, "Error allocating %ld bytes\t%s\n",
		 (long) hpos, ERRSTRING);
	unlink (lockfname);
	exit (1);
    }
    /*  Open database file, seek halfway and scan for first '\0' character  */
    if ( ( dbfp = fopen (dbfname, "r") ) == NULL )
    {
	fprintf (stderr, "Error opening file: \"%s\"\t%s\n",
		 dbfname, ERRSTRING);
	unlink (lockfname);
	exit (1);
    }
    if (fseek (dbfp, hpos, SEEK_SET) != 0)
    {
	fprintf (stderr, "Error seeking file: \"%s\"\t%s\n",
		 dbfname, ERRSTRING);
	unlink (lockfname);
	exit (1);
    }
    while ( ( ival = getc (dbfp) ) != EOF )
    {
	++hpos;
	if (ival == '\0') break;
    }
    if (ival == EOF)
    {
	fprintf (stderr, "No NULL character found\n");
	unlink (lockfname);
	exit (1);
    }
    /*  Read latter half in one block  */
    if (fread (buffer, statbuf.st_size - hpos, 1, dbfp) != 1)
    {
	fprintf (stderr, "Error reading file: \"%s\"\t%s\n",
		 dbfname, ERRSTRING);
	unlink (lockfname);
	exit (1);
    }
    fclose (dbfp);
    if ( ( dbfp = fopen (dbfname, "w") ) == NULL )
    {
	fprintf (stderr, "Error opening file: \"%s\"\t%s\n",
		 dbfname, ERRSTRING);
	unlink (lockfname);
	exit (1);
    }
    if (fwrite (buffer, statbuf.st_size - hpos, 1, dbfp) != 1)
    {
	fprintf (stderr, "Error writing file: \"%s\"\t%s\n",
		 dbfname, ERRSTRING);
	unlink (lockfname);
	exit (1);
    }
    fclose (dbfp);
    unlink (lockfname);
    return (0);
}   /*  End Function main  */
