#!/usr/bin/env python3
'''
NAME
    music2png - Converts textual music notation to classically notated PNG file

SYNOPSIS
    music2png [options] INFILE

DESCRIPTION
    This filter reads LilyPond or ABC music notation text from the input file
    INFILE (or stdin if INFILE is -), converts it to classical music notation
    and writes it to a trimmed PNG image file.

    This script is a wrapper for LilyPond and ImageMagick commands.

OPTIONS
    -f FORMAT
        The INFILE music format. 'abc' for ABC notation, 'ly' for LilyPond
        notation. Defaults to 'abc' unless source starts with backslash.

    -o OUTFILE
        The file name of the output file. If not specified the output file is
        named like INFILE but with a .png file name extension.

    -m
        Skip if the PNG output file is newer that than the INFILE.
        Compares timestamps on INFILE and OUTFILE. If
        INFILE is - (stdin) then compares MD5 checksum stored in file
        named like OUTFILE but with a .md5 file name extension.
        The .md5 file is created if the -m option is used and the
        INFILE is - (stdin).

    -v
        Verbosely print processing information to stderr.

    --help, -h
        Print this documentation.

    --version
        Print program version number.

SEE ALSO
    lilypond(1), abc2ly(1), convert(1)

AUTHOR
    Written by Stuart Rackham, <srackham@gmail.com>;
    Python3: Berthold Gehrke, <berthold.gehrke@gmail.com>

COPYING
    Copyright (C) 2006 Stuart Rackham.
    Copyright (C) 2018-2020 Berthold Gehrke. Free use of this software
    is granted under the terms of the GNU General Public License v2
    or higher (GPLv2+).
'''

import hashlib
import os
import sys
import tempfile

VERSION = '0.1.3'  # Python3

# Globals.
VERBOSE = False

class EApp(Exception):
    pass     # Application specific exception.

def print_stderr(line):
    sys.stderr.write(line + os.linesep)

def print_verbose(line):
    if VERBOSE:
        print_stderr(line)

def write_file(filename, data, mode='w'):
    f = open(filename, mode)
    try:
        f.write(data)
    finally:
        f.close()

def read_file(filename, mode='r'):
    f = open(filename, mode)
    try:
        return f.read()
    finally:
        f.close()

def run(cmd):
    global VERBOSE
    if not VERBOSE:
        cmd += ' 2>%s' % os.devnull
    print_verbose('executing: %s' % cmd)
    if os.system(cmd):
        raise EApp('failed command: %s' % cmd)

def music2png(format, infile, outfile, modified):
    '''Convert ABC notation in file infile to cropped PNG file named outfile.'''
    outfile = os.path.abspath(outfile)
    outdir = os.path.dirname(outfile)
    if not os.path.isdir(outdir):
        raise EApp('directory does not exist: %s' % outdir)
    basefile = tempfile.mktemp(dir=os.path.dirname(outfile))
    temps = [basefile + ext for ext in ('.abc', '.ly', '.ps', '.midi')]
    skip = False
    if infile == '-':
        source = sys.stdin.read()
        checksum = hashlib.new('md5', bytes(source, encoding='utf-8', errors='ignore')).digest()
        filename = os.path.splitext(outfile)[0] + '.md5'
        if modified:
            if os.path.isfile(filename) and os.path.isfile(outfile) and \
                    checksum == read_file(filename, 'rb'):
                skip = True
            else:
                write_file(filename, checksum, 'wb')
    else:
        if not os.path.isfile(infile):
            raise EApp('input file does not exist: %s' % infile)
        if modified and os.path.isfile(outfile) and \
                os.path.getmtime(infile) <= os.path.getmtime(outfile):
            skip = True
        source = read_file(infile)
    if skip:
        print_verbose('skipped: no change: %s' % outfile)
        return
    if format is None:
        if source and source.startswith('\\'):  # Guess input format.
            format = 'ly'
        else:
            format = 'abc'
    # Write temporary source file.
    write_file('%s.%s' % (basefile, format), source)
    abc = basefile + '.abc'
    ly = basefile + '.ly'
    png = basefile + '.png'
    saved_pwd = os.getcwd()
    os.chdir(outdir)
    try:
        if format == 'abc':
            run('abc2ly -o "%s" "%s"' % (ly, abc))
        run('lilypond --png -o "%s" "%s"' % (os.path.basename(basefile), ly))
        os.rename(png, outfile)
    finally:
        os.chdir(saved_pwd)
    # Chop the bottom 75 pixels off to get rid of the page footer then crop the
    # music image. The -strip option necessary because FOP does not like the
    # custom PNG color profile used by Lilypond.
    run('convert "%s" -strip -gravity South -chop 0x75 -trim "%s"' % (outfile, outfile))
    for f in temps:
        if os.path.isfile(f):
            print_verbose('deleting: %s' % f)
            os.remove(f)

def usage(msg=''):
    if msg:
        print_stderr(msg)
    print_stderr('\n'
                 'usage:\n'
                 '    music2png [options] INFILE\n'
                 '\n'
                 'options:\n'
                 '    -f FORMAT\n'
                 '    -o OUTFILE\n'
                 '    -m\n'
                 '    -v\n'
                 '    --help\n'
                 '    --version')

def main():
    # Process command line options.
    global VERBOSE
    format = None
    outfile = None
    modified = False
    import getopt
    opts, args = getopt.getopt(sys.argv[1:], 'f:o:mhv', ['help', 'version'])
    for o, v in opts:
        if o in ('--help', '-h'):
            print(__doc__)
            sys.exit(0)
        if o == '--version':
            print(('music2png version %s' % (VERSION,)))
            sys.exit(0)
        if o == '-f':
            format = v
        if o == '-o':
            outfile = v
        if o == '-m':
            modified = True
        if o == '-v':
            VERBOSE = True
    if len(args) < 1:
        usage()
        sys.exit(1)
    if len(args) > 1 and outfile is not None:
        usage('OUTFILE must not be specified for multiple INFILEs')
        sys.exit(1)
    if len(args) > 1 and '-' in args:
        usage('can not use - as INFILE while there are multiple INFILEs')
        sys.exit(1)
    if format not in (None, 'abc', 'ly'):
        usage('invalid FORMAT')
        sys.exit(1)

    for infile in args:
        print_verbose('Processing %s' % infile)
        if outfile is None:
            if infile == '-':
                usage('OUTFILE must be specified')
                sys.exit(1)
        outfile = os.path.splitext(infile)[0] + '.png'
        # Do the work.
        music2png(format, infile, outfile, modified)
        # Print something to suppress asciidoc 'no output from filter' warnings.
    if args[0] == '-':
        sys.stdout.write(' ')

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except KeyboardInterrupt:
        sys.exit(1)
    except Exception as e:
        print_stderr("%s: %s" % (os.path.basename(sys.argv[0]), str(e)))
        sys.exit(1)
