#!/usr/bin/env bash
# Time: 2020-05-13 22:49:19

# $1 is a path to svn directory
getSvnExternals() {
  svnbase="${1:-.}"
  svnpath="$2"
  svn propget svn:externals -R "$svnbase/$svnpath" 2> /dev/null | while read a b c d e; do
    [ -n "$a" ] || continue
    if [ "$b" = "-" ]; then
      wcparent="$a"
      external="$c"
      wcdir=$(echo "$wcparent/$d" | sed s#^./##)
      [ -z "$e" ] || echo "WARNING: Invalid format #1. line='$a $b $c $d $e'"
    else
      [ -n "$wcparent" ] || echo "WARNING: Invalid format #2. wcparent=$wcparent"
      external="$a"
      wcdir=$(echo "$wcparent/$b" | sed s#^./##)
      [ -z "$c" ] || echo "WARNING: Invalid format #3. line='$a $b $c $d $e'"
    fi
    echo -e "$1/$wcdir\t$external"
    ## recurse into external directory
    [ -d "$wcdir" ] && getSvnExternals "$1/$wcdir"
  done
}

# $1 is a path to svn directory
getSvnUrl() {
    svn info --xml "${1:-.}" |
        sed -n -E -e '/^.*<relative-url>([^<]+)<.*$/{s//\1/;p;q;}'
}
