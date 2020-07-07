#!/usr/bin/env bash
# Time: 2020-05-13 22:49:19

if [[ -t 1 ]]
then    # stdout是终端，可以显示颜色
    FATAL_FORMAT="\\033[31m"
    CANCEL_FORMAT="\\033[0m"
else    # stdout不是终端，不显示颜色
    FATAL_FORMAT=
    CANCEL_FORMAT=
fi

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

    local curr_url="$(getSvnInfo "$1/$wcdir")"
    local cmp_external="$external"
    local cmp_curr_url="$curr_url"

    if [[ "$external" == /* ]]; then
        # 外链不是同一个库
        cmp_external="$(getSvnInfo "$svnbase" "url" | sed 's!^\([^:]\+://[^/]\+\)/.*$!\1!')$external"
        cmp_curr_url="$(getSvnInfo "$svnbase/$wcdir" "url")"
    elif [[ "$external" =~ ^[^:/]+://.*$ ]]; then
        # 外链是全URL
        cmp_curr_url="$(getSvnInfo "$svnbase/$wcdir" "url")"
    fi

    if [[ "$cmp_curr_url" == "$cmp_external" ]]; then
        # 外链和要求的一样
        echo -e "${svnbase}/${wcdir}\t${external}"
    else
        echo -e "${svnbase}/${wcdir}\t${external}\t${FATAL_FORMAT}${curr_url}${CANCEL_FORMAT}"
    fi

    ## recurse into external directory
    [ -d "$wcdir" ] && getSvnExternals "$svnbase/$wcdir"
  done
}

getSvnInfo() {
    local propname="${2:-relative-url}"
    svn info --xml "${1:-.}" |
        sed -n -E -e '/^.*<${propname}>([^<]+)<.*$/{s//\1/;p;q;}'
}

