#!/usr/bin/env bash
# Time: 2020-05-13 22:49:19

if [[ -t 1 ]]
then    # stdout是终端，可以显示颜色
    FATAL_FORMAT="\\033[31m"
    TRUNK_FORMAT="\\033[93m"
    BRANCH_FORMAT="\\033[96m"
    TAGS_FORMAT="\\033[92m"
    PEG_FORMAT="\\033[95m"
    CANCEL_FORMAT="\\033[0m"
else    # stdout不是终端，不显示颜色
    FATAL_FORMAT=
    TRUNK_FORMAT=
    BRANCH_FORMAT=
    TAGS_FORMAT=
    PEG_FORMAT=
    CANCEL_FORMAT=
fi

# $1 is a path to svn directory
getSvnExternals() {
  local svnbase="${1:-.}"
  local svnpath="$2"
  svn propget svn:externals -R "$svnbase/$svnpath" 2> /dev/null | while read a b c d e; do
    [ -n "$a" ] || continue
    if [ "$b" = "-" ]; then
      local wcparent="$a"
      local external="$c"
      local wcdir=$(echo "$wcparent/$d" | sed 's#^./##')
      [ -z "$e" ] || echo "WARNING: Invalid format #1. line='$a $b $c $d $e'"
    else
      [ -n "$wcparent" ] || echo "WARNING: Invalid format #2. wcparent=$wcparent"
      local external="$a"
      local wcdir=$(echo "$wcparent/$b" | sed 's#^./##')
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

    if [[ "$external" =~ @[0-9]+$ ]]; then
        # 如果外链有peg，当前URL也加上revision进行比较
        local peg=$(getSvnInfo "$1/$wcdir" "entry" "revision")
        cmp_curr_url="${cmp_curr_url}@${peg}"
        curr_url="${curr_url}@${peg}"
    fi

    if [[ "$cmp_curr_url" == "$cmp_external" ]]; then
        # 外链和要求的一样
        echo -e "${svnbase}/${wcdir}\t${external}"
    else
        echo -e "${svnbase}/${wcdir}\t${external}\t${curr_url}"
    fi

    ## recurse into external directory
    [ -d "$wcdir" ] && getSvnExternals "$svnbase/$wcdir"
  done
}

getSvnInfo() {
    local propname="${2:-relative-url}"
    local attrname="$3"

    if [[ -z "$attrname" ]]; then
        # 取节点值
        svn info --xml "$1" |
            tr '\n' ' ' |
            sed -e 's/ \+/ /g' -e 's/> </></g' -e 's@\s*\(<[^/>]\+>\)\s*@\n\1@g' |
            sed -n -E -e "/^.*<${propname}>([^<]+)<.*\$/{s//\1/;p;q;}"
    else
        # 取属性值
        svn info --xml "$1" |
            tr '\n' ' ' |
            sed -e 's/ \+/ /g' -e 's/> </></g' -e 's@\s*\(<[^/>]\+>\)\s*@\n\1@g' |
            sed -n -E -e "/^.*<${propname}\s.*>/{s/^.*<${propname}\b[^>]*\s${attrnam}=\"([^\"]*)\".*\$/\1/;p;q;}"
    fi
}

addEscape() {
    echo -n "$*" | sed 's/\\/\\\\/g'
}

removeEscape() {
    echo -en "$*"
}

highlightBranch() {
    sed "s@\b\(trunk\)@$(removeEscape "$TRUNK_FORMAT")\1$(removeEscape "$CANCEL_FORMAT")@g" |
    sed "s@\b\(branches\)/\([^/]\+\)@\1/$(removeEscape "$BRANCH_FORMAT")\2$(removeEscape "$CANCEL_FORMAT")@g" |
    sed "s@\b\(tags\)/\([^/]\+\)@\1/$(removeEscape "$TAGS_FORMAT")\2$(removeEscape "$CANCEL_FORMAT")@g" |
    sed "s/@\([0-9]\+\)\b/@$(removeEscape "$PEG_FORMAT")\1$(removeEscape "$CANCEL_FORMAT")/g"
}
