# 进入与当前tmux session名称一致的目录
cdd() {
    if type tmux &> /dev/null
    then
        cd "$HOME/workspace/$(tmux display-message -p '#S')"
    fi
}

grepp() {
  if test -z "$1"; then
    echo "USAGE: grepp searchterm [filetosearch]";
  elif test -z "$2"; then
    perl -00ne "print if /$1/i"
  else
    term=$1
    shift
    while ! test -z "$1"
    do
        perl -00ne "print if /$term/i" < $1
        shift
    done
  fi 
}

urlencode() {
    if [ $# -gt 0 ];
    then
        echo "$@" | perl -MURI::Escape -lne 'print uri_escape($_)'
    else
        perl -MURI::Escape -lne 'print uri_escape($_)'
    fi
}

urldecode() {
    if [ $# -gt 0 ];
    then
        echo "$@" | perl -MURI::Escape -lne 'print uri_unescape($_)'
    else
        perl -MURI::Escape -lne 'print uri_unescape($_)'
    fi
}

htmlencode() {
    if [ $# -gt 0 ]
    then
        echo "$@" | perl -lne "use HTML::Entities qw(encode_entities_numeric); use open(':locale'); print encode_entities_numeric(\$_,'<&>\\x0-\\x1f')"
    else
        perl -lne "use HTML::Entities qw(encode_entities_numeric); use open(':locale'); print encode_entities_numeric(\$_,'<&>\\x0-\\x1f')"
    fi
}

htmldecode() {
    if [ $# -gt 0 ];
    then
        echo "$@" | perl -MHTML::Entities -lne 'print decode_entities($_)'
    else
        perl -MHTML::Entities -lne 'print decode_entities($_)'
    fi
}

ansiesc() {
    sed -e 's/\[[0-9;]\+m//g'
}

vman () {
    vim +"set ft=man" +"Man $*"
}

function = {
    echo "result=($@);print('{0}\t0x{0:X}\t0o{0:o}\t0b{0:b}'.format(result))" | python -
}

