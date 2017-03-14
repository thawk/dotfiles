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
    if [ $# -gt 0 ]
    then
        echo "$*" | urlencode
        return
    fi

    perl -lpe 's/([^A-Za-z0-9.])/sprintf("%%%02X", ord($1))/seg'
}

urldecode() {
    if [ $# -gt 0 ]
    then
        echo "$*" | urldecode
        return
    fi

    local data=${1//+/ }
    printf '%b' "${data//\%/\\x}"
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
    python - << EOD
import math
result=($@)
bytes=int(math.ceil(len('{:b}'.format(result))/8.0))
print('    '.join((
    '{0}'.format(result),
    '0x{0:0>{1}X}'.format(result, bytes*2),
    '0o{0:0>{1}o}'.format(result, 1),
    '0b{0:0>{1}b}'.format(result, bytes*8),
    )))
EOD
}

