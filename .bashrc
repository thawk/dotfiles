# Source global definitions
if [ -f /etc/bashrc ]; then
	. /etc/bashrc
fi

# Disable flow control
stty -ixon

export CDPATH=:$HOME/workspace

# User specific aliases and functions
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8

#export GREP_OPTIONS="--color"

export HISTIGNORE='&:ls:ll:[bf]g:exit'
# ignore line begin with spaces
export HISTIGNORE='$HISTIGNORE:[ 	]*'
export HISTCONTROL=erasedups:ignorespace

# 文件名补全时，忽略.svn目录
export FIGNORE=.svn

# prevent accident press ctrl-d to exit the shell
export IGNOREEOF=1

export MC_SKIN=solarized

# use dir_colors
[ -f ~/.dir_colors ] && eval `dircolors -b ~/.dir_colors` 

alias ls='ls --color=auto'
alias ll='ls -l'
alias wine='env LANG=zh_CN.UTF-8 wine'
alias xpop='xprop | grep --color=none "WM_CLASS\|^WM_NAME" | xmessage -file -'
alias tmux='tmux -2'

if [ `uname -o` = "Cygwin" ]
then
    alias cyg='apt-cyg mirror http://mirrors.163.com/cygwin/'
    alias cyp='apt-cyg mirror http://mirrors.kernel.org/sources.redhat.com/cygwinports/'
fi

# 使用了pam_ssh，不再需要keychain
#/usr/bin/keychain -Q -q ~/.ssh/id_rsa
#[[ -f $HOME/.keychain/$HOSTNAME-sh ]] && source $HOME/.keychain/$HOSTNAME-sh

shopt -s histappend
shopt -s histverify

if [ -d ~/bin ]; then
    export PATH=~/bin:"$PATH"
fi

if [ -d ~/.vim/bundle/base16-shell ]; then
    export PATH="$PATH":~/.vim/bundle/base16-shell
fi
    
# 如果有vim则用vim。否则用vi。在有vim时，如果没有vi，将vi定义为vim的alias
vi=$(which vi 2> /dev/null)
vim=$(which vim 2> /dev/null)
if [ ! -z "$vim" ]; then
    export EDITOR="$vim"
    [ -z "$vi" ] && alias vi=vim
elif [ ! -z "$vi" ]; then
    export EDITOR="vi"
fi

PS1='[\u@\h \W]\$ '

if [ -f /etc/bash_completion ] 
then
    . /etc/bash_completion
fi

shopt -s extglob progcomp
USER_BASH_COMPLETION_DIR=~/.bash_completion.d
if [ -d $USER_BASH_COMPLETION_DIR -a -r $USER_BASH_COMPLETION_DIR -a \
     -x $USER_BASH_COMPLETION_DIR ]; then
	for i in $USER_BASH_COMPLETION_DIR/*; do
		[[ ${i##*/} != @(*~|*.bak|*.swp|\#*\#|*.dpkg*|.rpm*) ]] &&
			[ \( -f $i -o -h $i \) -a -r $i ] && . $i
	done
fi

timestamp() {
    while [ $# -gt 0 ]
    do
        timestamp=$1
        date -d @$((timestamp / 1000000)) +"%Y-%m-%d %T".$((timestamp % 1000000))
        shift
    done
}

epochtime() {
    while [ $# -gt 0 ]
    do
        epochtime=$1
        date -d @$((epochtime / 1000)) +"%Y-%m-%d %T".$((epochtime % 1000))
        shift
    done
}

time_t() {
    while [ $# -gt 0 ]
    do
        time_t=$1
        date -d @$((time_t)) +"%Y-%m-%d %T"
        shift
    done
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

dec2hex() {
    if [ $# -eq 0 ]
    then    # 从stdin读取
        while read i
        do
            dec2hex $i
        done
    else    # 从命令行读取
        while [ ! -z "$1" ]
        do
            echo "obase=16; ibase=10; $1" | bc
            shift
        done
    fi
}

hex2dec() {
    if [ $# -eq 0 ]
    then    # 从stdin读取
        while read i
        do
            hex2dec $i
        done
    else    # 从命令行读取
        while [ ! -z "$1" ]
        do
            echo $((0x$1))
            shift
        done
    fi
}

b362dec() {
    while [ ! -z "$1" ]
    do
        echo $((36#$1))
        shift
    done
}

dec2b36() {
    b36arr=($(echo {0..9} {A..Z}))
    while [ ! -z "$1" ]
    do
        for i in $(echo "obase=36; $1" | bc)
        do
            echo -n ${b36arr[${i#0}]}
        done
        echo
        shift
    done
}

if [ -d "$HOME/libexec" ]
then
    for f in "$HOME/libexec/"*.bash
    do
        source "$f"
    done

    if find "$HOME/libexec" -name "*.so" -quit
    then
        if [ -z "$LD_LIBRARY_PATH" ]
        then
            export LD_LIBRARY_PATH="$HOME/libexec"
        else
            export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$HOME/libexec"
        fi
    fi
fi
