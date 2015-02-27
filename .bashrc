export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8

export CDPATH=.:$HOME/workspace:$HOME/workspace/stsv5/cs/trunk
#export GREP_OPTIONS="--color"

export HISTIGNORE='&:ls:ll:[bf]g:exit'
# ignore line begin with spaces
export HISTIGNORE='$HISTIGNORE:[ 	]*'
export HISTCONTROL=earsedups:ignorespace

# prevent accident press ctrl-d to exit the shell
export IGNOREEOF=1

export MC_SKIN=solarized

[ -e $HOME/workspace/stsv5/cs/trunk/cfg ] && export STSV5_HOME=$HOME/workspace/stsv5/cs/trunk/cfg

# use dir_colors
[ -f ~/.dir_colors ] && eval `dircolors -b ~/.dir_colors` 

alias ls='ls --color=auto'
alias ll='ls -l'
alias wine='env LANG=zh_CN.UTF-8 wine'
alias xpop='xprop | grep --color=none "WM_CLASS\|^WM_NAME" | xmessage -file -'
alias tmux='tmux -2'

# 使用了pam_ssh，不再需要keychain
#/usr/bin/keychain -Q -q ~/.ssh/id_rsa
#[[ -f $HOME/.keychain/$HOSTNAME-sh ]] && source $HOME/.keychain/$HOSTNAME-sh

[ -d $HOME/my/doc/viki ] && viki=$HOME/my/doc/viki
[ -d $HOME/my/doc/pkm ]  && pkm=$HOME/my/doc/pkm
[ -d $HOME/my/doc/blog ]  && blog=$HOME/my/doc/blog

shopt -s histappend
shopt -s histverify

if [ -d ~/bin ]; then
    export PATH=~/bin:"$PATH"
fi

# 如果有vim则用vim。否则用vi。在有vim时，如果没有vi，将vi定义为vim的alias
vi=$(which vi 2> /dev/null)
vim=$(which vim 2> /dev/null)
if [ ! -z $vim ]; then
    export EDITOR="$vim"
    [ -z $vi ] && alias vi=vim
elif [ ! -z $vi ]; then
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

#if [ -f /etc/bash_completion ]; then
#    . /etc/bash_completion
#fi
#

# todo.sh
#export TODO_DIR=~/my/archive/todo
#alias t='todo.py -t dark'
#if [ ! -z `type -t _todo_sh` ]
#then
#    complete -F _todo_sh -o default t
#fi

# task
#if [ -d "$HOME/my/archive/task" ]
#then
#    alias th="task rc:$HOME/my/archive/task/home/taskrc"
#    alias tw="task rc:$HOME/my/archive/task/work/taskrc"
#
#    . $HOME/my/archive/task/task_completer.sh
#    complete -F _task_sh -o default th tw task
#fi

#PROMPT_COMMAND='RET=$?; if [[ $RET = 0 ]]; then echo -ne "\033[0;32m$RET\033[0m"; else echo -ne "\033[0;31m$RET\033[0m"; fi; echo -n " "'
#PROMPT_COMMAND='RET=$?; if [[ $RET != 0 ]]; then echo -e "RET=\033[0;31m$RET\033[0m"; fi'
#PROMPT_COMMAND='if [[ $? != 0 ]]; then PS1="\033[0;31m[\u@\u \W]\$ \033[0m"; else PS1="[\u@\h \W]\$ "; fi'

grepp() {
  if test -z "$1"; then
    echo "USAGE: grepp searchterm [filetosearch]";
  elif test -z "$2"; then
    perl -00ne "print if /$1/i"
  else
    perl -00ne "print if /$1/i" < $2
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
    while [ ! -z "$1" ]
    do
        printf "%x\n" "$1"
        shift
    done
}

hex2dec() {
    while [ ! -z "$1" ]
    do
        echo $((0x$1))
        shift
    done
}

[ -f "$HOME/libexec/svn.bash" ] && source "$HOME/libexec/svn.bash"
[ -f "$HOME/libexec/stsv5_llm_path.sh" ] && source "$HOME/libexec/stsv5_llm_path.sh"

#if [ "$SSH_CONNECTION" ]; then
#    if [ -z "$STY" ]; then
#        # Screen is not currently running, but we are in SSH, so start a session
#        #exec screen -U -d -R ssh
#        screen -U -d -R ssh
#    fi
#fi

# http://savannah.nongnu.org/projects/ranger
# This changes the directory after you close ranger
function ranger-cd {
  before="$(pwd)"
  ranger --fail-unless-cd "$@" || return 0
  after="$(grep \^\' ~/.config/ranger/bookmarks | cut -b3-)"
  if [[ "$before" != "$after" ]]; then
    cd "$after"
  fi
}
alias rcd=ranger-cd
