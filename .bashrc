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

[[ -s /home/tanht/.autojump/etc/profile.d/autojump.sh ]] && source /home/tanht/.autojump/etc/profile.d/autojump.sh


