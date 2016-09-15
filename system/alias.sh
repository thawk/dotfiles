# 如果有vim则用vim。否则用vi。在有vim时，如果没有vi，将vi定义为vim的alias
vi=$(which vi 2> /dev/null)
vim=$(which vim 2> /dev/null)
if [ ! -z "$vim" ]; then
    export EDITOR="$vim"
    [ -z "$vi" ] && alias vi=vim
elif [ ! -z "$vi" ]; then
    export EDITOR="vi"
fi

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

