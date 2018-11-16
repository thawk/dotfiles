# 如果有vim则用vim。否则用vi。在有vim时，如果没有vi，将vi定义为vim的alias
if [[ "$OSTYPE" == "darwin"* ]] || [[ "$OSTYPE" == "freebsd"* ]]
then
    alias ls='ls -G'
    type gmake &> /dev/null && alias make=gmake
else
    alias ls='ls --color=auto'
fi
alias ll='ls -l'

type wine &> /dev/null && alias wine='env LANG=zh_CN.UTF-8 wine'
type xprop &> /dev/null && alias xpop='xprop | grep --color=none "WM_CLASS\|^WM_NAME" | xmessage -file -'
type tmux &> /dev/null && alias tmux='tmux -2'

if [[ "$OSTYPE" = "cygwin" ]]
then
    alias cyg='apt-cyg mirror http://mirrors.163.com/cygwin/'
    alias cyp='apt-cyg mirror http://mirrors.kernel.org/sources.redhat.com/cygwinports/'
fi

