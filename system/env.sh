# User specific aliases and functions
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8

#export GREP_OPTIONS="--color"

# 文件名补全时，忽略.svn目录
export FIGNORE=.svn

# prevent accident press ctrl-d to exit the shell
export IGNOREEOF=1

if which vim &> /dev/null ; then
    export EDITOR="vim"
    which vi &> /dev/null || alias vi=vim
elif which vi &> /dev/null ; then
    export EDITOR="vi"
fi


