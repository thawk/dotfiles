# Disable flow control
stty -ixon

HISTIGNORE='&:ls:ll:[bf]g:exit'
# ignore line begin with spaces
HISTIGNORE='$HISTIGNORE:[ 	]*'
HISTCONTROL=erasedups:ignorespace

# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
HISTSIZE=1000
HISTFILESIZE=2000

